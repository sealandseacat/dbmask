"""Export an offline review bundle for the fixed synthetic PostgreSQL contract.

This is deliberately not a general database exporter. Both connection URLs must
pass the contract's local, fixed-account and fixed-database guards. A completed
positive validation and restored negative controls are required before export.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import shutil
import subprocess
import tempfile
from itertools import zip_longest
from pathlib import Path

from _postgres_contract_fixture import (
    COLUMNS,
    SENSITIVE,
    SOURCE_DATABASE,
    TARGET_DATABASE,
    validate_rows,
    validate_urls,
)
from sqlalchemy import create_engine, text

PRIMARY_KEYS = {"customers": ["id"], "orders": ["tenant_id", "order_id"]}
NEGATIVE_CASES = {
    "restore_email_5001": "Restore the original email at row 5,001",
    "restore_email_last": "Restore the original email at the final row",
    "missing_order": "Remove one order",
    "replace_order_key": "Replace an order key without changing the row count",
    "drop_unique": "Remove the customer-reference UNIQUE constraint",
}
CSV_FORMAT = {
    "encoding": "UTF-8",
    "delimiter": ",",
    "quote": '"',
    "header": True,
    "line_terminator": "LF",
    "null": "\\N",
    "null_encoding": "An unquoted \\N is SQL NULL; every non-NULL field is double-quoted.",
    "empty_string": '""',
    "literal_null_marker": '"\\N"',
    "escaping": "A double quote inside a non-NULL field is doubled.",
    "postgresql_copy_options": "FORMAT CSV, HEADER TRUE, NULL '\\N'",
}


class ReviewExportError(RuntimeError):
    """An expected export failure whose message is safe to retain in reports."""


def _validate_report(report: dict, rows: int) -> None:
    if not isinstance(report, dict) or report.get("status") != "passed":
        raise ValueError("review export requires a passed contract report")
    if report.get("rows_per_table") != rows or report.get("total_fixture_rows", rows * 2) != rows * 2:
        raise ValueError("review export row count differs from the contract report")
    final = report.get("stages", {}).get("final-strict", {})
    issues = final.get("result")
    if (final.get("exit_code") != 0 or not isinstance(issues, list) or not issues
            or not all(isinstance(issue, dict) and issue.get("status") == "pass" for issue in issues)):
        raise ValueError("review export requires successful final-strict validation")
    expected = {f"public.{table}.{column}" for table, columns in SENSITIVE.items() for column in columns}
    completeness = [issue for issue in issues if issue.get("check") == "masking_completeness"]
    if (len(completeness) != len(expected)
            or {issue.get("location") for issue in completeness} != expected
            or not all(issue.get("detail", {}).get("rows_compared") == rows
                       and issue.get("detail", {}).get("coverage") == "all rows"
                       for issue in completeness)):
        raise ValueError("review export requires final-strict coverage of every sensitive value")
    controls = report.get("negative_controls", {})
    if (not isinstance(controls, dict) or not set(NEGATIVE_CASES).issubset(controls)
            or not all(isinstance(value, dict) and value.get("expected_refusal_confirmed") is True
                       for value in controls.values())):
        raise ValueError("review export requires confirmed negative controls and final restoration")


def _csv_field(value) -> str:
    # PostgreSQL CSV distinguishes an unquoted NULL marker from a quoted literal.
    return "\\N" if value is None else '"' + str(value).replace('"', '""') + '"'


def _write_csv_row(handle, values) -> None:
    handle.write(",".join(_csv_field(value) for value in values) + "\n")


def _sample_positions(rows: int) -> list[int]:
    return sorted({position for position in (
        1, 2, 3, 17, 23, 34, 46, 699, 700, 701, 4999, 5000, 5001, rows - 1, rows,
    ) if 1 <= position <= rows})


def _sample_reason(position: int, rows: int) -> list[str]:
    reasons = []
    if position == 1:
        reasons.append("First row; email is repeated at the final row")
    if position == rows:
        reasons.append("Final row; email repeats the first row")
    if position in {2, 3}:
        reasons.append("Ordinary values")
    if position % 17 == 0:
        reasons.append("Customer phone is NULL")
    if position % 23 == 0:
        reasons.append("Customer name is NULL")
    if position in {699, 700, 701}:
        reasons.append("Order composite-key boundary: (1, 700) to (2, 1)")
    if position in {4999, 5000, 5001}:
        reasons.append("5,000-row comparison-budget boundary")
    if position == rows - 1:
        reasons.append("Penultimate row")
    return reasons


def _file_info(path: Path, root: Path, **extra) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": path.relative_to(root).as_posix(), "sha256": digest.hexdigest(),
            "bytes": path.stat().st_size, **extra}


def _export_csvs(source, target, rows: int, staging: Path) -> tuple[list[dict], dict]:
    files, samples = [], {}
    csv_dir = staging / "csv"
    csv_dir.mkdir()
    selected = set(_sample_positions(rows))
    missing = object()
    source_engine, target_engine = create_engine(source), None
    try:
        target_engine = create_engine(target)
        with source_engine.connect() as original, target_engine.connect() as masked:
            for table, columns in COLUMNS.items():
                keys = PRIMARY_KEYS[table]
                # Only the fixed fixture's identifiers enter this SQL statement.
                query = text(
                    f"SELECT {', '.join(columns)} FROM public.{table} ORDER BY {', '.join(keys)}"
                ).execution_options(stream_results=True, yield_per=1000)
                before_rows = original.execute(query).mappings()
                after_rows = masked.execute(query).mappings()
                paths = {side: csv_dir / f"{table}.{side}.csv" for side in ("before", "after")}
                samples[table] = []
                count, previous_key = 0, None
                with paths["before"].open("w", encoding="utf-8", newline="") as before_file, \
                        paths["after"].open("w", encoding="utf-8", newline="") as after_file:
                    _write_csv_row(before_file, columns)
                    _write_csv_row(after_file, columns)
                    for before, after in zip_longest(before_rows, after_rows, fillvalue=missing):
                        if before is missing or after is missing:
                            raise AssertionError(f"{table}: before/after row counts differ during export")
                        count += 1
                        if count > rows:
                            raise AssertionError(f"{table}: export found more rows than the contract report")
                        before_key = tuple(before[column] for column in keys)
                        after_key = tuple(after[column] for column in keys)
                        if (before_key != after_key
                                or not all(isinstance(value, int) and not isinstance(value, bool)
                                           for value in before_key)
                                or (previous_key is not None and before_key <= previous_key)):
                            raise AssertionError(f"{table}: primary keys are missing, misaligned or not unique")
                        previous_key = before_key
                        _write_csv_row(before_file, (before[column] for column in columns))
                        _write_csv_row(after_file, (after[column] for column in columns))
                        if count in selected:
                            samples[table].append({
                                "position": count, "key": list(before_key),
                                "reasons": _sample_reason(count, rows),
                                "before": {column: before[column] for column in columns},
                                "after": {column: after[column] for column in columns},
                            })
                if count != rows:
                    raise AssertionError(f"{table}: exported row count differs from the contract report")
                for side, path in paths.items():
                    files.append(_file_info(
                        path, staging, kind="csv", table=table, side=side, rows=count,
                        columns=list(columns), primary_key=list(keys),
                        null_encoding=CSV_FORMAT["null_encoding"],
                    ))
    finally:
        source_engine.dispose()
        if target_engine is not None:
            target_engine.dispose()
    return files, samples


def _dump_files(source, target, staging: Path, executable: str) -> tuple[list[dict], str]:
    # libpq variables such as PGHOSTADDR can redirect even an explicit --host.
    # Keep only the guarded connection and our own timeout/password settings.
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith("PG")}
    environment["PGPASSWORD"] = str(source.password)
    environment["PGCONNECT_TIMEOUT"] = "10"
    try:
        version = subprocess.run(
            [executable, "--version"], capture_output=True,
            text=True, check=False, env=environment, timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReviewExportError("requested pg_dump version check timed out after 30 seconds") from exc
    except OSError as exc:
        raise ReviewExportError("requested pg_dump client could not be started") from exc
    if version.returncode != 0 or not version.stdout.strip():
        raise ReviewExportError("requested pg_dump client version could not be read")
    client_version = version.stdout.strip()
    files = []
    for label, url in (("source", source), ("masked", target)):
        destination = staging / f"{label}.dump"
        # Connection arguments are explicit; ambient libpq settings were removed.
        # Passwords never appear in argv, the manifest, or the review page.
        arguments = [executable, "--host", str(url.host), "--port", str(url.port or 5432),
                     "--username", str(url.username), "--dbname", str(url.database),
                     "--no-password", "--format=custom", "--no-owner", "--no-acl"]
        environment["PGPASSWORD"] = str(url.password)
        try:
            with destination.open("wb") as handle:
                result = subprocess.run(
                    arguments, stdout=handle, stderr=subprocess.PIPE, check=False,
                    env=environment, timeout=300,
                )
        except subprocess.TimeoutExpired as exc:
            raise ReviewExportError(f"requested {label} pg_dump timed out after 300 seconds") from exc
        except OSError as exc:
            raise ReviewExportError(f"requested {label} pg_dump could not be started or saved") from exc
        if result.returncode != 0:
            raise ReviewExportError(f"requested {label} pg_dump failed; review bundle was not published")
        # A zero exit with missing/wrong-format output must not be reported as a dump.
        with destination.open("rb") as handle:
            if handle.read(5) != b"PGDMP":
                raise ReviewExportError(f"requested {label} pg_dump did not produce a custom-format archive")
        files.append(_file_info(destination, staging, kind="postgresql_custom_dump", side=label))
    return files, client_version


def _escape(value) -> str:
    return html.escape(str(value), quote=True)


def _value_html(value) -> str:
    if value is None:
        return '<span class="null">NULL <small>(database null)</small></span>'
    if value == "":
        return '<span class="empty">&quot;&quot; <small>(empty string)</small></span>'
    return '<span class="value">' + _escape(value) + "</span>"


def _change_label(before, after, sensitive: bool) -> tuple[str, str]:
    if before is None and after is None:
        return "NULL preserved", "ok"
    if not sensitive:
        return ("Preserved", "ok") if before == after else ("CHANGED — inspect", "bad")
    if before is None:
        return "NULL changed — inspect", "bad"
    if after is None:
        return "Changed to NULL — inspect", "bad"
    return ("Changed", "ok") if before != after else ("UNCHANGED — inspect", "bad")


def _render_html(manifest: dict, samples: dict) -> str:
    rows = manifest["rows_per_table"]
    sections = []
    for table, columns in COLUMNS.items():
        cards = []
        for number, sample in enumerate(samples[table]):
            key = ", ".join(f"{column}={value}" for column, value in zip(PRIMARY_KEYS[table], sample["key"]))
            fields = []
            for column in columns:
                sensitive = column in SENSITIVE[table]
                before, after = sample["before"][column], sample["after"][column]
                label, css = _change_label(before, after, sensitive)
                fields.append(
                    f"<tr><th scope=\"row\">{_escape(column)}</th>"
                    f"<td><span class=\"tag {'mask' if sensitive else 'keep'}\">"
                    f"{'MASK' if sensitive else 'KEEP'}</span></td>"
                    f"<td>{_value_html(before)}</td><td>{_value_html(after)}</td>"
                    f"<td class=\"{css}\">{_escape(label)}</td></tr>"
                )
            reasons = "; ".join(sample["reasons"])
            cards.append(
                f"<details{' open' if number == 0 else ''}><summary>"
                f"<strong>{_escape(key)}</strong><span>{_escape(reasons)}</span></summary>"
                '<div class="table-wrap"><table><thead><tr>'
                '<th>Field</th><th>Rule</th><th>Before: untouched source</th>'
                '<th>After: final masked copy</th><th>Observed</th></tr></thead>'
                f"<tbody>{''.join(fields)}</tbody></table></div></details>"
            )
        sections.append(
            f'<section id="{_escape(table)}"><h2>{_escape(table)}</h2>'
            f'<p><strong>{len(samples[table])} selected rows shown</strong> out of {rows:,}. '
            f'Both full CSV files contain {rows:,} data rows, ordered by '
            f'<code>{_escape(", ".join(PRIMARY_KEYS[table]))}</code>.</p>'
            f'<p class="links"><a href="csv/{_escape(table)}.before.csv">Download full before CSV</a>'
            f'<a href="csv/{_escape(table)}.after.csv">Download full after CSV</a></p>'
            + "".join(cards) + "</section>"
        )
    controls = "".join(
        '<tr><th scope="row">' + _escape(NEGATIVE_CASES.get(case, case))
        + '</th><td>Strict validation rejects the injected fault</td>'
        + '<td class="ok">Expected rejection confirmed</td></tr>'
        for case in manifest["negative_controls"]
    )
    dump_links = ""
    if manifest["dumps"]["requested"]:
        dump_links = (
            '<a href="source.dump">Source PostgreSQL dump</a>'
            '<a href="masked.dump">Masked PostgreSQL dump</a>'
        )
    seed_map = {True: "on", False: "off", None: "not recorded"}.get(manifest["seed_map_enabled"], "not recorded")
    working_tree = {True: "Uncommitted local changes were present", False: "Clean checkout",
                    None: "Working-tree state was not recorded"}.get(
                        manifest["working_tree_dirty"], "Working-tree state was not recorded",
                    )
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>dbmask synthetic PostgreSQL review</title>
<style>
:root{color-scheme:light;--ink:#172b39;--muted:#526773;--line:#d8e3e9;--accent:#12645f}
*{box-sizing:border-box}body{margin:0;background:#f3f6f8;color:var(--ink);font:16px/1.55 system-ui,sans-serif}
main{max-width:1180px;margin:auto;padding:36px 22px 64px}header{border-top:5px solid var(--accent);padding:24px 28px;background:white;border-radius:10px}
h1{font-size:clamp(1.7rem,4vw,2.3rem);line-height:1.2;margin:8px 0 14px}h2{margin-top:0;font-size:1.5rem}h3{font-size:1.1rem}
p{margin:10px 0}a{color:#095e8c;text-underline-offset:3px}code{overflow-wrap:anywhere;font-size:.91em}
.eyebrow{font-size:.78rem;letter-spacing:.12em;font-weight:750;color:var(--accent)}.status{display:inline-block;background:#e4f5ef;color:#12624c;padding:4px 12px;border-radius:20px;font-weight:700}
.metrics{display:flex;flex-wrap:wrap;gap:12px;margin:22px 0}.metric{flex:1;min-width:150px;padding:14px 18px;background:white;border:1px solid var(--line);border-radius:8px}.metric strong{display:block;font-size:1.3rem}.metric span{color:var(--muted);font-size:.88rem}
section{margin-top:26px;padding:24px;background:white;border:1px solid var(--line);border-radius:10px}.note{border-left:4px solid #d39b20;background:#fff8e7;padding:12px 16px;margin:18px 0}.links{display:flex;flex-wrap:wrap;gap:12px 24px}
details{border:1px solid var(--line);border-radius:7px;margin:12px 0;overflow:hidden}summary{cursor:pointer;padding:13px 16px;background:#f7fafb}summary strong{margin-right:18px}summary span{font-size:.88rem;color:var(--muted)}
.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;vertical-align:top;padding:11px 13px;border-bottom:1px solid var(--line)}thead{background:#edf3f5}tbody th{font-weight:600}td{overflow-wrap:anywhere;min-width:115px}.value{white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,monospace}.null{color:#705400;font-weight:650}.empty{color:#6648a0}small{font-weight:400}
.tag{display:inline-block;border-radius:4px;padding:2px 7px;font-size:.7rem;font-weight:800;letter-spacing:.04em}.mask{background:#e4f0ff;color:#174a80}.keep{background:#e8edf0;color:#475f6b}.ok{color:#116448;font-weight:600}.bad{color:#a32b20;font-weight:700}.meta{color:var(--muted);font-size:.9rem}footer{margin-top:28px;color:var(--muted);font-size:.88rem}
@media(max-width:640px){main{padding:18px 10px 36px}header,section{padding:18px 14px}summary span{display:block}th,td{padding:9px}}
</style></head><body><main><header><div class="eyebrow">DBMASK · SYNTHETIC FIXTURE REVIEW</div>
<h1>Before and after, matched by primary key</h1><span class="status">Final strict validation passed</span>
<p>These are deliberately generated test records. The source is untouched; the after data is the final
masked state, after every injected fault was restored and strict validation passed again.</p>
<p class="meta">Source commit: <code>""" + _escape(manifest["source_commit"] or "not recorded") + """</code><br>""" + _escape(working_tree) + """</p>
</header><div class="metrics"><div class="metric"><strong>""" + f"{rows:,}" + """</strong><span>Data rows in each table / CSV</span></div>
<div class="metric"><strong>""" + f"{rows * 2:,}" + """</strong><span>Records across two tables</span></div>
<div class="metric"><strong>""" + _escape(seed_map) + """</strong><span>Persistent seed map</span></div></div>
<div class="note"><strong>This page shows selected samples.</strong> It includes ordinary rows, NULLs,
the repeated first/final email, order key boundaries, and rows around 5,000. Use the four full CSV files
for all rows. Passing this fixture does not establish detection accuracy or production readiness.</div>
<nav class="links"><a href="#customers">Customers</a><a href="#orders">Orders</a>
<a href="#controls">Fault checks</a><a href="../report.json">Full run report</a><a href="manifest.json">File manifest and hashes</a>""" + dump_links + "</nav>" + "".join(sections) + """
<section id="controls"><h2>Deliberate faults were detected and restored</h2>
<p>A refusal is the expected result for each faulty database below. These faults are absent from the
exported after data. The final strict validation returned exit code 0.</p>
<div class="table-wrap"><table><thead><tr><th>Fault injected</th><th>Expected behavior</th><th>Observed</th></tr></thead><tbody>""" + controls + r"""</tbody></table></div></section>
<section><h2>Reading the CSV files</h2><p>Files use UTF-8 with a header. Every non-NULL value is quoted.
An unquoted <code>\N</code> means SQL NULL; <code>&quot;&quot;</code> means an empty string;
<code>&quot;\N&quot;</code> means the literal two-character string <code>\N</code>.
Quotes within a value are doubled. Embedded commas and newlines remain inside the quoted field.</p>
<p>For PostgreSQL COPY, use <code>FORMAT CSV, HEADER TRUE, NULL '\N'</code>.
Keep the quoting information when interpreting NULLs; spreadsheet previews may display these cases similarly.</p>
<p><span class="tag mask">MASK</span> marks a reviewed sensitive field. Non-NULL values should change;
SQL NULLs should remain NULL. <span class="tag keep">KEEP</span> marks values that should be preserved.</p></section>
<footer>Offline, self-contained review of the fixed dbmask PostgreSQL contract. No external assets,
scripts, production records, or database credentials are embedded in this page.</footer></main></body></html>
"""


def export_review_bundle(
    source: str, target: str, rows: int, output: Path, report: dict, *,
    include_dumps: bool = False, pg_dump: str = "pg_dump",
) -> dict:
    """Atomically publish CSVs, a sampled HTML view, and optional synthetic dumps.

    ``output`` is the existing run evidence directory. File paths inside the
    manifest are relative to ``review/``; paths returned to the run report are
    relative to ``output``. No existing review bundle is replaced.
    """
    source_url, target_url = validate_urls(source, target)
    validate_rows(rows)
    _validate_report(report, rows)
    output = Path(output).resolve()
    if not output.is_dir():
        raise ValueError("review export requires an existing run output directory")
    destination = output / "review"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("review export refuses to overwrite an existing review bundle")
    lock = output / ".review-export.lock"
    try:
        descriptor = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise FileExistsError("a review export is already active or has an unfinished lock") from exc
    os.close(descriptor)
    staging = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=".review-", dir=output))
        files, samples = _export_csvs(source_url, target_url, rows, staging)
        client_version = None
        if include_dumps:
            dump_files, client_version = _dump_files(source_url, target_url, staging, pg_dump)
            files.extend(dump_files)
        environment = report.get("environment", {})
        manifest = {
            "schema_version": 1, "synthetic_data_only": True,
            "state": "final masked state after restored negative controls and passed final-strict",
            "source_database": SOURCE_DATABASE, "target_database": TARGET_DATABASE,
            "rows_per_table": rows, "total_fixture_rows": rows * 2,
            "source_commit": environment.get("source_commit"),
            "working_tree_dirty": environment.get("working_tree_dirty"),
            "seed_map_enabled": environment.get("seed_map_enabled"),
            "csv_format": CSV_FORMAT, "primary_keys": PRIMARY_KEYS,
            "sample_keys": {table: [sample["key"] for sample in selected]
                            for table, selected in samples.items()},
            "sample_positions": _sample_positions(rows),
            "negative_controls": {case: {"expected_refusal_confirmed": True}
                                  for case in report["negative_controls"]},
            "final_strict_exit_code": 0, "run_report": "../report.json",
            "dumps": {"requested": include_dumps, "format": "custom" if include_dumps else None,
                      "client_version": client_version},
            "files": files,
            "hash_scope": "Every bundle payload is listed; manifest.json excludes itself. Its hash is in report.json.",
        }
        review_page = staging / "index.html"
        review_page.write_text(_render_html(manifest, samples), encoding="utf-8")
        files.append(_file_info(review_page, staging, kind="html"))
        manifest_path = staging / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        manifest_file = _file_info(manifest_path, staging, kind="manifest")
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("review bundle appeared during export; refusing to replace it")
        staging.rename(destination)
        return {
            "directory": "review", "index": "review/index.html", "manifest": "review/manifest.json",
            "manifest_sha256": manifest_file["sha256"], "rows_per_table": rows,
            "dumps_included": include_dumps,
            "files": [{**item, "path": "review/" + item["path"]} for item in [*files, manifest_file]],
        }
    finally:
        try:
            if staging is not None and staging.exists():
                shutil.rmtree(staging)
        finally:
            lock.unlink(missing_ok=True)
