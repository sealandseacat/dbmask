"""Command-line interface.

Examples
--------
    dbmask scan   --config config/dbmask.config.yaml
    dbmask mask   --config config/dbmask.config.yaml          # dry-run by default
    dbmask mask   --config config/dbmask.config.yaml --apply  # actually write back
    dbmask history --config config/dbmask.config.yaml
    dbmask strategies
"""
from __future__ import annotations

import json
import sys
from contextlib import contextmanager

import click

from dbmask import __version__
from dbmask.config import Config
from dbmask.detection.result import Sensitivity
from dbmask.history.backend import history_backend
from dbmask.history.file_store import FileHistoryStore
from dbmask.history.records import HistoryValidationError
from dbmask.runner import Runner


@click.group()
@click.version_option(__version__, prog_name="dbmask")
def cli() -> None:
    """dbmask — discover and mask sensitive data in any database."""


def _load(config_path: str) -> Config:
    try:
        return Config.load(config_path)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"[error] Failed to load config '{config_path}': {exc}", err=True)
        sys.exit(2)


@contextmanager
def _runner(config: Config):
    try:
        with Runner(config) as runner:
            yield runner
    except (ValueError, KeyError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


def _shape_only(value) -> object:
    """Redact a value while keeping its shape (``Ada-99`` -> ``***-**``)."""
    if value is None:
        return None
    return "".join("*" if ch.isalnum() else ch for ch in str(value))


def _warn_llm_data_egress(config: Config) -> None:
    """Make it explicit when column samples will leave the machine."""
    llm = config.llm
    if not llm.enabled or (llm.provider or "").lower() != "openai":
        return
    dest = llm.base_url or "https://api.openai.com"
    if llm.send_values:
        click.echo(
            f"[warn] LLM fallback is enabled: up to {llm.sample_size} sampled "
            f"values per undecided column will be sent to {dest}. Set "
            "llm.send_values: false to send column names only, or use "
            "provider: local for a fully on-prem model.",
            err=True,
        )
    else:
        click.echo(
            f"[warn] LLM fallback is enabled (metadata-only): column names — "
            f"but no data values — will be sent to {dest}.",
            err=True,
        )


@cli.command()
@click.option("--config", "config_path", required=True, help="Path to config YAML.")
@click.option("--json", "as_json", is_flag=True, help="Emit decisions as JSON.")
@click.option("--output", type=click.Path(dir_okay=False), help="Export a review worksheet (.csv/.xlsx/.md).")
def scan(config_path: str, as_json: bool, output: str) -> None:
    """Classify every column as sensitive or not (no data is modified)."""
    config = _load(config_path)
    _warn_llm_data_egress(config)
    if output and config.history.source_file and not config.detection.user_id.strip():
        raise click.ClickException("Set detection.user_id before exporting a file-history review")
    with _runner(config) as runner:
        report = runner.scan()
        with_history = ({r.key: r for r in runner.history.records_for_review()}
                        if output and runner.history else {})

    if output:
        from dataclasses import replace

        from dbmask.history.files import write_history_file
        from dbmask.history.records import HistoryRecord

        records = []
        for decision in report.decisions:
            record = HistoryRecord.from_decision(decision)
            if decision.is_sensitive:
                record = replace(record, masking_strategy=runner.masker.resolve_strategy(decision))
            stored = with_history.get(record.key)
            if stored and decision.source in {"history", "history_pending"}:
                if isinstance(runner.history, FileHistoryStore) and stored.review_status != "approved":
                    from datetime import datetime, timezone

                    stored = replace(stored, user_id=config.detection.user_id,
                                     analysis_date=datetime.now(timezone.utc).isoformat())
                records.append(stored)
            else:
                records.append(replace(record, revision=stored.revision if stored else 0))
        try:
            if isinstance(runner.history, FileHistoryStore):
                from dbmask.history.writeback import export_review

                export_review(runner.history, output, records)
                click.echo(f"Review exported to {output}; keep its .dbmask.json companion", err=True)
            else:
                write_history_file(output, records)
        except (ValueError, OSError) as exc:
            raise click.ClickException(str(exc)) from exc

    if as_json:
        click.echo(json.dumps([d.to_dict() for d in report.decisions], indent=2))
    else:
        for d in report.decisions:
            if d.sensitivity is Sensitivity.UNKNOWN:
                flag = "UNKNOWN ?"
            elif d.is_sensitive:
                flag = "SENSITIVE"
            else:
                flag = "ok"
            rule = f" -> {d.rule}" if d.rule else ""
            score = f"match={d.confidence:.2%}" if d.source == "pattern" else f"conf={d.confidence:.2f}"
            click.echo(f"[{flag:9}] {d.schema}.{d.table}.{d.column}{rule} "
                       f"({d.source}, {score})")
            if d.pattern_sample_basis:
                click.echo(f"  {d.detail}")
            elif d.source == "history_pending":
                click.echo(f"  Review required: {d.detail}")
        s = runner.pipeline.stats
        click.echo("\n--- Summary ---")
        click.echo(f"Columns analyzed : {s.total}")
        click.echo(f"Sensitive found  : {s.sensitive}")
        click.echo(f"Needs review     : {s.unknown} (unknown)")
        click.echo(f"By source        : {s.by_source}")
        click.echo(f"LLM tokens used  : {s.tokens}")
        if s.unknown:
            click.echo(
                "\nUnknown columns are NOT masked. Mark them in the overrides "
                "file (detection.overrides_file) or enable the LLM fallback "
                "(llm.enabled) to classify them.",
            )
    for err in report.errors:
        click.echo(f"[error] {err}", err=True)
    if report.errors:
        click.echo(
            f"\nScan incomplete: {len(report.errors)} column(s) could not be "
            "analyzed (see errors above).",
            err=True,
        )
        sys.exit(3)


@cli.command()
@click.option("--config", "config_path", required=True, help="Path to config YAML.")
@click.option("--apply", "apply", is_flag=True,
              help="Write masked values back. Without this flag it's a dry-run preview.")
@click.option("--allow-partial", "allow_partial", is_flag=True,
              help="Proceed even if some columns could not be analyzed "
                   "(they will NOT be masked). Off by default: an incomplete "
                   "scan aborts masking.")
@click.option("--show-values", "show_values", is_flag=True,
              help="Show real original values in the preview. By default "
                   "originals are redacted so sensitive data does not end up "
                   "in terminals, scrollback, or CI logs.")
def mask(config_path: str, apply: bool, allow_partial: bool, show_values: bool) -> None:
    """Mask sensitive columns. Dry-run preview unless --apply is given."""
    config = _load(config_path)
    _warn_llm_data_egress(config)
    if config.masking.seed == "dbmask":
        click.echo(
            "[warn] masking.seed is the publicly-known default ('dbmask'). "
            "For guessable values, anyone can recompute the mapping. Set a "
            "private seed, e.g.  masking.seed: ${DBMASK_SEED}",
            err=True,
        )
    # The CLI flag is the single source of truth for write access. Without
    # --apply this is ALWAYS a dry run — even if the YAML says
    # `masking.dry_run: false`. (Config-level dry_run still exists for library
    # users driving MaskingEngine/Runner directly.) Previously the flag only
    # switched dry-run OFF, so a config with `dry_run: false` wrote to the
    # database while the CLI printed "DRY-RUN (no changes written)".
    config.masking.dry_run = not apply

    with _runner(config) as runner:
        report = runner.scan()
        for err in report.errors:
            click.echo(f"[error] scan: {err}", err=True)
        if report.errors and not allow_partial:
            click.echo(
                f"\nAborting: {len(report.errors)} column(s) could not be "
                "analyzed, and unanalyzed columns would be silently left "
                "unmasked. Fix the errors above, or re-run with "
                "--allow-partial to mask only what was scanned successfully.",
                err=True,
            )
            sys.exit(2)
        from dbmask.masking.rules import MaskingValidationError

        try:
            results = runner.mask(report.decisions)
        except MaskingValidationError as exc:
            raise click.ClickException(
                f"Masking stopped: {exc}. Earlier committed batches may have changed; "
                "review the error and restart from an untouched test copy."
            ) from exc

    mode = "APPLIED" if apply else "DRY-RUN (no changes written)"
    click.echo(f"=== Masking {mode} ===")
    previewed = False
    for res in results:
        click.echo(f"\n{res.schema}.{res.table}  "
                   f"(scanned={res.rows_scanned}, written={res.rows_written})")
        for plan in res.columns:
            click.echo(f"  - {plan.column}: rule={plan.rule} -> strategy={plan.strategy_name}")
        for plan in res.skipped_columns:
            click.echo(
                f"  ! {plan.column}: NOT MASKED — primary-key column. "
                "Rewriting key values is not supported (it would break row "
                "addressing and foreign keys); this column still holds its "
                "original data.",
                err=True,
            )
        for sample in res.preview[:3]:
            previewed = True
            before = sample["before"]
            if not show_values:
                before = {k: _shape_only(v) for k, v in before.items()}
            click.echo(f"    before: {before}")
            click.echo(f"    after : {sample['after']}")
    if previewed and not show_values:
        click.echo("\n(original values are redacted; pass --show-values to display them)")

    unknown = report.unknown
    if unknown:
        click.echo(
            f"\n[warn] {len(unknown)} column(s) could not be classified and "
            "were NOT masked:",
            err=True,
        )
        for d in unknown:
            click.echo(f"  ? {d.schema}.{d.table}.{d.column} — {d.detail}", err=True)
        click.echo(
            "  Mark them in the overrides file (detection.overrides_file) or "
            "enable the LLM fallback to classify them.",
            err=True,
        )

    if not apply:
        click.echo("\nRe-run with --apply to write these changes back.")


@cli.command()
@click.option("--config", "config_path", required=True, help="Path to config YAML.")
@click.option("--json", "as_json", is_flag=True, help="Emit records including review metadata.")
@click.option("--audit", is_flag=True, help="Show imported record revisions as JSON.")
def history(config_path: str, as_json: bool, audit: bool) -> None:
    """Show all decisions recorded in the history store."""
    config = _load(config_path)
    if not config.history.enabled:
        click.echo("History is disabled in config.")
        return
    with history_backend(config.history) as store:
        if audit and isinstance(store, FileHistoryStore):
            raise click.ClickException("File history uses .bak snapshots; --audit is SQL-only")
        if audit or as_json:
            records = store.audit_records() if audit else [r.to_dict() for r in store.records_for_review()]
            click.echo(json.dumps(records, indent=2))
            return
        for d in store.all_decisions():
            rule = f" -> {d.rule}" if d.rule else ""
            click.echo(f"{d.key}: {d.sensitivity.value}{rule} ({d.source}, {d.review_status}, user_id={d.user_id})")


@cli.command()
@click.option("--config", "config_path", required=True, help="Path to config YAML.")
@click.option("--limit", default=50, show_default=True, help="Max pairs to list.")
@click.option("--json", "as_json", is_flag=True, help="Emit the pairs as JSON.")
def seeds(config_path: str, limit: int, as_json: bool) -> None:
    """Show the tracked (original -> masked) pairs in the seed map.

    Original values are not stored — only a salted hash — so each pair is shown
    by its seed token rather than the original value.
    """
    config = _load(config_path)
    from dbmask.masking.seed_store import DEFAULT_SEED_MAP_URL, SeedStore

    seed_map = config.masking.seed_map
    if not seed_map.enabled:
        click.echo("Seed map is disabled in config (masking.seed_map.enabled: false).")
        return

    with SeedStore(
        url=seed_map.url or DEFAULT_SEED_MAP_URL, salt=seed_map.salt
    ) as store:
        total = store.count()
        pairs = store.all_pairs(limit=limit)

    if as_json:
        click.echo(json.dumps(pairs, indent=2, default=str))
        return

    click.echo(f"Tracked pairs: {total}")
    if pairs:
        click.echo(f"\n{'SEED':18} {'SCOPE':18} MASKED VALUE")
        for p in pairs:
            click.echo(f"{p['seed']:18} {p['scope']:18} {p['masked_value']}")
    if total > len(pairs):
        click.echo(f"\n... {total - len(pairs)} more (use --limit).")


@cli.command("history-import")
@click.option("--config", "config_path", required=True, help="Path to config YAML.")
@click.option("--file", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--sheet", default="history", show_default=True, help="XLSX worksheet name.")
@click.option("--dry-run", is_flag=True, help="Validate the full batch without changing decision records.")
@click.option("--replace-approved", is_flag=True, help="Explicitly replace an approved record at its exported revision.")
def history_import(config_path: str, input_path: str, sheet: str, dry_run: bool, replace_approved: bool) -> None:
    """Import reviewed historical decisions; never changes the source data."""
    from dbmask.history.files import read_history_file
    from dbmask.history.store import HistoryStore

    config = _load(config_path)
    if not config.history.enabled:
        raise click.ClickException("History is disabled in config.")
    try:
        if config.history.source_file:
            from pathlib import Path

            if Path(input_path).resolve() != Path(config.history.source_file):
                raise HistoryValidationError(
                    "File mode reads history.source_file directly. To save an exported review, "
                    "use history-writeback; SQL history-import is available without source_file"
                )
            with FileHistoryStore(config.history.source_file, sheet=config.history.sheet) as file_store:
                rows = file_store.records_for_review()
                result = {"source_file": str(file_store.path), "records": len(rows),
                          "approved": sum(r.review_status == "approved" for r in rows),
                          "pending": sum(r.review_status == "pending" for r in rows),
                          "warnings": [r.reason for r in rows if r != file_store.original[r.key]],
                          "dry_run": dry_run, "written": False}
            click.echo(json.dumps(result, indent=2))
            return
        records = read_history_file(input_path, sheet=sheet)
        with HistoryStore(config.history.url) as store:
            result = store.import_records(records, dry_run=dry_run, replace_approved=replace_approved)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(result, indent=2))


@cli.command("history-export")
@click.option("--config", "config_path", required=True, help="Path to config YAML.")
@click.option("--output", required=True, type=click.Path(dir_okay=False))
def history_export(config_path: str, output: str) -> None:
    """Export current records, suggestions and legacy evidence for human review."""
    from dbmask.history.files import write_history_file

    config = _load(config_path)
    if not config.history.enabled:
        raise click.ClickException("History is disabled in config.")
    try:
        with history_backend(config.history) as store:
            records = store.records_for_review()
        if isinstance(store, FileHistoryStore):
            from dbmask.history.writeback import export_review

            export_review(store, output, records)
        else:
            write_history_file(output, records)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Exported {len(records)} records to {output}")


@cli.command("history-writeback")
@click.option("--config", "config_path", required=True, help="Path to config YAML.")
@click.option("--file", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--sheet", default="history", show_default=True, help="Review worksheet (source sheet is configured).")
@click.option("--reviewed-by", required=True, help="Person approving the changed decisions.")
@click.option("--apply", is_flag=True, help="Merge approved rows into the original history file; otherwise preview.")
def history_writeback(config_path: str, input_path: str, sheet: str, reviewed_by: str, apply: bool) -> None:
    """Save human-reviewed decisions to the configured original CSV/XLSX/MD."""
    from dbmask.history.writeback import writeback

    config = _load(config_path)
    if not config.history.enabled or not config.history.source_file:
        raise click.ClickException("history-writeback requires enabled history.source_file")
    try:
        with FileHistoryStore(config.history.source_file, sheet=config.history.sheet) as store:
            result = writeback(store, input_path, reviewed_by=reviewed_by, apply=apply, sheet=sheet)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(result, ensure_ascii=False, indent=2))


@cli.command()
def strategies() -> None:
    """List the available masking strategies."""
    from dbmask.masking.rules import STRATEGIES

    for name in sorted(STRATEGIES):
        click.echo(name)


@cli.command()
@click.option("--config", "config_path", required=True, help="Path to config YAML.")
@click.option("--json", "as_json", is_flag=True, help="Emit the report as JSON.")
@click.option("--strict", "strict", is_flag=True,
              help="Warnings and skipped checks also fail the run. Use in CI "
                   "when 'could not verify' must not pass the gate.")
def validate(config_path: str, as_json: bool, strict: bool) -> None:
    """Validate the masked database against the original (source) database.

    Runs three checks: row counts, schema elements, and masking completeness.
    Exits non-zero if any check fails (handy for CI / Jenkins gates).
    """
    config = _load(config_path)
    with _runner(config) as runner:
        report = runner.validate()

    passed = report.passed_strict if strict else report.passed
    summary = report.summary()

    if as_json:
        click.echo(json.dumps([i.to_dict() for i in report.issues], indent=2))
    else:
        icons = {"pass": "✓", "fail": "✗", "warning": "!", "skipped": "-", "error": "E"}
        for issue in report.issues:
            icon = icons.get(issue.status.value, "?")
            click.echo(f"[{icon}] {issue.check:22} {issue.location}: {issue.message}")
        click.echo("\n--- Validation summary ---")
        for status, count in summary.items():
            click.echo(f"  {status:8}: {count}")

        caveats = []
        if summary.get("warning"):
            caveats.append(f"{summary['warning']} warning(s)")
        if summary.get("skipped"):
            caveats.append(f"{summary['skipped']} skipped")
        if passed and caveats and not strict:
            click.echo(
                f"\nRESULT: PASSED ✓ — with {', '.join(caveats)}: not everything "
                "could be verified (use --strict to fail on this)"
            )
        else:
            click.echo("\nRESULT: " + ("PASSED ✓" if passed else "FAILED ✗"))

    if not passed:
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    cli()
