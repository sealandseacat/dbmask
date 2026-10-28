# LLM detection (optional)

Patterns decide the common cases for free. The LLM layer exists for the long
tail — columns whose values are unusual enough that no heuristic fires. It
is **off by default**, consulted only when overrides, history and patterns
were all inconclusive, and capped by a token budget.

## Decision flow

The LLM sees, per undecided column: the column name and (by default) up to
`llm.sample_size` distinct sampled values. It answers with
sensitive/not-sensitive, a rule label (`email`, `address`, …) and a
confidence. Accepted answers are saved as pending suggestions; only applicable
approved imports are reused from history. Invalid or uncertain answers become
`UNKNOWN`, are not saved as decisions and do not authorize masking.

The shared parser accepts a single JSON object (optionally one complete fenced
JSON block), not a prose or keyword-based guess. It requires a genuine JSON
boolean, a finite numeric confidence between 0 and 1, and a valid rule for a
sensitive answer (`null` for a non-sensitive answer). Missing or mistyped
fields, ambiguous output, and responses such as `I cannot determine this.`
require review. Custom provider results are checked by the pipeline too.

`llm.min_confidence` defaults to **0.8**. Valid answers below that threshold
become `UNKNOWN` for either sensitivity outcome. The threshold is configurable
from 0 to 1; setting 0 explicitly disables only the confidence gate, never
response validation. Review UNKNOWNs through overrides or approved history.
Provider raw responses are not copied into decision details or history.

## Providers

### OpenAI / OpenAI-compatible

```yaml
llm:
  enabled: true
  provider: openai
  model: gpt-4o-mini
  api_key: ${OPENAI_API_KEY}
  base_url:            # blank = api.openai.com; set for Azure/OpenRouter/gateways
  max_tokens_budget: 1000000
  sample_size: 50
  min_confidence: 0.8
```

### Fully local (nothing leaves your network)

Ollama:

```yaml
llm:
  enabled: true
  provider: local
  model: llama3
  base_url: http://localhost:11434     # api_style defaults to "ollama"
```

LM Studio, vLLM, or any OpenAI-compatible local server:

```yaml
llm:
  enabled: true
  provider: local
  model: qwen2.5-7b-instruct
  base_url: http://localhost:1234
  api_style: openai                    # /v1/chat/completions
```

## Privacy controls

Sending column samples to an external provider is data egress from the
database. dbmask makes that explicit and controllable:

- **The CLI warns before anything is sent** — `scan`/`mask` print where the
  values will go whenever an external provider is enabled.
- **Metadata-only mode** — `llm.send_values: false` sends the *column name
  only*; the prompt tells the model to judge from the name alone. Weaker
  detection, zero value egress:

    ```yaml
    llm:
      enabled: true
      provider: openai
      send_values: false
    ```

- **Local providers** — with `provider: local`, samples go to your own
  machine/network only.
- **Budget** — `max_tokens_budget` is a hard stop; when it is reached the
  scan reports an error (and `mask` then refuses to run rather than treating
  unscanned columns as safe).

## Practical guidance

- Prefer patterns + overrides for anything regulated; use the LLM to *find*
  candidates, then pin the decision in the overrides file. Overrides beat
  the LLM on every later run.
- The LLM's answer is stored in history with `source=llm` — audit them with
  `dbmask history --config …`.
- Confidence is the model's self-report, not a calibrated probability.
  Passing `min_confidence` is a review policy, not proof of detection accuracy.
  A public benchmark with per-rule precision/recall is on the
  [roadmap](roadmap.md).
