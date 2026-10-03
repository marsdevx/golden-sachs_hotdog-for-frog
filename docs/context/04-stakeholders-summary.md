# 04. Stakeholders (summary)

Full version: `stakeholders.md` in the repo root (sections 4-7: incidents, personas, conflict map, market landscape, glossary). This is the compressed version for quick grounding.

**Warning:** the CISO / developer / compliance interviews were **simulated by Claude**. They are hypotheses, not real Goldman Sachs statements. Never quote them as real in code, docs, README or pitch.

## Shared insight
Nobody did anything wrong on purpose. **Nobody saw the whole system.** Three needs come up everywhere:
**visibility** (what is the agent doing), **attribution** (who owns it), **provability** (can we show it).

## Primary operator (from the real mentor): IT department / platform team
Mandates "integrate via the gateway from Monday". Needs: easy rollout, toggles/sliders, no developer code changes.

## Personas
| Persona | Core value | Wants | Fears |
|---|---|---|---|
| **CISO** | Control | Owner per agent; hard **read vs write/irreversible** boundary (irreversible needs confirmation); call limits; alert at ~10x normal volume; proof, not just blocking. Minimum = owner + irreversible actions + call limit (~80% of value). | Yet another tool/portal; 6-month config; policies only engineers can write. **Control must live outside the model** (deterministic, auditable, not prompt-injectable). |
| **Senior developer** | Clarity and speed | **Constraints as code** (`max_scope: read_only`, `tables: [clients_public]`), effective immediately; an "agent passport" (access, last-24h actions, deviations) as a notification; a sandbox / dry-run mode; **explained denials** (what was tried, which rule fired). | Unexplained blocks, manual forms, 2-week access reviews. Those lead to **shadow agents**. |
| **Chief Compliance Officer** | Evidence | **Regulator-grade, immutable log**: who asked, which data was read, which tool was called, what came back, model version, active rules. **Data lineage with sensitivity labels** in answers. Agent treated like an employee (owner, permitted actions, same approvals). Plain-language rules, tested on history before enabling. **Proof by negation** ("agent X never received category-Y data this quarter"). | Black-box AI deciding what a violation is; "works 99%"; pretty dashboard with an editable log. |

Main contradiction: CISO wants explicit declarations at deploy, the developer wants them inferred from behaviour. Universal constraint: nobody wants another system configured by hand.

## Three composite incidents (use as demo scenarios)
1. **Information-barrier leak**: an M&A agent in a shared chat reveals client names to a trader. Worse case is hidden influence: a trading answer silently based on M&A data. → asker-context-aware access, sensitivity labels, lineage in logs.
2. **Unauthorised action in a chain**: an onboarding agent "fixes" a jurisdiction field via an adjacent service, which freezes a client account. → read/write boundary, irreversible-action approval, governing tool calls *between* approved steps.
3. **Cost feedback loop**: a market-monitoring agent goes from 200 calls/day to 40,000 calls in 4 h. Found out from the bill. 3 h to find the owner. → rate/budget limits, loop detection, anomaly alert, owner attribution.

## Key question compliance asks of us
Are we building something that **prevents** problems or something that lets the bank **prove** they did not happen? Best answer: **both**. Preventive controls + immutable, queryable evidence trail.
