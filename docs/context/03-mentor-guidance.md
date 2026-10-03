# 03. Mentor guidance (Goldman Sachs mentor conversation, 3 Oct 2026)

Source: `AI Control Layer Our Transcript with menthors.txt` (auto-transcribed, paraphrased here). This is the closest thing we have to "what the judges want to see". It carries more weight than the simulated stakeholder interviews.

## Framing
- Good name for the thing: **"AI firewall"**. More precisely a **proxy** than just an HTTP server.
- Picture: a landscape of **agents** → **LLMs** → **resources** (databases, MCP servers, APIs). The layer controls those interactions: **authentication, access control, input validation/filtering (to LLMs and MCPs), output filtering, token spend, resource access**.
- Scope is **internal** (employees and internal agents inside the organisation), **not** defending against external attackers. Think "changing internal rules about processes and pipelines".

## Scope advice
- **Pick 2-3, at most 5 controls.** Make **one really, really good**, with parameters, then show how the other 4-5 plug in. Show it's not only access control: input validation, output filtering and token limits all exist.
- The mentor will look at it like this: an agent works with **no controls** (everything passes) → then we **enable control 1, control 2, control 3** and show the behaviour change.

## The canonical demo pattern the mentor sketched
1. Agent talks to an MCP/LLM through the layer.
2. IT person **ticks a box**: control "Output filtering" is enabled → personal data is removed from output.
3. IT person moves a **slider / extends the control**: "no personal data" **+ "no credit data"** → second attempt removes more.
4. The IT person reconfigured the system; **for the agent it was completely transparent** (no code change).

## Stakeholders (mentor's view)
- The buyer/operator is the **IT department**, which says: "From Monday you must integrate via this gateway to access resources." On Friday developers don't care. On Monday they go through the new capability.
- Deployment pattern is open: one **central gateway** or **micro-gateways next to resources**. Both are valid. Mention it as a scalability story.
- Obvious value consumers: **security department** and **risk & compliance** ("what the heck is happening").
- **Risk-weighted actions:** an agent trying to **book a trade** is a much bigger risk than one **filling an Excel form on an internal wiki**. Score requests by confidence and impact.

## On our M&A / trading information-barrier use case
- Mentor: **"That's a really good use case"**, "an amazing use case to show that".
- Caveat: real investment banks have a hard **Chinese wall** between investment banking and markets, so it would not happen at that level in reality. Present it as **conceptual**.
- Suggested approach: **use an LLM to generate synthetic data** for the use case and simulate the flow.

## Prevention + detection
- Ideally **preventive controls**. Also valuable: **log every interaction**, then run **post-hoc analysis tooling** over the logs to detect dangerous patterns (the firewall sees all interactions). Both are good.

## Placement and integration
- The layer can sit before the agent (user → agent input) and/or after the agent (agent → LLM/tools). Choose by **applicability**: can it be deployed **transparently** (e.g. just change the endpoint / base URL), or must developers wrap their agent? **Demonstrate how easy deployment is in a "Monday release cycle"**.
- **Modular architecture:** organisations use internally and externally hosted models of all kinds, so provide **pluggable adapters** (Claude, Gemini, local models). Adapters may optionally reuse a provider's own built-in safety features.

## Unanswered in the conversation
- Whether judges run it on their machines or ours, and whether external API keys are OK. Asked but not clearly answered. Still open.
- The mentor gave a talk on real-life use cases ("track three", ~30 min after the conversation) as inspiration for what to monitor. If someone attended, add notes here.
