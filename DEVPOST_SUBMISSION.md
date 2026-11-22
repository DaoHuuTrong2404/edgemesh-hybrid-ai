# EdgeMesh Hybrid Copilot — Devpost Submission (`#BuildHybridAI 2026`)

## Inspiration
Teams adopting Gemini Nano on Chrome and Firebase AI Logic quickly hit a trust gap: developers want zero-cost, low-latency on-device execution for routine tasks and guaranteed privacy for sensitive customer or clinical records, while still escalating heavy architectural or SQL reasoning to `gemini-2.5-flash-lite` in the cloud. Relying on ad-hoc client `if/else` checks risks leaking SSNs, API keys, or payment PANs during automatic cloud fallback.

## What it does
**EdgeMesh Hybrid Copilot** wraps Firebase AI Logic's hybrid `getGenerativeModel()` modes (`InferenceMode.ONLY_ON_DEVICE`, `InferenceMode.PREFER_ON_DEVICE`, and `InferenceMode.ONLY_IN_CLOUD`) behind a deterministic pre-egress privacy & complexity firewall:
- **Zero-Egress PII Guard:** Detects and redacts SSNs, Medical Record Numbers (`MRN-*`), emails, phone numbers, developer secrets (`sk-`, `AIza`, `ghp_`, `xoxb-`), and Luhn-validated credit cards directly in browser RAM.
- **Cost & Complexity Router:** Scores prompt complexity and token footprint locally; trivial/medium tasks run via `PREFER_ON_DEVICE` (`$0.00` token spend), while complex multi-step engineering tasks escalate to Firebase cloud **strictly after PII scrubbing**.
- **Fail-Closed Air-Gap Mode:** When offline without Gemini Nano weights ready, EdgeMesh refuses cloud fallback cleanly (`blocked: true`) instead of silently queuing sensitive prompts.
- **Live Audit Workbench:** Side-by-side comparison of local input vs. exact outbound egress payload, real `response.inferenceSource` tracking, warm-up progress via `model.initializeDeviceModel()`, and a live decision ledger.

## How we built it
- **TypeScript + Vite + Firebase SDK (`firebase@13.4.0` / `@firebase/ai`):** Pure policy engine (`src/routingPolicy.ts`) decoupled from Firebase SDK integration (`src/hybridRouter.ts`) so the routing contract is unit-tested and mathematically audited independently of network credentials.
- **Standalone Build Pipeline:** `scripts/build-docs.mjs` inlines Vite's compiled bundle into a zero-server `docs/index.html` for instant GitHub Pages hosting and reproducible offline inspection.

## Challenges we ran into
Preventing silent raw-secret leaks during `PREFER_ON_DEVICE` cloud fallback required enforcing that `outboundPrompt` ALWAYS binds to `sanitizedPrompt` whenever `mode !== ONLY_ON_DEVICE`, plus decoupling false-positive numeric IDs from real credit cards using Luhn modulus verification.

## Accomplishments that we're proud of
- Verified `0` raw secret leaks and `0` offline policy violations across 300 randomized multi-entity adversarial prompts (`verify_hybrid_router.py`).
- Full strict TypeScript compilation (`tsc --noEmit`) with official Firebase AI Logic `HybridParams`, `InferenceMode`, `InferenceSource`, and `initializeDeviceModel` typings.
- Instant 1-click preset workflows (`Clinical PII`, `Edge Triage`, `Redacted Cloud RCA`, `Air-Gapped Fail-Closed`) in a crisp responsive telemetry UI.

## What we learned
Pairing Firebase's hybrid `InferenceMode` primitives with an explicit local redaction diff turns hybrid AI from an invisible heuristic into a user-auditable privacy contract.

## What's next for EdgeMesh Hybrid Copilot
Streaming chunk-by-chunk diff inspection (`generateContentStream`), IndexedDB encrypted local audit logs, and Chrome extension side-panel deployment.
