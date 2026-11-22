# EdgeMesh Hybrid Copilot (`#BuildHybridAI 2026`)

Privacy-first hybrid AI router and copilot workbench built on **Firebase AI Logic (`firebase/ai`)** and **Chrome Built-in Gemini Nano** (`LanguageModel` / Prompt API).

## Architecture Overview

EdgeMesh enforces deterministic client-side **PII detection & redaction** and **complexity/token gating** *before* dispatching any prompt to Google's hybrid `getGenerativeModel()` API:

1. **PII & Secret Scanner (`src/routingPolicy.ts`)**: Scans every prompt in browser memory for API keys (`sk-`, `AIza`, `ghp_`, `xoxb-`), SSNs, Medical Record Numbers (`MRN-*`), emails, phone numbers, and **Luhn-validated payment card PANs**.
2. **Fail-Closed Hybrid Mode Selection**:
   - `InferenceMode.ONLY_ON_DEVICE`: Enforced automatically whenever unredacted PII is detected (without explicit redaction consent), Strict Privacy Lock is enabled, or the device is offline. Fails closed (`blocked: true`) when offline with no local Gemini Nano runtime — zero bytes leave the device.
   - `InferenceMode.PREFER_ON_DEVICE`: Used for low/medium complexity workloads (`complexityScore <= 62` and `<= 1800` estimated tokens) to run free locally via Chrome Gemini Nano (`$0.00` marginal token cost), with seamless Firebase fallback if `onDeviceAvailable` is false.
   - `InferenceMode.ONLY_IN_CLOUD`: Used for high-complexity reasoning (`gemini-2.5-flash-lite`) only when online and explicitly scrubbed of every PII token (`[REDACTED_*]`).
3. **Firebase AI Logic SDK Binding (`src/hybridRouter.ts`)**:
   - Uses `initializeApp`, `getAI(app, { backend: new GoogleAIBackend() })`, `getGenerativeModel(ai, { mode, inCloudParams })`, `model.initializeDeviceModel(onDownloadProgress)` (triggered explicitly by user button click), and inspects `response.inferenceSource` (`on_device` vs `in_cloud`).
   - Includes a deterministic offline/sandbox evaluation mode so judges can verify routing policies, Luhn redaction diffs, fail-closed locks, and cost savings immediately without configuring API keys, or bind live Firebase credentials in the UI drawer.

## Quick Start & Build

```bash
npm install
npm run type-check
npm run build:docs
npm test
```

- Standalone single-file web workbench: `docs/index.html` (can be opened directly in any modern browser or hosted on GitHub Pages).
- Mathematical & security fuzz audit (`300` adversarial multi-secret cases via `lambai_overlord.py`):

```bash
python verify_hybrid_router.py
```

## Project Layout

- `src/routingPolicy.ts` — Deterministic PII redactor, Luhn checksum validator, token/complexity estimator, and routing engine.
- `src/hybridRouter.ts` — Firebase AI Logic (`firebase/ai` v13.4.0) hybrid SDK adapter, Chrome Built-in AI probe, and telemetry ledger.
- `src/main.ts`, `src/styles.css`, `index.html` — Interactive workbench UI.
- `scripts/build-docs.mjs` — Single-file HTML bundler emitting `docs/index.html`.
- `tests/hybridRouter.test.mjs` — Node unit test suite covering Luhn PAN validation, PII redaction, Firebase `InferenceMode` mapping, and offline fail-closed guarantees.
- `verify_hybrid_router.py` — 300-case adversarial leak & offline policy audit.
