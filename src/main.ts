import {
	EdgeMeshHybridEngine,
	probeBrowserBuiltInAi,
	type DispatchExecutionResult,
} from "./hybridRouter.ts";
import {
	evaluateRoutingPolicy,
	type PolicyInferenceMode,
} from "./routingPolicy.ts";

interface ScenarioPreset {
	id: string;
	online: boolean;
	onDeviceAvailable: boolean;
	strictPrivacyLock: boolean;
	allowCloudAfterRedaction: boolean;
	prompt: string;
}

const PRESETS: Record<string, ScenarioPreset> = {
	"clinical-pii": {
		id: "clinical-pii",
		online: true,
		onDeviceAvailable: true,
		strictPrivacyLock: false,
		allowCloudAfterRedaction: false,
		prompt:
			"Patient MRN-849201 (SSN 123-45-6789, card 4532-0151-1283-0366, contact +84 912 345 678) presents acute dyspnea and pulse 118 bpm. Draft bedside handoff summary.",
	},
	"edge-triage": {
		id: "edge-triage",
		online: true,
		onDeviceAvailable: true,
		strictPrivacyLock: false,
		allowCloudAfterRedaction: true,
		prompt:
			"Summarize shift handoff: Ward B has 2 stable telemetry patients cleared for morning discharge and 1 pending cardiology consult.",
	},
	"cloud-architecture": {
		id: "cloud-architecture",
		online: true,
		onDeviceAvailable: true,
		strictPrivacyLock: false,
		allowCloudAfterRedaction: true,
		prompt:
			"Analyze distributed root-cause deadlock in payment microservice owned by dev-ops@acme.io using key sk-prod9876543210abcd.\nCompare optimistic locking vs partitioned queue migration trade-offs and produce benchmark rollout schema:\n```\nBEGIN; SELECT * FROM ledger WHERE id = 42 FOR UPDATE; COMMIT;\n```",
	},
	"airgapped-lock": {
		id: "airgapped-lock",
		online: false,
		onDeviceAvailable: false,
		strictPrivacyLock: true,
		allowCloudAfterRedaction: false,
		prompt:
			"Field responder offline checklist with API key AIzaSyDemoKey0123456789abcdef012345 — confirm fail-closed zero egress.",
	},
};

const engine = new EdgeMeshHybridEngine();

const el = {
	runtimeBadge: document.getElementById("runtime-channel-badge") as HTMLElement,
	probeBadge: document.getElementById("probe-status-badge") as HTMLElement,
	presetButtons: Array.from(
		document.querySelectorAll<HTMLButtonElement>(".btn-preset"),
	),
	toggleOnline: document.getElementById("toggle-online") as HTMLInputElement,
	toggleNano: document.getElementById("toggle-nano") as HTMLInputElement,
	toggleStrict: document.getElementById(
		"toggle-strict-privacy",
	) as HTMLInputElement,
	toggleAllowRedacted: document.getElementById(
		"toggle-allow-redacted-cloud",
	) as HTMLInputElement,
	sliderComplexity: document.getElementById(
		"slider-complexity",
	) as HTMLInputElement,
	labelComplexity: document.getElementById("label-complexity") as HTMLElement,
	promptInput: document.getElementById("prompt-input") as HTMLTextAreaElement,
	btnDispatch: document.getElementById("btn-dispatch") as HTMLButtonElement,
	btnWarmup: document.getElementById("btn-warmup") as HTMLButtonElement,
	btnReset: document.getElementById("btn-reset") as HTMLButtonElement,
	warmupStatus: document.getElementById("warmup-status") as HTMLElement,
	cfgApiKey: document.getElementById("cfg-api-key") as HTMLInputElement,
	cfgProjectId: document.getElementById("cfg-project-id") as HTMLInputElement,
	cfgAppId: document.getElementById("cfg-app-id") as HTMLInputElement,
	cfgCloudModel: document.getElementById("cfg-cloud-model") as HTMLInputElement,
	btnConnectFirebase: document.getElementById(
		"btn-connect-firebase",
	) as HTMLButtonElement,
	btnDisconnectFirebase: document.getElementById(
		"btn-disconnect-firebase",
	) as HTMLButtonElement,
	kpiLocalShare: document.getElementById("kpi-local-share") as HTMLElement,
	kpiCallCounts: document.getElementById("kpi-call-counts") as HTMLElement,
	kpiUsdSaved: document.getElementById("kpi-usd-saved") as HTMLElement,
	kpiUsdSpent: document.getElementById("kpi-usd-spent") as HTMLElement,
	kpiPiiCount: document.getElementById("kpi-pii-count") as HTMLElement,
	kpiLatency: document.getElementById("kpi-latency") as HTMLElement,
	kpiLastSource: document.getElementById("kpi-last-source") as HTMLElement,
	decisionModePill: document.getElementById(
		"decision-mode-pill",
	) as HTMLElement,
	nodePii: document.getElementById("node-pii") as HTMLElement,
	nodePiiDetail: document.getElementById("node-pii-detail") as HTMLElement,
	nodeRouter: document.getElementById("node-router") as HTMLElement,
	nodeRouterDetail: document.getElementById(
		"node-router-detail",
	) as HTMLElement,
	nodeTarget: document.getElementById("node-target") as HTMLElement,
	nodeTargetDetail: document.getElementById(
		"node-target-detail",
	) as HTMLElement,
	decisionReason: document.getElementById("decision-reason") as HTMLElement,
	piiBadgeList: document.getElementById("pii-badge-list") as HTMLElement,
	rawPromptPreview: document.getElementById(
		"raw-prompt-preview",
	) as HTMLElement,
	egressLockBadge: document.getElementById("egress-lock-badge") as HTMLElement,
	outboundPromptPreview: document.getElementById(
		"outbound-prompt-preview",
	) as HTMLElement,
	responseMetaBadge: document.getElementById(
		"response-meta-badge",
	) as HTMLElement,
	copilotResponse: document.getElementById("copilot-response") as HTMLElement,
	ledgerTbody: document.getElementById("ledger-tbody") as HTMLElement,
};

function getPillClass(mode: PolicyInferenceMode, blocked: boolean): string {
	if (blocked) return "pill pill-blocked";
	if (mode === "ONLY_ON_DEVICE") return "pill pill-local";
	if (mode === "PREFER_ON_DEVICE") return "pill pill-prefer";
	return "pill pill-cloud";
}

function readCurrentPolicyInput() {
	return {
		prompt: el.promptInput.value,
		online: el.toggleOnline.checked,
		onDeviceAvailable: el.toggleNano.checked,
		strictPrivacyLock: el.toggleStrict.checked,
		allowCloudAfterRedaction: el.toggleAllowRedacted.checked,
		localMaxComplexity: Number(el.sliderComplexity.value),
	};
}

function renderLivePreview(): void {
	const input = readCurrentPolicyInput();
	el.labelComplexity.textContent = `${input.localMaxComplexity} / 100`;

	const decision = evaluateRoutingPolicy(input);

	el.decisionModePill.className = getPillClass(decision.mode, decision.blocked);
	el.decisionModePill.textContent = decision.blocked
		? `${decision.mode} · BLOCKED`
		: decision.mode;

	el.nodePii.className =
		"pipe-node " + (decision.containsPii ? "is-warn" : "is-local");
	el.nodePiiDetail.textContent = decision.containsPii
		? `${decision.findings.length} PII entities flagged (${[...new Set(decision.findings.map((f) => f.kind))].join(", ")})`
		: "No sensitive PII detected";

	el.nodeRouter.className = "pipe-node is-cloud";
	el.nodeRouterDetail.textContent = `Complexity ${decision.complexityScore}/100 · ~${decision.estimatedTokens} tok`;

	el.nodeTarget.className =
		"pipe-node " +
		(decision.blocked
			? "is-blocked"
			: decision.mode === "IN_CLOUD"
				? "is-cloud"
				: "is-local");
	el.nodeTargetDetail.textContent = decision.blocked
		? "Blocked (Fail-Closed)"
		: decision.targetModel;

	el.decisionReason.textContent = decision.reason;

	el.rawPromptPreview.textContent = input.prompt || "(Empty prompt)";
	el.piiBadgeList.textContent =
		decision.findings.length > 0
			? decision.findings.map((f) => f.kind).join(" · ")
			: "No PII";

	if (decision.blocked) {
		el.egressLockBadge.className = "pill pill-blocked";
		el.egressLockBadge.textContent = "Zero Network Egress (Blocked)";
		el.outboundPromptPreview.textContent =
			"[BLOCKED BY FAIL-CLOSED POLICY] Payload withheld locally; cloud fallback prohibited.";
	} else if (decision.mode === "ONLY_ON_DEVICE") {
		el.egressLockBadge.className = "pill pill-local";
		el.egressLockBadge.textContent = "Local-Only (Zero Egress)";
		el.outboundPromptPreview.textContent =
			"[IN-BROWSER GEMINI NANO ONLY — 0 BYTES SENT OVER NETWORK]\n\n" +
			decision.outboundPrompt;
	} else {
		el.egressLockBadge.className =
			decision.findings.length > 0 ? "pill pill-prefer" : "pill pill-cloud";
		el.egressLockBadge.textContent =
			decision.findings.length > 0
				? "PII Scrubbed Before Egress"
				: "Clean Egress Ready";
		el.outboundPromptPreview.textContent = decision.sanitizedPrompt;
	}
}

function renderMetricsAndLedger(lastResult?: DispatchExecutionResult): void {
	const m = engine.getMetrics();
	const localPct =
		m.totalCalls > 0 ? Math.round((m.onDeviceCalls / m.totalCalls) * 100) : 0;

	el.kpiLocalShare.textContent = `${localPct}%`;
	el.kpiCallCounts.textContent = `${m.onDeviceCalls} local / ${m.inCloudCalls} cloud / ${m.blockedCalls} blocked`;
	el.kpiUsdSaved.textContent = `$${m.estimatedUsdSaved.toFixed(4)}`;
	el.kpiUsdSpent.textContent = `Spent: $${m.estimatedUsdSpent.toFixed(4)}`;
	el.kpiPiiCount.textContent = String(m.piiEntitiesShielded);
	el.kpiLatency.textContent = `${m.avgLatencyMs} ms`;

	if (lastResult) {
		el.kpiLastSource.textContent = `Last: ${lastResult.actualSource}`;
		el.responseMetaBadge.className = getPillClass(
			lastResult.decision.mode,
			lastResult.actualSource === "blocked",
		);
		el.responseMetaBadge.textContent = `${lastResult.actualSource.toUpperCase()} · ${lastResult.latencyMs}ms · ${lastResult.runtimeChannel}`;
		el.copilotResponse.textContent = lastResult.responseText;

		el.runtimeBadge.className =
			lastResult.runtimeChannel === "LIVE_FIREBASE_AI" ||
			lastResult.runtimeChannel === "LIVE_CHROME_NANO"
				? "pill pill-local"
				: "pill pill-info";
		el.runtimeBadge.textContent = `Channel: ${lastResult.runtimeChannel}`;
	}

	const rows = engine.getHistory();
	el.ledgerTbody.innerHTML = "";
	if (rows.length === 0) {
		const tr = document.createElement("tr");
		tr.innerHTML =
			'<td colspan="5" class="muted-cell">Run a preset or dispatch a prompt to inspect live telemetry.</td>';
		el.ledgerTbody.appendChild(tr);
		return;
	}

	for (const row of rows.slice(0, 8)) {
		const tr = document.createElement("tr");
		tr.innerHTML = `
			<td>${row.sdkInferenceMode}</td>
			<td>${row.actualSource}</td>
			<td>${row.decision.findings.length} (${row.egressVerifiedZeroRawPii ? "safe" : "alert"})</td>
			<td>${row.decision.complexityScore}/100</td>
			<td>${row.latencyMs} ms</td>
		`;
		el.ledgerTbody.appendChild(tr);
	}
}

async function runDispatch(): Promise<void> {
	el.btnDispatch.disabled = true;
	try {
		const res = await engine.dispatchPrompt({
			...readCurrentPolicyInput(),
			cloudModelName: el.cfgCloudModel.value.trim() || "gemini-2.5-flash-lite",
		});
		renderLivePreview();
		renderMetricsAndLedger(res);
	} finally {
		el.btnDispatch.disabled = false;
	}
}

function applyPreset(presetId: string): void {
	const preset = PRESETS[presetId];
	if (!preset) return;
	for (const btn of el.presetButtons) {
		btn.classList.toggle("is-active", btn.dataset.preset === presetId);
	}
	el.toggleOnline.checked = preset.online;
	el.toggleNano.checked = preset.onDeviceAvailable;
	el.toggleStrict.checked = preset.strictPrivacyLock;
	el.toggleAllowRedacted.checked = preset.allowCloudAfterRedaction;
	el.promptInput.value = preset.prompt;
	renderLivePreview();
	void runDispatch();
}

for (const btn of el.presetButtons) {
	btn.addEventListener("click", () => {
		if (btn.dataset.preset) applyPreset(btn.dataset.preset);
	});
}

for (const input of [
	el.toggleOnline,
	el.toggleNano,
	el.toggleStrict,
	el.toggleAllowRedacted,
	el.sliderComplexity,
	el.promptInput,
]) {
	input.addEventListener("input", renderLivePreview);
}

el.btnDispatch.addEventListener("click", () => {
	void runDispatch();
});

el.btnWarmup.addEventListener("click", async () => {
	el.btnWarmup.disabled = true;
	try {
		const res = await engine.warmUpOnDeviceModel((p) => {
			el.warmupStatus.textContent = `Downloading / initializing on-device weights: ${Math.round(p * 100)}%`;
		});
		el.warmupStatus.textContent = `${res.status} (${res.channel})`;
	} catch (err) {
		el.warmupStatus.textContent = `Warm-up failed: ${err instanceof Error ? err.message : String(err)}`;
	} finally {
		el.btnWarmup.disabled = false;
	}
});

el.btnReset.addEventListener("click", () => {
	engine.resetStats();
	el.copilotResponse.textContent = "";
	el.responseMetaBadge.className = "pill pill-muted";
	el.responseMetaBadge.textContent = "Cleared";
	renderMetricsAndLedger();
});

el.btnConnectFirebase.addEventListener("click", () => {
	const connected = engine.configureFirebase(
		{
			apiKey: el.cfgApiKey.value.trim(),
			projectId: el.cfgProjectId.value.trim(),
			appId: el.cfgAppId.value.trim(),
		},
		el.cfgCloudModel.value.trim(),
	);
	el.runtimeBadge.className = connected
		? "pill pill-local"
		: "pill pill-blocked";
	el.runtimeBadge.textContent = connected
		? "Live Firebase AI SDK Bound"
		: "Missing API Key / Project / App ID";
});

el.btnDisconnectFirebase.addEventListener("click", () => {
	engine.configureFirebase(null);
	el.runtimeBadge.className = "pill pill-info";
	el.runtimeBadge.textContent = "SDK Ready · Sandbox Mode";
});

void probeBrowserBuiltInAi().then((probe) => {
	el.probeBadge.textContent = `Nano Probe: ${probe.availabilityStatus} (${probe.apiSurface})`;
	el.probeBadge.className =
		probe.availabilityStatus === "available"
			? "pill pill-local"
			: "pill pill-muted";
});

// Initialize with Clinical PII preset and run initial dispatch so dashboard renders rich live evidence
applyPreset("clinical-pii");
