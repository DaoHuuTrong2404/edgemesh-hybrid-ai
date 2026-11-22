/**
 * EdgeMesh Hybrid AI — Pure Deterministic Privacy & Complexity Routing Policy.
 * Evaluates PII risk, token budget, offline constraints, and complexity before
 * dispatching to Firebase AI Logic (`PREFER_ON_DEVICE`, `ONLY_ON_DEVICE`, or `IN_CLOUD`).
 */

export type PolicyInferenceMode =
	| "ONLY_ON_DEVICE"
	| "PREFER_ON_DEVICE"
	| "IN_CLOUD";

export interface PiiFinding {
	kind: "EMAIL" | "SSN" | "API_KEY" | "CARD" | "MRN" | "PHONE";
	maskedToken: string;
}

export interface RoutingPolicyInput {
	prompt: string;
	online: boolean;
	onDeviceAvailable: boolean;
	strictPrivacyLock: boolean;
	allowCloudAfterRedaction: boolean;
	localMaxComplexity?: number;
	localMaxTokens?: number;
}

export interface RoutingDecision {
	mode: PolicyInferenceMode;
	targetModel: string;
	containsPii: boolean;
	findings: PiiFinding[];
	sanitizedPrompt: string;
	outboundPrompt: string;
	estimatedTokens: number;
	complexityScore: number;
	estimatedCloudUsd: number;
	reason: string;
	blocked: boolean;
}

export function passesLuhn(digits: string): boolean {
	if (!/^\d{13,19}$/.test(digits)) return false;
	let sum = 0;
	let dbl = false;
	for (let i = digits.length - 1; i >= 0; i--) {
		let d = digits.charCodeAt(i) - 48;
		if (dbl) {
			d *= 2;
			if (d > 9) d -= 9;
		}
		sum += d;
		dbl = !dbl;
	}
	return sum % 10 === 0;
}

export function scanAndRedactPii(text: string): {
	containsPii: boolean;
	findings: PiiFinding[];
	sanitizedPrompt: string;
} {
	const findings: PiiFinding[] = [];
	let sanitized = text;

	// 1. API keys / tokens (sk-, AIza, ghp_, xoxb-)
	sanitized = sanitized.replace(
		/\b(?:sk-[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_-]{20,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{12,})\b/g,
		() => {
			findings.push({ kind: "API_KEY", maskedToken: "[REDACTED_API_KEY]" });
			return "[REDACTED_API_KEY]";
		},
	);

	// 2. SSN (XXX-XX-XXXX)
	sanitized = sanitized.replace(/\b\d{3}-\d{2}-\d{4}\b/g, () => {
		findings.push({ kind: "SSN", maskedToken: "[REDACTED_SSN]" });
		return "[REDACTED_SSN]";
	});

	// 3. Medical Record Number (MRN-123456 or MRN: 123456)
	sanitized = sanitized.replace(/\bMRN[\s:#-]*[A-Z0-9]{5,12}\b/gi, () => {
		findings.push({ kind: "MRN", maskedToken: "[REDACTED_MRN]" });
		return "[REDACTED_MRN]";
	});

	// 4. Email addresses
	sanitized = sanitized.replace(
		/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
		() => {
			findings.push({ kind: "EMAIL", maskedToken: "[REDACTED_EMAIL]" });
			return "[REDACTED_EMAIL]";
		},
	);

	// 5. Credit card candidates verified by Luhn checksum
	sanitized = sanitized.replace(/\b(?:\d[ -]*?){13,19}\b/g, (raw) => {
		const digits = raw.replace(/\D/g, "");
		if (passesLuhn(digits)) {
			findings.push({ kind: "CARD", maskedToken: "[REDACTED_CARD]" });
			return "[REDACTED_CARD]";
		}
		return raw;
	});

	// 6. Phone numbers (+84 / US formats)
	sanitized = sanitized.replace(
		/(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\b0\d{2,3}|\b\d{3})[\s.-]?\d{3}[\s.-]?\d{3,4}\b/g,
		(raw) => {
			const digits = raw.replace(/\D/g, "");
			if (digits.length >= 9 && digits.length <= 12) {
				findings.push({ kind: "PHONE", maskedToken: "[REDACTED_PHONE]" });
				return "[REDACTED_PHONE]";
			}
			return raw;
		},
	);

	return {
		containsPii: findings.length > 0,
		findings,
		sanitizedPrompt: sanitized,
	};
}

export function estimateTokens(text: string): number {
	const trimmed = text.trim();
	if (!trimmed) return 0;
	const words = trimmed.split(/\s+/).length;
	const charEst = Math.ceil(trimmed.length / 3.8);
	return Math.max(words, charEst);
}

export function scoreComplexity(text: string): number {
	const low = text.toLowerCase();
	const tokens = estimateTokens(text);
	let score = Math.min(45, Math.round(tokens / 25));

	const highSignals = [
		/\b(architect|root[- ]cause|multi[- ]step|synthesize|compare|differential|correlation|schema|json|sql|migration|refactor|proof)\b/g,
		/\b(trade-?off|benchmark|forecast|matrix|timeline|audit|compliance)\b/g,
	];
	for (const re of highSignals) {
		const matches = low.match(re);
		if (matches) score += Math.min(28, matches.length * 10);
	}

	const lineBreaks = (text.match(/\n/g) || []).length;
	if (lineBreaks >= 5) score += 14;
	if (text.includes("```") || /\{[\s\S]{15,}\}/.test(text)) score += 15;

	return Math.max(5, Math.min(100, score));
}

export function evaluateRoutingPolicy(
	input: RoutingPolicyInput,
): RoutingDecision {
	const localMaxComplexity = input.localMaxComplexity ?? 62;
	const localMaxTokens = input.localMaxTokens ?? 1800;

	const { containsPii, findings, sanitizedPrompt } = scanAndRedactPii(
		input.prompt,
	);
	const estimatedTokens = estimateTokens(input.prompt);
	const complexityScore = scoreComplexity(input.prompt);
	const estimatedCloudUsd = Number(
		((estimatedTokens * 0.1 + 300 * 0.4) / 1_000_000).toFixed(6),
	);

	// Rule 1: Strict privacy lock or unredacted PII forces on-device execution (fail-closed if offline/unavailable)
	if (
		input.strictPrivacyLock ||
		(containsPii && !input.allowCloudAfterRedaction)
	) {
		const blocked =
			!input.onDeviceAvailable && !input.online
				? true
				: !input.onDeviceAvailable;
		return {
			mode: "ONLY_ON_DEVICE",
			targetModel: "gemini-nano-4 (on-device)",
			containsPii,
			findings,
			sanitizedPrompt,
			outboundPrompt: input.prompt,
			estimatedTokens,
			complexityScore,
			estimatedCloudUsd,
			reason: containsPii
				? `PII Guard triggered (${findings.map((f) => f.kind).join(", ")}) — locked strictly to on-device Gemini Nano.`
				: "Privacy Lock enabled — executing strictly on local device.",
			blocked,
		};
	}

	// Rule 2: Offline execution forces on-device model
	if (!input.online) {
		return {
			mode: "ONLY_ON_DEVICE",
			targetModel: "gemini-nano-4 (on-device)",
			containsPii,
			findings,
			sanitizedPrompt,
			outboundPrompt: input.prompt,
			estimatedTokens,
			complexityScore,
			estimatedCloudUsd,
			reason:
				"Device offline — forced ONLY_ON_DEVICE execution with zero network dependency.",
			blocked: !input.onDeviceAvailable,
		};
	}

	// Rule 3: Low/Medium complexity & fits context window -> PREFER_ON_DEVICE ($0 marginal cost)
	if (
		complexityScore <= localMaxComplexity &&
		estimatedTokens <= localMaxTokens
	) {
		return {
			mode: "PREFER_ON_DEVICE",
			targetModel: input.onDeviceAvailable
				? "gemini-nano-4 (on-device)"
				: "gemini-2.5-flash-lite (cloud fallback)",
			containsPii,
			findings,
			sanitizedPrompt,
			outboundPrompt: sanitizedPrompt,
			estimatedTokens,
			complexityScore,
			estimatedCloudUsd,
			reason: input.onDeviceAvailable
				? `Complexity ${complexityScore}/100 <= ${localMaxComplexity} — running locally via PREFER_ON_DEVICE ($0.00 cost).`
				: "On-device model unavailable — PREFER_ON_DEVICE seamlessly escalated redacted prompt to cloud.",
			blocked: false,
		};
	}

	// Rule 4: High complexity or large context -> IN_CLOUD with mandatory PII scrubbing
	return {
		mode: "IN_CLOUD",
		targetModel: "gemini-2.5-flash-lite (Firebase AI Logic)",
		containsPii,
		findings,
		sanitizedPrompt,
		outboundPrompt: sanitizedPrompt,
		estimatedTokens,
		complexityScore,
		estimatedCloudUsd,
		reason: containsPii
			? `High complexity (${complexityScore}/100) — PII scrubbed (${findings.length} entities) before IN_CLOUD Firebase AI dispatch.`
			: `High complexity (${complexityScore}/100) or long context (${estimatedTokens} tok) — routed IN_CLOUD to gemini-2.5-flash-lite.`,
		blocked: false,
	};
}
