import assert from "node:assert/strict";
import test from "node:test";
import { InferenceMode, InferenceSource } from "firebase/ai";
import {
	EdgeMeshHybridEngine,
	mapPolicyModeToFirebase,
} from "../src/hybridRouter.ts";
import {
	evaluateRoutingPolicy,
	passesLuhn,
	scanAndRedactPii,
} from "../src/routingPolicy.ts";

test("Luhn validator accepts valid cards and rejects non-Luhn order IDs", () => {
	assert.equal(passesLuhn("4532015112830366"), true);
	assert.equal(passesLuhn("378282246310005"), true);
	assert.equal(passesLuhn("4532015112830367"), false);
	assert.equal(passesLuhn("1234567890123"), false);
});

test("scanAndRedactPii removes SSN, MRN, API keys, emails, cards, and phones", () => {
	const raw =
		"MRN-849201 SSN 123-45-6789 key sk-prod9876543210abcd mail alice@example.org card 4532-0151-1283-0366 phone +84 912 345 678";
	const res = scanAndRedactPii(raw);
	assert.equal(res.containsPii, true);
	assert.equal(res.findings.length >= 6, true);
	assert.equal(res.sanitizedPrompt.includes("123-45-6789"), false);
	assert.equal(res.sanitizedPrompt.includes("sk-prod9876543210abcd"), false);
	assert.equal(res.sanitizedPrompt.includes("alice@example.org"), false);
	assert.equal(res.sanitizedPrompt.includes("4532-0151-1283-0366"), false);
});

test("Policy maps strictly to official @firebase/ai InferenceMode values", () => {
	assert.equal(
		mapPolicyModeToFirebase("ONLY_ON_DEVICE"),
		InferenceMode.ONLY_ON_DEVICE,
	);
	assert.equal(
		mapPolicyModeToFirebase("PREFER_ON_DEVICE"),
		InferenceMode.PREFER_ON_DEVICE,
	);
	assert.equal(
		mapPolicyModeToFirebase("IN_CLOUD"),
		InferenceMode.ONLY_IN_CLOUD,
	);
});

test("Offline + unavailable on-device model enforces fail-closed block", async () => {
	const engine = new EdgeMeshHybridEngine();
	const res = await engine.dispatchPrompt({
		prompt: "Offline note with AIzaSyDemoKey0123456789abcdef012345",
		online: false,
		onDeviceAvailable: false,
		strictPrivacyLock: false,
		allowCloudAfterRedaction: true,
	});
	assert.equal(res.decision.mode, "ONLY_ON_DEVICE");
	assert.equal(res.decision.blocked, true);
	assert.equal(res.actualSource, "blocked");
	assert.equal(res.runtimeChannel, "FAIL_CLOSED_BLOCKED");
	assert.equal(res.egressVerifiedZeroRawPii, true);
});

test("High-complexity prompt with allowCloudAfterRedaction scrubs PII before IN_CLOUD", async () => {
	const engine = new EdgeMeshHybridEngine();
	const res = await engine.dispatchPrompt({
		prompt:
			"Analyze root-cause deadlock for lead@corp.io with key sk-test1234567890abcdef.\nCompare trade-off benchmark matrix:\n```\nSELECT * FROM jobs;\n```",
		online: true,
		onDeviceAvailable: true,
		strictPrivacyLock: false,
		allowCloudAfterRedaction: true,
	});
	assert.equal(res.decision.mode, "IN_CLOUD");
	assert.equal(res.sdkInferenceMode, InferenceMode.ONLY_IN_CLOUD);
	assert.equal(res.actualSource, InferenceSource.IN_CLOUD);
	assert.equal(res.decision.outboundPrompt.includes("lead@corp.io"), false);
	assert.equal(
		res.decision.outboundPrompt.includes("sk-test1234567890abcdef"),
		false,
	);
	assert.equal(res.egressVerifiedZeroRawPii, true);
});

test("Low-complexity prompt routes PREFER_ON_DEVICE with zero cloud spend", async () => {
	const decision = evaluateRoutingPolicy({
		prompt: "Summarize Ward B shift checklist cleanly.",
		online: true,
		onDeviceAvailable: true,
		strictPrivacyLock: false,
		allowCloudAfterRedaction: true,
	});
	assert.equal(decision.mode, "PREFER_ON_DEVICE");
	assert.equal(decision.blocked, false);
});
