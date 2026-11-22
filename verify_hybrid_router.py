"""
Standalone mathematical & security property verifier for EdgeMesh Hybrid Copilot.
Executed via `lambai_overlord.py --exec-file` inside an isolated sandbox.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import List


def passes_luhn(digits: str) -> bool:
    if not re.fullmatch(r"\d{13,19}", digits):
        return False
    total = 0
    dbl = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if dbl:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        dbl = not dbl
    return total % 10 == 0


API_KEY_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_-]{20,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{12,})\b"
)
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
MRN_RE = re.compile(r"\bMRN[\s:#-]*[A-Z0-9]{5,12}\b", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
CARD_CAND_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
PHONE_RE = re.compile(
    r"(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\b0\d{2,3}|\b\d{3})[\s.-]?\d{3}[\s.-]?\d{3,4}\b"
)


@dataclass
class Decision:
    mode: str
    contains_pii: bool
    findings: List[str]
    sanitized_prompt: str
    outbound_prompt: str
    blocked: bool
    complexity: int
    tokens: int


def scan_and_redact(text: str):
    findings: List[str] = []
    s = text

    def sub_record(pattern: re.Pattern, tag: str, src: str) -> str:
        def repl(_m):
            findings.append(tag)
            return f"[REDACTED_{tag}]"

        return pattern.sub(repl, src)

    s = sub_record(API_KEY_RE, "API_KEY", s)
    s = sub_record(SSN_RE, "SSN", s)
    s = sub_record(MRN_RE, "MRN", s)
    s = sub_record(EMAIL_RE, "EMAIL", s)

    def card_repl(m):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if passes_luhn(digits):
            findings.append("CARD")
            return "[REDACTED_CARD]"
        return raw

    s = CARD_CAND_RE.sub(card_repl, s)

    def phone_repl(m):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if 9 <= len(digits) <= 12:
            findings.append("PHONE")
            return "[REDACTED_PHONE]"
        return raw

    s = PHONE_RE.sub(phone_repl, s)
    return len(findings) > 0, findings, s


def estimate_tokens(text: str) -> int:
    trimmed = text.strip()
    if not trimmed:
        return 0
    words = len(trimmed.split())
    char_est = int(-(-len(trimmed) // 3.8))
    return max(words, char_est)


def score_complexity(text: str) -> int:
    low = text.lower()
    tokens = estimate_tokens(text)
    score = min(45, round(tokens / 25))
    sig1 = re.findall(
        r"\b(?:architect|root[- ]cause|multi[- ]step|synthesize|compare|differential|correlation|schema|json|sql|migration|refactor|proof)\b",
        low,
    )
    sig2 = re.findall(
        r"\b(?:trade-?off|benchmark|forecast|matrix|timeline|audit|compliance)\b",
        low,
    )
    if sig1:
        score += min(28, len(sig1) * 10)
    if sig2:
        score += min(28, len(sig2) * 10)
    if text.count("\n") >= 5:
        score += 14
    if "```" in text or re.search(r"\{[\s\S]{15,}\}", text):
        score += 15
    return max(5, min(100, score))


def evaluate_policy(
    prompt: str,
    online: bool,
    on_device: bool,
    strict_lock: bool,
    allow_cloud_after_redaction: bool,
    local_max_complexity: int = 62,
    local_max_tokens: int = 1800,
) -> Decision:
    has_pii, findings, sanitized = scan_and_redact(prompt)
    tokens = estimate_tokens(prompt)
    comp = score_complexity(prompt)

    if strict_lock or (has_pii and not allow_cloud_after_redaction):
        return Decision(
            mode="ONLY_ON_DEVICE",
            contains_pii=has_pii,
            findings=findings,
            sanitized_prompt=sanitized,
            outbound_prompt=prompt,
            blocked=not on_device,
            complexity=comp,
            tokens=tokens,
        )
    if not online:
        return Decision(
            mode="ONLY_ON_DEVICE",
            contains_pii=has_pii,
            findings=findings,
            sanitized_prompt=sanitized,
            outbound_prompt=prompt,
            blocked=not on_device,
            complexity=comp,
            tokens=tokens,
        )
    if comp <= local_max_complexity and tokens <= local_max_tokens:
        return Decision(
            mode="PREFER_ON_DEVICE",
            contains_pii=has_pii,
            findings=findings,
            sanitized_prompt=sanitized,
            outbound_prompt=sanitized,
            blocked=False,
            complexity=comp,
            tokens=tokens,
        )
    return Decision(
        mode="IN_CLOUD",
        contains_pii=has_pii,
        findings=findings,
        sanitized_prompt=sanitized,
        outbound_prompt=sanitized,
        blocked=False,
        complexity=comp,
        tokens=tokens,
    )


def make_luhn_pan(rng: random.Random, prefix: str = "453201") -> str:
    body = [int(c) for c in prefix] + [rng.randint(0, 9) for _ in range(9)]
    # compute Luhn check digit
    total = 0
    dbl = True
    for d in reversed(body):
        val = d * 2 if dbl else d
        if val > 9:
            val -= 9
        total += val
        dbl = not dbl
    check = (10 - (total % 10)) % 10
    return "".join(str(d) for d in body) + str(check)


def main() -> None:
    rng = random.Random(20261130)
    assert passes_luhn("4532015112830366")
    assert not passes_luhn("4532015112830367")

    checked = 0
    leaks = 0
    offline_violations = 0
    cloud_escalations = 0
    local_routes = 0

    for i in range(300):
        ssn = f"{rng.randint(100, 899)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"
        pan = make_luhn_pan(rng)
        email = f"eng{i}@acme-health.org"
        api_key = f"sk-live{rng.randint(100000000000, 999999999999)}xyz"
        mrn = f"MRN-{rng.randint(100000, 999999)}"
        phone = f"+84 912 {rng.randint(100, 999)} {rng.randint(100, 999)}"

        secrets = [ssn, pan, email, api_key, mrn, phone]
        high_comp = i % 3 == 0
        prompt = (
            (
                f"Analyze root-cause architecture trade-off matrix SQL migration:\n```\nSELECT {i};\n```\n"
                if high_comp
                else f"Quick ward checklist item #{i}: "
            )
            + f"owner {email}, key {api_key}, patient {mrn}, ssn {ssn}, card {pan}, tel {phone}"
        )

        online = bool(i % 4 != 0)
        on_device = bool(i % 5 != 0)
        strict = bool(i % 7 == 0)
        allow_redacted = bool(i % 2 == 0)

        d = evaluate_policy(prompt, online, on_device, strict, allow_redacted)
        checked += 1

        if not online and d.mode != "ONLY_ON_DEVICE":
            offline_violations += 1
        if not online and not on_device and not d.blocked:
            offline_violations += 1
        if d.mode in ("IN_CLOUD", "PREFER_ON_DEVICE") and not d.blocked:
            for sec in secrets:
                if sec in d.outbound_prompt:
                    leaks += 1
        if d.mode == "IN_CLOUD":
            cloud_escalations += 1
        else:
            local_routes += 1

    assert leaks == 0, f"Detected {leaks} raw PII leaks!"
    assert offline_violations == 0, f"Detected {offline_violations} offline violations!"
    print(
        f"HYBRID_AI_VERIFIED_OK | adversarial_cases={checked} | leaks={leaks} | "
        f"offline_violations={offline_violations} | local_or_blocked={local_routes} | cloud_scrubbed={cloud_escalations}"
    )


if __name__ == "__main__":
    main()
