# Threat Model, Security Boundary & Policy Guide

**Owner:** Developer 4 (Security Policy, Independent Verification & Audit)
**Scope:** The PII Security Firewall gateway, from file upload to LLM release
**Related:** `docs/architecture.md`, `docs/developer_4_policy_verifier_architecture.md`, `config/policy.yaml`

---

## 1. What we protect

| Asset | Why it matters |
|---|---|
| PII inside uploaded documents (SSN, passport, PAN, Aadhaar, cards, names, contacts, addresses) | The whole point of the gateway: none of it may reach a downstream LLM |
| The audit trail (`data/outputs/audit.log`) | Compliance evidence; must itself contain zero PII and be tamper-evident |
| The security policy (`config/policy.yaml`) | Weakening it silently would turn the gateway fail-open |
| The downstream LLM context | Must receive only sanitized, verified, inert data |

## 2. Trust boundaries

```
 Untrusted                     Gateway (trusted code, untrusted data)                     Approved LLM
───────────┐  ┌───────────────────────────────────────────────────────────────────┐  ┌──────────────
 Uploaded  │  │ B1 Pre-flight      B2 Extraction/OCR    B3 Detection → Policy     │  │
 file      ├─►│ (limits, MIME,  ─► (CanonicalDocument) ─► → Redaction             │  │
           │  │  zip/XXE guards)                          │                       │  │
           │  │                                           ▼                       │  │
           │  │                     B4 INDEPENDENT VERIFIER + RE-OCR (Dev 4)      │  │
           │  │                                           ▼                       │  │
           │  │                     B5 FAIL-CLOSED GATE (Dev 4) ── BLOCK ──► audit│  │
           │  │                                           │ PASS                  │  │
           │  │                     B6 Inert envelope <document_payload>  ────────┼─►│ LLM
           │  │                                                                   │  │   │
           │  │                     B7 LLM OUTPUT SCANNER (Dev 4)  ◄──────────────┼──┤◄──┘
───────────┘  └───────────────────────────────────────────────────────────────────┘  └──────────────
```

* **B4 is the security boundary.** Everything before it is "best effort"; B4 decides whether
  that effort was good enough, using a *different* detection stack.
* **B5 is fail-closed.** It returns PASS only when every check passed; a missing input,
  a crash, or an uncertain answer is BLOCK.

## 3. Threat actors

| Actor | Goal | Typical technique |
|---|---|---|
| Careless insider | Upload a document that happens to contain PII | Scanned forms, screenshots, speaker notes, hidden slides |
| Malicious insider | Exfiltrate PII through the "approved" AI channel | Evasion encodings designed to beat the detector |
| External attacker (document author) | Hijack the downstream LLM or the gateway | Prompt injection, zip bombs, XXE, malformed files |
| Curious operator | Read PII from logs or dashboards | Browsing audit logs / UI telemetry |

## 4. Threats and mitigations

| # | Threat | Mitigation | Where |
|---|---|---|---|
| T1 | PII missed by the primary detector (blind spot) | Independent verifier with a different stack: normalization, loose patterns, cue words, digit entropy, spacing detector. Verifier does not import `src.detection` (enforced by a unit test) | `src/verification/verifier.py` |
| T2 | Character spacing (`S S N : 1 2 3 …`, `R a h u l`) | De-spacing "compact view" + spacing detector | verifier |
| T3 | Zero-width / BiDi / soft-hyphen insertion | Unicode format (`Cf`) and combining (`Mn`) chars stripped before scanning; offsets mapped back to the original | verifier |
| T4 | Homoglyphs (Cyrillic `Ѕ`, Greek `Ο`), full-width digits, en-dashes | NFKC + homoglyph fold + dash unification | verifier |
| T5 | Obfuscated contact data (`john [at] corp [dot] com`) | Dedicated obfuscated-email pattern | verifier |
| T6 | Smuggling digits behind an allow-listed prefix (`INC-2026-219457890`) | Allow-list patterns cap digit runs at 6, so the remainder is scanned and caught by the entropy rule | `config/policy.yaml`, verifier |
| T7 | Low-confidence detection of critical PII ("probably an SSN") | CRITICAL `uncertainty_action: BLOCK`; HIGH/MEDIUM redact when in doubt | `src/policy/policy.py` |
| T8 | Burned box did not actually obliterate pixels | Re-OCR the sanitized image; any text read inside a burned box is a leak | `src/verification/residual_scan.py` |
| T9 | Poor scan quality hides PII from OCR | Page OCR confidence ≤ 0.60 blocks; low re-OCR confidence makes the verifier uncertain | gate, residual scan |
| T10 | Redaction silently skipped (bad offsets, unknown block) | Redactor reports every unapplied entity; gate blocks with `REDACTION_INCOMPLETE` | `src/sanitization/text_redactor.py`, gate |
| T11 | Any component crashes or is skipped | Missing verifier/policy result, internal exceptions, and audit-write failures all produce BLOCK | gate, checkpoint |
| T12 | Prompt injection inside a document | Dev 1's `InputSafetyGuard` scan; gate blocks on injection (configurable); released text always wrapped in an inert `<document_payload role="data_only">` envelope | gate, `src/security/input_safety.py` |
| T13 | LLM echoes or hallucinates PII | Output scanner re-runs the verifier on every response and redacts findings | `src/verification/output_scanner.py` |
| T14 | PII written to audit logs | Whitelisted record fields only; free-text fields re-scanned and scrubbed; basename-only (or hashed) filenames; `audit_compliance_check()` | `src/audit/logger.py` |
| T15 | Audit log tampering | Hash chain (`prev_hash` / `record_hash`), verified by `verify_chain()` | audit logger |
| T16 | Policy weakened (fail-open, ALLOW for SSN) | Loader rejects `fail_closed: false`, ALLOW on CRITICAL/HIGH tiers, duplicate tiers, bad thresholds; policy can only escalate risk vs. the schema | `src/policy/policy.py` |
| T17 | Hostile files (zip bombs, XXE, spoofed MIME) | Pre-flight guards (Dev 1); rejections can be recorded with `AuditLogger.log_security_event()` | `src/security/limits.py`, `src/ingestion/validators.py` |

## 5. Known limitations (residual risk we accept, and how we bound it)

* **Bare names without a cue** ("met Alice yesterday") are only caught by Dev 3's NER; the
  verifier catches names next to cues (`Name:`), honorifics (`Dr.`), or letter-spaced names.
  Mitigation: NER must be enabled in production; the ablation study measures its recall.
* **Over-blocking is preferred to leaking.** Long high-entropy digit runs (timestamps, some
  reference numbers) block the document. Add a capped allow-list pattern if a legitimate
  format keeps tripping it.
* **Partial disclosure** (e.g. last 4 digits of an SSN) is not treated as a leak.
* **Re-OCR uses the same OCR engine family** as extraction; independence is in the detection
  logic, not the OCR model. Pixel burning (Dev 2) is the primary control for images.
* **Hash salt.** Set `PII_FIREWALL_AUDIT_SALT` (and Dev 3's `set_hash_salt`) per deployment;
  the development default is public.

## 6. Policy guide (`config/policy.yaml`)

| Section | What it controls | Safe to change? |
|---|---|---|
| `rules.<TIER>.entities` | Which entity types belong to a risk tier | Yes. Moving a type *up* is always safe; the schema floor (`RISK_MAPPING`) still applies |
| `rules.<TIER>.min_confidence_to_redact` | Confidence bar for a "confident" detection | Yes (0–1) |
| `rules.<TIER>.uncertainty_action` | What happens below the bar (`REDACT` / `BLOCK`) | Yes; keep CRITICAL at `BLOCK` |
| `rules.MEDIUM/LOW.action` | May be `ALLOW` | Only with a documented business reason |
| `allow_lists.business_codes` | Regexes for non-PII business references | Yes; keep `\b` anchors and **cap digit runs** |
| `redaction.mode` | `token` (`[REDACTED_SSN]`) or `block` (`█████`) | Yes |
| `verification.*` | Verifier heuristics (entropy threshold, spacing run, cue window) | Tune on the dev set only, never on held-out data |
| `gate.max_allowed_residual_risk` | Highest residual risk that may still PASS | Keep `NONE` |
| `gate.min_page_ocr_confidence` | OCR confidence floor per page | Yes |
| `gate.block_on_prompt_injection` | Block vs. pass-through-as-inert-data | Yes |
| `gate.require_integrity_check` | Require a `DocumentIntegrityGuard` result | Set `true` once sanitized files are produced end-to-end |
| `gate.fail_closed` | Must be `true` | **No.** The loader refuses to start otherwise |
| `audit.*` | Log path, salt env var, filename hashing, hash chain | Yes |

A config error never falls back silently: `PolicyConfigError` is raised and the
caller must treat it as BLOCK.

## 7. Gate block codes

| Code | Meaning |
|---|---|
| `VERIFICATION_MISSING` | Independent verifier did not run |
| `VERIFIER_UNCERTAIN` | Verifier or re-OCR could not vouch for the content |
| `RESIDUAL_LEAK_DETECTED` | Verifier or re-OCR found PII after sanitization |
| `POLICY_NOT_APPLIED` / `POLICY_BLOCK` | Policy missing, or it returned BLOCK (e.g. uncertain critical PII) |
| `CRITICAL_PII_PRESENT` / `UNREDACTED_PII_PRESENT` | An entity left without REDACT/ALLOW |
| `REDACTION_INCOMPLETE` | Redactor could not apply one or more entities |
| `LOW_CONFIDENCE_UNCERTAINTY` | A page's OCR confidence ≤ threshold |
| `PROMPT_INJECTION_DETECTED` / `UNICODE_ANOMALY_DETECTED` | Input safety findings |
| `INTEGRITY_CHECK_FAILED` / `INTEGRITY_CHECK_MISSING` | Reconstructed file corrupt / not checked |
| `PIPELINE_ERROR`, `GATE_INTERNAL_ERROR`, `AUDIT_LOG_FAILURE` | Something broke: unknown is unsafe |
| `DOCUMENT_SANITIZED_AND_VERIFIED` | PASS: released to the approved LLM |
