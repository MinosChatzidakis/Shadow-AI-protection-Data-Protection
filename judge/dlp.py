import os
import json
import re
from typing import Tuple, List, Dict, Any

RULES_FILE = os.getenv("RULES_FILE", os.path.join(os.path.dirname(__file__), "..", "rules.json"))


def load_custom_rules() -> List[Dict[str, Any]]:
    candidates = [
        RULES_FILE,
        os.path.join(os.path.dirname(__file__), "rules.json"),
        os.path.join(os.getcwd(), "rules.json"),
    ]
    for p in candidates:
        try:
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"[DLP WARN] Error reading custom rules from {p}: {e}")
    return []


def save_custom_rules(rules: List[Dict[str, Any]]) -> bool:
    candidates = [
        RULES_FILE,
        os.path.join(os.path.dirname(__file__), "rules.json"),
        os.path.join(os.getcwd(), "rules.json"),
    ]
    for p in candidates:
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(rules, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            continue
    return False


def normalize_pattern(pat: str) -> str:
    """Expands human shortcuts and normalizes pattern for robust matching."""
    if not pat:
        return ""
    s = pat.strip()
    if re.match(r"^0\s*-\s*(?:9|\u221e|infinity|inf|\+|\*)$", s, re.IGNORECASE) or re.match(r"^(?:numbers?\vert{}digits?)$", s, re.IGNORECASE):
        return r"\b\d+\b"
    if re.match(r"^a\s*-\s*z$", s, re.IGNORECASE) or re.match(r"^(?:letters?\vert{}words?)$", s, re.IGNORECASE):
        return r"\b[a-zA-Z]+\b"
    if re.match(r"^(?:a\s*-\s*z\s*0\s*-\s*9|0\s*-\s*9\s*a\s*-\s*z|alphanumeric)$", s, re.IGNORECASE):
        return r"\b[a-zA-Z0-9]+\b"
    if re.match(r"^iban$", s, re.IGNORECASE):
        return r"(?i)\b(?:IBAN[:\s]*)?[A-Z]{2}\d{2}(?:[-\s]?[0-9A-Z]){11,30}\b"
    if "GR" in s and "{23}" in s:
        return r"(?i)\b(?:IBAN[:\s]*)?GR\d{2}(?:[-\s]?[0-9A-Z]){23}\b"
    raw_clean = re.sub(r"[\s-]+", "", s)
    if re.match(r"^[A-Z]{2}\d{2}[0-9A-Z]{11,30}$", raw_clean, re.IGNORECASE):
        spaced = "".join(c if i == 0 else f"[-\\s]*{c}" for i, c in enumerate(raw_clean))
        return f"(?i)\\b(?:IBAN[:\\s]*)?{spaced}\\b"
    if not s.startswith("(?"):
        return f"(?i){s}"
    return s


# High-severity patterns -> Immediate BLOCK (Hard Secrets & Malicious Prompt Injections)
BLOCK_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "API Secret Key": r"sk-[a-zA-Z0-9]{20,}",
    "Private Key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Database URL": r"(?:postgres|mysql|mongodb)://[^\s]+:[^\s]+@[^\s]+",

    "Prompt Injection (Instruction Override)": r"(?i)(?:ignore|disregard|forget|bypass)\s+(?:all\s+|previous\s+|prior\s+|system\s+)*(?:instructions|rules|guidelines|prompts)",
    "Prompt Injection (System Prompt Leak)": r"(?i)(?:reveal|show|display|output|print|repeat)\s+(?:your\s+|the\s+)*(?:system\s+prompt|developer\s+instructions|initial\s+prompt|core\s+directives)",
    "Prompt Injection (Jailbreak Persona)": r"(?i)\b(?:DAN\s+mode|jailbreak|do\s+anything\s+now|unrestricted\s+ai|developer\s+mode\s+enabled|bypass\s+safety)\b",
    "Prompt Injection (Roleplay Exploit)": r"(?i)(?:pretend\s+you\s+have\s+no\s+(?:rules|filters|morals)|act\s+as\s+(?:an?\s+)?unfiltered)",
}

# Medium-severity PII -> REDACT and forward (Greek & International Standards)
REDACT_PATTERNS = {
    "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "AMKA": r"(?i)(?:\b(?:ΑΜΚΑ|Α\.Μ\.Κ\.Α\.|AMKA|Social\s*Security)[^\w\n]{1,6})?\b\d{6}[-\s]?\d{5}\b",
    "AFM": r"(?i)(?:\b(?:ΑΦΜ|Α\.Φ\.Μ\.|AFM|VAT|Tax\s*ID)[^\w\n]{1,6})?\b\d{9}\b",
    "IBAN": r"(?i)\b(?:IBAN[:\s]*)?[A-Z]{2}\d{2}(?:[-\s]?[0-9A-Z]){11,30}\b",
    "CREDIT_CARD": r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|6[0-9]{3}|3[47][0-9]{2})[-\s]?(?:[0-9]{4}[-\s]?){2}[0-9]{3,4}\b",
    "PHONE": r"\b(?:\+?30[-.\s]?)?[26]\d{9}\b|\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
}


def inspect_prompt(text: str) -> Tuple[str, str, List[str]]:
    """
    Returns (action, processed_text, findings)
    action: "ALLOW" | "REDACT" | "BLOCK"
    """
    findings = []
    custom_rules = load_custom_rules()

    # 1. Check built-in hard-block secrets and prompt injection attacks first
    for label, pattern in BLOCK_PATTERNS.items():
        if re.search(pattern, text):
            findings.append(label)

    # 2. Check Manager Custom BLOCK Rules (with smart normalization)
    for r in custom_rules:
        if r.get("enabled", True) and r.get("action") == "BLOCK":
            raw_pat = r.get("pattern", "")
            norm_pat = normalize_pattern(raw_pat)
            matched = False
            try:
                if norm_pat and re.search(norm_pat, text):
                    matched = True
            except Exception:
                pass
            if not matched and raw_pat and raw_pat.lower() in text.lower():
                matched = True
            if matched:
                findings.append(f"Policy: {r.get('name')}")

    if findings:
        return "BLOCK", text, findings

    # 3. Redact sensitive PII findings (IBAN, AMKA, AFM, Email, Phone, Credit Cards)
    cleaned_text = text

    iban_rule = next((r for r in custom_rules if r.get("id") in ["rule-iban", "rule-any-iban"] or "iban" in r.get("name", "").lower()), None)
    is_iban_enabled = iban_rule.get("enabled", True) if iban_rule else True

    if is_iban_enabled and re.search(REDACT_PATTERNS["IBAN"], cleaned_text):
        findings.append("IBAN")
        cleaned_text = re.sub(REDACT_PATTERNS["IBAN"], "[REDACTED_IBAN]", cleaned_text)

    if re.search(REDACT_PATTERNS["CREDIT_CARD"], cleaned_text):
        findings.append("CREDIT_CARD")
        cleaned_text = re.sub(REDACT_PATTERNS["CREDIT_CARD"], "[REDACTED_CREDIT_CARD]", cleaned_text)

    if re.search(REDACT_PATTERNS["AMKA"], cleaned_text):
        findings.append("AMKA")
        cleaned_text = re.sub(
            r"(?i)((?:ΑΜΚΑ|Α\.Μ\.Κ\.Α\.|AMKA|Social\s*Security)[^\w\n]{1,6})?\b\d{6}[-\s]?\d{5}\b",
            lambda m: (m.group(1) or "") + "[REDACTED_AMKA]",
            cleaned_text,
        )

    if re.search(REDACT_PATTERNS["PHONE"], cleaned_text):
        findings.append("PHONE")
        cleaned_text = re.sub(REDACT_PATTERNS["PHONE"], "[REDACTED_PHONE]", cleaned_text)

    if re.search(REDACT_PATTERNS["AFM"], cleaned_text):
        findings.append("AFM")
        cleaned_text = re.sub(
            r"(?i)((?:ΑΦΜ|Α\.Φ\.Μ\.|AFM|VAT|Tax\s*ID)[^\w\n]{1,6})?\b\d{9}\b",
            lambda m: (m.group(1) or "") + "[REDACTED_AFM]",
            cleaned_text,
        )

    if re.search(REDACT_PATTERNS["EMAIL"], cleaned_text):
        findings.append("EMAIL")
        cleaned_text = re.sub(REDACT_PATTERNS["EMAIL"], "[REDACTED_EMAIL]", cleaned_text)

    # 4. Apply Manager Custom REDACT Rules (with smart normalization)
    for r in custom_rules:
        if r.get("enabled", True) and r.get("action") == "REDACT":
            raw_pat = r.get("pattern", "")
            norm_pat = normalize_pattern(raw_pat)
            clean_tag = re.sub(r"[^A-Z0-9_]", "_", r.get("name", "CUSTOM").upper()).strip("_")
            matched = False
            try:
                if norm_pat and re.search(norm_pat, cleaned_text):
                    matched = True
                    cleaned_text = re.sub(norm_pat, f"[REDACTED_{clean_tag}]", cleaned_text)
            except Exception:
                pass
            if not matched and raw_pat and raw_pat.lower() in cleaned_text.lower():
                matched = True
                cleaned_text = re.sub(re.escape(raw_pat), f"[REDACTED_{clean_tag}]", cleaned_text, flags=re.IGNORECASE)
            if matched:
                findings.append(f"Policy: {r.get('name')}")

    if findings:
        return "REDACT", cleaned_text, list(set(findings))

    # 5. Safe to forward as-is
    return "ALLOW", text, []