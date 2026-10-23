import hmac
import re

from fastapi import HTTPException

from core.config import REQUEST_INVESTIGATION_TOKEN

EMAIL_DOMAIN = "@dcbindia.com"
AUTHORIZATION_VALUE = re.compile(r"(?i)(\bauthorization\s*[:=]\s*)(?:bearer|basic)\s+\S+")
SENSITIVE_FIELD = re.compile(
	r'''(?i)(?P<prefix>["']?(?:password|passwd|pwd|access[_-]?token|refresh[_-]?token|'''
	r'''id[_-]?token|client[_-]?secret|api[_-]?key|authorization|secret|mobileNo|primaryMobileNumber|phone|email|panNumber|aadhaarVaultNumber|externalAadhaarRefNo|applicantExternalAadhaarRefNo|beneficiaryBankAccountNo|bankAccountNumber|accountNumber|beneficiaryIfscCode)["']?\s*[:=]\s*)'''
	r'''(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&}]+)'''
)

ANALYSIS_SENSITIVE_FIELD = re.compile(
	r'''(?i)(?P<prefix>["']?(?:cookie|set-cookie|token|session[_-]?(?:id|token)|csrf[_-]?token|'''
	r'''customerName|customerId|applicantName|applicantId|userId|firstName|lastName|fullName|'''
	r'''address(?:line\d*)?|dateOfBirth|dob|pan(?:number)?|aadhaar(?:number)?|nationalId|'''
	r'''mobile|phone|email|userName|accountNumber|cardNumber)["']?\s*[:=]\s*)'''
	r'''(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&}]+)'''
)
ANALYSIS_BEARER = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
ANALYSIS_AUTHORIZATION = re.compile(r'''(?i)(\bauthorization\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^,}\r\n]+)''')
ANALYSIS_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
ANALYSIS_PAN = re.compile(r"(?i)\b[A-Z]{5}\d{4}[A-Z]\b")
ANALYSIS_AADHAAR = re.compile(r"(?<!\d)(?:\d{4}[ -]?){2}\d{4}(?!\d)")
ANALYSIS_MOBILE = re.compile(r"(?<!\d)(?:\+?91[ -]?)?[6-9](?:[ -]?\d){9}(?!\d)")
ANALYSIS_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{240,}={0,2}(?![A-Za-z0-9+/])")


def redact_sensitive_text(value: str) -> str:
	value = AUTHORIZATION_VALUE.sub(r"\1[REDACTED]", value)

	def redact_field(match: re.Match) -> str:
		original = match.group("value")
		if original.startswith('"') and original.endswith('"'):
			replacement = '"[REDACTED]"'
		elif original.startswith("'") and original.endswith("'"):
			replacement = "'[REDACTED]'"
		else:
			replacement = "[REDACTED]"
		return match.group("prefix") + replacement

	return SENSITIVE_FIELD.sub(redact_field, value)


def redact_analysis_text(value: str) -> str:
	value = redact_sensitive_text(value)
	value = re.sub(r"(?im)^(\s*(?:set-cookie|cookie)\s*:\s*)[^\r\n]*", r"\1[REDACTED]", value)
	value = re.sub(r'''(?i)(["'](?:set-cookie|cookie)["']\s*:\s*)"[^"\r\n]*"''', r'\1"[REDACTED]"', value)
	value = re.sub(r"(?i)(\bcookie\s*=\s*)[^,}\r\n]+", r"\1[REDACTED]", value)
	value = ANALYSIS_AUTHORIZATION.sub(r"\1[REDACTED]", value)
	value = ANALYSIS_BEARER.sub("[REDACTED]", value)
	value = re.sub(r"(?i)\b(https?://)[^/@\s:]+:[^/@\s]+@", r"\1[REDACTED]@", value)
	value = ANALYSIS_AADHAAR.sub("[AADHAAR]", value)
	value = ANALYSIS_MOBILE.sub("[MOBILE]", value)

	def redact_analysis_field(match: re.Match) -> str:
		original = match.group("value")
		if original.startswith('"') and original.endswith('"'):
			replacement = '"[REDACTED]"'
		elif original.startswith("'") and original.endswith("'"):
			replacement = "'[REDACTED]'"
		else:
			replacement = "[REDACTED]"
		return match.group("prefix") + replacement

	value = ANALYSIS_SENSITIVE_FIELD.sub(redact_analysis_field, value)
	value = ANALYSIS_EMAIL.sub("[EMAIL]", value)
	value = ANALYSIS_PAN.sub("[PAN]", value)
	value = ANALYSIS_BASE64.sub("[BASE64 OMITTED]", value)
	return value


def redact_request_entry(entry: dict) -> dict:
	redacted = dict(entry)
	for field in ("raw", "message"):
		if isinstance(redacted.get(field), str):
			redacted[field] = redact_sensitive_text(redacted[field])
	return redacted


def authorize_request_investigation(token: str | None) -> None:
	if REQUEST_INVESTIGATION_TOKEN and (
		not token or not hmac.compare_digest(token, REQUEST_INVESTIGATION_TOKEN)
	):
		raise HTTPException(status_code=401, detail="Request investigation access denied")


def authorize_environment_access(token: str | None, environment: str) -> None:
	if environment == "prod" and not REQUEST_INVESTIGATION_TOKEN:
		raise HTTPException(
			status_code=503,
			detail="Production access is unavailable until REQUEST_INVESTIGATION_TOKEN is configured",
		)
	authorize_request_investigation(token)
