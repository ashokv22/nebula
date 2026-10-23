import hmac
import json
import re
from typing import Literal

from fastapi import HTTPException

from core.config import LEAD_PSEUDONYM_KEY, REQUEST_INVESTIGATION_TOKEN

RedactionPolicy = Literal["INTERNAL_INVESTIGATION", "EXTERNAL_AI"]

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
LEAD_FIELD_CATEGORIES = {
	"identity": frozenset("""customername applicantname firstname middlename lastname fullname
		customerfullname applicantfullname borrowername dependentname nomineename customerid
		customerreference externalcustomerid fathername mothername spousename guardianname
		dateofbirth birthdate dob gender maritalstatus nationality passport passportno
		passportnumber voterid voteridnumber drivinglicense drivinglicensenumber identitydocument
		identitydocumentnumber identityproof proofofidentity documentnumber identitynumber
		nationalid kycnumber taxid""".split()),
	"contact": frozenset("""mobileno primarymobilenumber alternatemobilenumber mobile phonenumber
		phone telephone whatsappnumber emailaddress email address mailingaddress
		residentialaddress permanentaddress currentaddress communicationaddress streetaddress
		addressline1 addressline2 addressline3 addressline4 city district statename pincode
		postalpincode postalcode zipcode""".split()),
	"credentials": frozenset("""password passwd pwd token bearertoken authtoken accesstoken
		refreshtoken idtoken clientid clientsecret apikey apisecret authorization secret secretkey
		secretvalue privatekey cookie sessiontoken sessionkey sessionid csrftoken jwt
		securityanswer otp otpvalue onetimepassword cvv securitycode""".split()),
	"financial": frozenset("""aadhaarvaultnumber aadharnumber aadhaarnumber aadhaarno aadharno
		aadhaar aadhar externalaadhaarrefno applicantexternalaadhaarrefno aadhaarref
		aadhaarreference aadharvaultnumber pan panno pannumber accountnumber accountno
		bankaccountnumber bankaccountno beneficiarybankaccountno ifsccode beneficiaryifsccode
		routingnumber cardnumber creditcardnumber salary income""".split()),
	"correlation": frozenset("""leadid applicantid applicationid partnerloanid requestid traceid
		correlationid""".split()),
}
LEAD_FIELD_ASSIGNMENT = re.compile(
	r"""(?<![A-Za-z0-9_])["']?(?P<key>[A-Za-z][A-Za-z0-9_-]*)["']?\s*[:=]\s*"""
)
LEAD_STRUCTURED_DTO = re.compile(r"\b[A-Z][A-Za-z0-9_$]*(?:Dto|Request|Response)\s*\(")
LEAD_TECHNICAL_KEYS = frozenset({
	"amount", "loanamount", "totalamount", "price", "cost", "rate", "balance",
	"status", "statuscode", "httpstatus", "httpstatuscode", "duration", "durationms",
	"elapsed", "elapsedms", "timestamp", "time", "errorcode", "errorclass",
	"errortype", "exceptiontype", "code", "leadid", "applicantid", "applicationid",
	"partnerloanid", "requestid", "traceid", "correlationid",
})
LEAD_EXTERNAL_SAFE_FIELDS = frozenset({
	"action", "operation", "event", "eventtype", "stage", "fromstage", "tostage",
	"oldstage", "newstage", "result", "outcome", "validationcode", "failurecode",
	"apiname", "service", "retrycount", "attempt", "attemptnumber", "method",
	"logger", "severity", "level", "exceptiontype", "errorclass", "apioperation",
	"httpmethod", "endpointpath", "httpstatus", "durationms", "errorcode",
	"payloadomitted",
})
LEAD_EXTERNAL_CONTAINERS = frozenset({
	"lead", "applicant", "applicantdetails", "customer", "customerdetails", "contact",
	"contactdetails", "identitydetails", "application", "data", "payload", "request", "response",
})
LEAD_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
LEAD_PAN = re.compile(r"(?i)\b[A-Z]{5}\d{4}[A-Z]\b")
LEAD_AADHAAR = re.compile(r"(?<!\d)(?:\d{4}[ -]?){2}\d{4}(?!\d)")
LEAD_MOBILE = re.compile(r"(?<!\d)(?:\+?91[ -]?)?[6-9](?:[ -]?\d){9}(?!\d)")
LEAD_SECRET_TOKEN = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
LEAD_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
LEAD_AUTH_HEADER = re.compile(
	r"""(?i)(\bauthorization\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^,;|}\r\n]+)"""
)
INTERNAL_INVESTIGATION = "INTERNAL_INVESTIGATION"
EXTERNAL_AI = "EXTERNAL_AI"


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


def _normalized_lead_key(key: str) -> str:
	return re.sub(r"[^a-z0-9]", "", key.casefold())


def _lead_field_category(key: str) -> str | None:
	normalized = _normalized_lead_key(key)
	return next(
		(category for category, keys in LEAD_FIELD_CATEGORIES.items() if normalized in keys),
		None,
	)


def _pseudonym(value: str, category: str, key: str) -> str:
	from os import getenv

	secret = LEAD_PSEUDONYM_KEY or getenv("API_TOKEN")
	if not secret:
		raise ValueError("LEAD_PSEUDONYM_KEY or API_TOKEN is required for external identifier pseudonyms")
	digest = hmac.new(
		secret.encode(),
		f"{category}:{_normalized_lead_key(key)}:{value}".encode(),
		"sha256",
	).hexdigest()[:12]
	return f"[{category.upper()}_{digest}]"


def _redact_leaf(value: str, key: str, policy: str, lead_id: str | None) -> str:
	category = _lead_field_category(key)
	normalized = _normalized_lead_key(key)
	if category in {"identity", "contact", "credentials", "financial"}:
		return "[REDACTED]" if value else value
	if category == "correlation":
		if policy == INTERNAL_INVESTIGATION:
			if normalized in {"leadid", "applicantid", "applicationid", "partnerloanid"} and value == lead_id:
				return value
			if normalized in {"requestid", "traceid", "correlationid"}:
				return value
			return "[REDACTED]" if value else value
		return _pseudonym(value, "id", key) if value else value
	return _redact_standalone(value)


def _redact_standalone(value: str) -> str:
	value = LEAD_AUTH_HEADER.sub(r"\1[REDACTED]", value)
	value = LEAD_SECRET_TOKEN.sub("[REDACTED]", value)
	value = LEAD_JWT.sub("[REDACTED]", value)

	def redact_pattern(pattern: re.Pattern, label: str) -> str:
		def replacement(match: re.Match) -> str:
			previous_matches = list(LEAD_FIELD_ASSIGNMENT.finditer(value, 0, match.start()))
			previous = previous_matches[-1] if previous_matches else None
			if previous and _normalized_lead_key(previous.group("key")) in LEAD_TECHNICAL_KEYS:
				between = value[previous.end():match.start()]
				if not re.search(r"\s", between):
					return match.group(0)
			return label
		return pattern.sub(replacement, value)

	value = redact_pattern(LEAD_AADHAAR, "[AADHAAR]")
	value = redact_pattern(LEAD_MOBILE, "[MOBILE]")
	value = redact_pattern(LEAD_PAN, "[PAN]")
	return redact_pattern(LEAD_EMAIL, "[EMAIL]")


def _sanitize_json(value, policy: str, lead_id: str | None, supported: list[bool]):
	if isinstance(value, dict):
		result = {}
		for key, item in value.items():
			normalized = _normalized_lead_key(str(key))
			category = _lead_field_category(str(key))
			if category in {"identity", "contact", "credentials", "financial"}:
				result[key] = "[REDACTED]" if item not in (None, "") else item
			elif category == "correlation" and isinstance(item, (str, int, float)):
				result[key] = _redact_leaf(str(item), str(key), policy, lead_id)
			elif _normalized_lead_key(str(key)) in LEAD_TECHNICAL_KEYS:
				result[key] = item
			else:
				if (
					policy == EXTERNAL_AI
					and not isinstance(item, (dict, list))
					and item not in (None, "")
					and normalized not in LEAD_EXTERNAL_SAFE_FIELDS
					and normalized not in LEAD_EXTERNAL_CONTAINERS
				):
					supported[0] = False
				result[key] = _sanitize_json(item, policy, lead_id, supported)
		return result
	if isinstance(value, list):
		return [_sanitize_json(item, policy, lead_id, supported) for item in value]
	if isinstance(value, str):
		return _redact_standalone(value)
	return value


def _balanced_dto_payload(value: str) -> bool:
	match = LEAD_STRUCTURED_DTO.search(value)
	if not match:
		return True
	depth = 0
	quote = None
	escaped = False
	for char in value[match.end() - 1:]:
		if escaped:
			escaped = False
		elif char == "\\":
			escaped = True
		elif quote:
			if char == quote:
				quote = None
		elif char in "\"'":
			quote = char
		elif char == "(":
			depth += 1
		elif char == ")":
			depth -= 1
			if depth == 0:
				return True
	return False


def _sanitize_assignments(
	value: str,
	policy: str,
	lead_id: str | None,
	supported: list[bool] | None = None,
) -> str:
	matches = list(LEAD_FIELD_ASSIGNMENT.finditer(value))
	if not matches:
		return _redact_standalone(value)
	if supported is not None:
		prefix = value[:matches[0].start()]
		tail = value[matches[-1].end():]
		suffix = tail[len(tail.rstrip(" ,;|)}]")):]
		if (
			not re.fullmatch(
				r"(?:[\s\(\[\{,;|]|[A-Z][A-Za-z0-9_$]*(?:Dto|Request|Response)\s*\()*",
				prefix,
			)
			or not re.fullmatch(r"[\s,;|)}\]]*", suffix)
		):
			supported[0] = False
	parts = []
	cursor = 0
	for index, match in enumerate(matches):
		parts.append(value[cursor:match.end()])
		value_start = match.end()
		value_end = matches[index + 1].start() if index + 1 < len(matches) else len(value)
		while value_end > value_start and value[value_end - 1] in " ,;|)}]":
			value_end -= 1
		original = value[value_start:value_end]
		key = match.group("key")
		category = _lead_field_category(key)
		normalized = _normalized_lead_key(key)
		if (
			supported is not None
			and category is None
			and normalized not in LEAD_TECHNICAL_KEYS
			and normalized not in LEAD_EXTERNAL_SAFE_FIELDS
			and normalized not in LEAD_EXTERNAL_CONTAINERS
			and original.strip()
		):
			supported[0] = False
		if category or _normalized_lead_key(key) in LEAD_TECHNICAL_KEYS:
			if category:
				replacement = _redact_leaf(original.strip().strip("\"'"), key, policy, lead_id)
				if original.startswith('"') and original.endswith('"'):
					replacement = json.dumps(replacement)
			else:
				replacement = original
			parts.append(replacement)
		else:
			parts.append(original)
		cursor = value_end
	parts.append(value[cursor:])
	return _redact_standalone("".join(parts))


def redact_lead_evidence_text(
	value: str,
	lead_id: str | None = None,
	policy: RedactionPolicy = INTERNAL_INVESTIGATION,
) -> str:
	if policy not in {INTERNAL_INVESTIGATION, EXTERNAL_AI}:
		raise ValueError(f"Unsupported lead redaction policy: {policy}")
	trimmed = value.lstrip()
	if trimmed.startswith(("{", "[")):
		try:
			parsed = json.loads(value)
		except json.JSONDecodeError:
			return "[UNSAFE_PAYLOAD_OMITTED]" if policy == EXTERNAL_AI else _sanitize_assignments(value, policy, lead_id)
		supported = [True]
		sanitized = _sanitize_json(parsed, policy, lead_id, supported)
		if policy == EXTERNAL_AI and not supported[0]:
			return "[UNSAFE_PAYLOAD_OMITTED]"
		return json.dumps(sanitized, ensure_ascii=True, separators=(",", ":"))
	if not _balanced_dto_payload(value):
		return "[UNSAFE_PAYLOAD_OMITTED]" if policy == EXTERNAL_AI else _sanitize_assignments(value, policy, lead_id)
	supported = [True] if policy == EXTERNAL_AI else None
	result = _sanitize_assignments(value, policy, lead_id, supported)
	if policy == EXTERNAL_AI and (supported == [False] or not LEAD_FIELD_ASSIGNMENT.search(value)):
		return "[UNSAFE_PAYLOAD_OMITTED]"
	if policy == INTERNAL_INVESTIGATION and lead_id:
		result = re.sub(
			r"(?<![A-Za-z0-9_])" + re.escape(lead_id) + r"(?![A-Za-z0-9_])",
			lead_id,
			result,
		)
	return result


def redact_lead_entry(
	entry: dict,
	lead_id: str | None = None,
	policy: RedactionPolicy = INTERNAL_INVESTIGATION,
) -> dict:
	redacted = dict(entry)
	for field in ("raw", "message"):
		if isinstance(redacted.get(field), str):
			redacted[field] = redact_lead_evidence_text(redacted[field], lead_id, policy)
	if isinstance(redacted.get("user"), str):
		redacted["user"] = "[REDACTED]"
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
