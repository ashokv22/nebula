import re
from datetime import datetime, timezone

HEADER = re.compile(
    r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) "
    r"\[(?P<thread>[^]]+)\] (?P<level>TRACE|DEBUG|INFO|WARN|ERROR)\s+"
    r"\[(?P<request_id>[^,\]]*),(?P<user>[^\]]*)\] "
    r"\[(?P<pid>[^]]+)\] --- (?P<logger>.*?) : (?P<message>[\s\S]*)$"
)
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
EXCEPTION = re.compile(r"\b([\w.$]+(?:Exception|Error))\b")

EXCEPTION_DECLARATION = re.compile(
    r"(?m)^\s*(?:Caused by:\s*|Suppressed:\s*)?"
    r"(?P<class>[\w.$]+(?:Exception|Error))"
    r"(?::\s*(?P<message>[^\r\n]*))?\s*$"
)

ADVICE_EXCEPTION_DECLARATION = re.compile(
    r"(?m)^\s*GlobalExceptionHandlingControllerAdvice\b[^\r\n]*?"
    r"(?P<class>[\w.$]+(?:Exception|Error))\s*:\s*(?P<message>[^\r\n]*)"
)


def find_exception_declaration(message: str):
    return EXCEPTION_DECLARATION.search(message) or ADVICE_EXCEPTION_DECLARATION.search(message)


def parse_entry(ns: str, raw: str) -> dict:
    cleaned = ANSI.sub("", raw)
    match = HEADER.match(cleaned)
    entry = {"timestamp": datetime.fromtimestamp(int(ns) / 1e9, timezone.utc).isoformat(),
             "raw": cleaned}
    if match:
        entry.update(match.groupdict())
        entry["applicationTimestamp"] = entry.pop("timestamp")
        entry["timestamp"] = datetime.fromtimestamp(int(ns) / 1e9, timezone.utc).isoformat()
        entry["message"] = match.group("message")
    else:
        entry.update({"level": None, "request_id": None, "user": None, "logger": None, "thread": None,
                      "message": cleaned})
    declaration = find_exception_declaration(entry["message"])
    entry["exception"] = declaration.group("class") if declaration else None
    return entry


def parse_request_fields(entry: dict, marker: str) -> dict | None:
    match = re.search(rf"\bREQ {marker}\s*\|(?P<fields>.*)", entry["message"])
    if not match:
        return None
    fields = {}
    segments = match.group("fields").split("|")
    for segment in segments:
        key, separator, value = segment.partition("=")
        if separator:
            fields[key.strip().casefold()] = value.strip()
    result = {"method": fields.get("method"),
              "uri": fields.get("uri") or fields.get("path") or fields.get("url"),
              "status": None, "durationMs": None}
    if segments:
        positional = re.match(r"\s*([A-Za-z]+)\s+(\S+)", segments[0])
        if positional:
            result["method"] = result["method"] or positional.group(1)
            result["uri"] = result["uri"] or positional.group(2)
    status = fields.get("status") or fields.get("statuscode") or fields.get("httpstatus")
    if status and status.isdigit():
        result["status"] = int(status)
    duration = (fields.get("durationms") or fields.get("duration")
                or fields.get("elapsedms"))
    duration_match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(?:ms)?\s*", duration or "",
                                  re.IGNORECASE)
    if duration_match:
        value = float(duration_match.group(1))
        result["durationMs"] = int(value) if value.is_integer() else value
    return result


def _timestamp_key(timestamp: str) -> datetime:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def request_event(entry: dict, request_id: str, event_index: int) -> tuple[dict, dict | None]:
    message = entry["message"]
    start_fields = parse_request_fields(entry, "START")
    end_fields = parse_request_fields(entry, "END")
    if start_fields is not None:
        event_type = "REQUEST_START"
    elif end_fields is not None:
        event_type = "REQUEST_END"
    elif entry["exception"]:
        event_type = "EXCEPTION"
    else:
        event_type = "APPLICATION_LOG"
    exception = None
    exception_match = find_exception_declaration(message)
    if entry["exception"]:
        exception_class = exception_match.group("class") if exception_match else entry["exception"]
        exception_message = exception_match.group("message").strip() if exception_match and exception_match.group("message") else None
        exception = {
            "eventId": f"event-{event_index}",
            "timestamp": entry["timestamp"],
            "requestId": request_id if entry["request_id"] == request_id else None,
            "exceptionClass": exception_class,
            "message": exception_message,
            "stackTrace": message,
        }
    event_message = message.splitlines()[0] if entry["exception"] else message
    truncated = event_type == "APPLICATION_LOG" and len(event_message) > 300
    if truncated:
        event_message = event_message[:297] + "..."
    event = {
        "eventId": f"event-{event_index}",
        "timestamp": entry["timestamp"],
        "level": entry["level"],
        "logger": entry["logger"],
        "thread": entry["thread"],
        "eventType": event_type,
        "message": event_message,
        "raw": entry["raw"],
        "truncated": truncated,
        "requestId": request_id if entry["request_id"] == request_id else None,
    }
    if exception:
        event["exceptionId"] = exception["eventId"]
    return event, exception


def request_marker_metadata(entry: dict, marker: str) -> dict:
    fields = parse_request_fields(entry, marker) or {}
    match = re.search(rf"\bREQ {marker}\s*\|(?P<fields>.*)", entry["message"])
    parsed = {}
    if match:
        for segment in match.group("fields").split("|"):
            key, separator, value = segment.partition("=")
            if separator:
                parsed[key.strip().casefold().replace("_", "")] = value.strip()
    fields.update({
        "platform": parsed.get("platform"),
        "appVersion": parsed.get("appversion"),
        "clientOs": parsed.get("clientos") or parsed.get("os"),
    })
    return fields


def extract_request_id(entry: dict) -> str | None:
    if entry.get("request_id"):
        return entry["request_id"]
    malformed_header = re.match(
        r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} \[[^]]+\] \S+\s+"
        r"\[(?P<request_id>[^,\]]+),",
        entry["raw"],
    )
    return malformed_header.group("request_id") if malformed_header else None


def request_entry_matches(entry: dict, request_id: str) -> bool:
    return extract_request_id(entry) == request_id