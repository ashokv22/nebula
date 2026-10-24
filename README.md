# UAT Log Investigator

Read-only FastAPI prototype querying existing Loki logs through an SSH tunnel.

## Run in Ubuntu WSL

Terminal 1:

```bash
ssh -N -L 13100:127.0.0.1:3100 dev
```

Terminal 2:

```bash
cd uat-investigator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

Try:

```bash
curl -s http://127.0.0.1:8000/health | jq .
curl -s 'http://127.0.0.1:8000/requests/39c1Yjae?minutes=1440' | jq '{request_id,count,start:(.start.message),end:(.end.message),errors:[.errors[].message]}'
curl -s 'http://127.0.0.1:8000/errors/recent?minutes=60&limit=20' | jq '{count,errors:[.errors[]|{timestamp,request_id,exception,message:(.message|split("\n")[0])}]}'
curl -s http://127.0.0.1:8000/analyze -H 'Content-Type: application/json' -d '{"requestId":"Qwk449Um","minutes":1440}' | jq .
curl -s http://127.0.0.1:8000/analyze -H 'Content-Type: application/json' -d '{"text":"ERROR external API failed with status 502"}' | jq .
```

Docs: http://127.0.0.1:8000/docs

Keep port 8000 bound to localhost unless the service is protected. Set
`REQUEST_INVESTIGATION_TOKEN` to require the `X-Request-Investigation-Token`
header on `/requests/{request_id}` and the new Lead Intelligence endpoints.
Production log endpoints fail closed unless this token is configured. The
detailed response retains request evidence with common password, token, secret,
and authorization values redacted;
large application-log event messages are previews, with full redacted evidence
available in the detailed `timeline` field.

Loki range-query limits apply to the existing request, user, and error endpoints;
large result sets there can be truncated.

## Persistent application logging (Linux)

The FastAPI app configures a DEBUG-level `WatchedFileHandler` at
`/var/log/nebula/nebula.log` and an INFO-level console handler. Uvicorn loggers
and descendants have their handlers cleared and propagate once to the root
handlers to avoid duplicate records. Keep the FastAPI systemd unit's
`StandardOutput` and `StandardError` directed to journald; do not append the
console stream to `/var/log/nebula/nebula.log`, or it will duplicate the file
handler's records. HTTPX wire logging is kept at WARNING. Exception traces include exception type and frame locations,
not exception messages or source lines. Loki logs record duration and result
count without logging the query; Groq provider diagnostics log only allowlisted
error type, parameter, and code values.

No Nebula FastAPI systemd unit was found during setup inspection; the existing
`dcb-ft16-server.service` is a Java service running as `ubuntu`. Set the file
ownership below to the actual FastAPI service user and group. Example for an
`ubuntu` service:

```bash
sudo install -d -o ubuntu -g ubuntu -m 0750 /var/log/nebula
sudo install -d -o root -g root -m 0755 /etc/nebula
sudo install -o root -g root -m 0644 deploy/logrotate/nebula.logrotate \
  /etc/nebula/nebula.logrotate
sudo install -o root -g root -m 0644 deploy/systemd/nebula-logrotate.service \
  /etc/systemd/system/nebula-logrotate.service
sudo install -o root -g root -m 0644 deploy/systemd/nebula-logrotate.timer \
  /etc/systemd/system/nebula-logrotate.timer
sudo systemctl daemon-reload
sudo logrotate --debug --state /var/lib/logrotate/nebula.status \
  /etc/nebula/nebula.logrotate
sudo systemctl enable --now nebula-logrotate.timer
SERVICE=nebula-fastapi.service  # replace with the installed FastAPI unit name
sudo systemctl show "$SERVICE" -p User -p Group
sudo systemctl restart "$SERVICE"
```

Before installation, update `create 0640 ubuntu ubuntu` and `su ubuntu ubuntu`
in `deploy/logrotate/nebula.logrotate` if the FastAPI service has a different
user/group. The app user needs write access to the directory; rotated files are
created mode `0640` for that user/group. This dedicated hourly timer invokes a
separate logrotate config and state file, so it does not alter or race the
system's existing logrotate service/timer configuration. It checks hourly,
rotates at 5 MB, compresses archives, and retains up to 720 hourly rotations
with a 30-day maximum age.

Verify after deployment:

```bash
sudo systemctl status "$SERVICE" nebula-logrotate.timer --no-pager
sudo journalctl -u "$SERVICE" -n 100 --no-pager
sudo tail -n 100 /var/log/nebula/nebula.log
sudo logrotate --force --state /var/lib/logrotate/nebula.status \
  /etc/nebula/nebula.logrotate
sudo ls -l /var/log/nebula
```

Run the logging smoke test from the repository root with
`python3 -m unittest tests.test_logging`.

Set `API_TOKEN` to enable Groq analysis. The service sends only a compact,
redacted diagnostic context to `openai/gpt-oss-20b`; it does not alter the
existing request timeline or raw-log responses. Context defaults are capped at
40 events, 900 characters per event, and 12,000 total characters. Successful
request-ID analyses are cached by the fingerprint of that compact context;
send `"forceRefresh": true` to bypass the cache.

For `/analyze` request-ID investigations, the optional
`X-Request-Investigation-Token` header follows the same protection as the
request timeline endpoint. `minutes` defaults to 60 and is limited to 1-1440.

## Lead Intelligence

The lead investigation endpoint searches exact `leadId`, `applicantId`,
`applicationId`, and `partnerLoanId` field/value associations over a bounded
Loki range, then correlates matching MDC request IDs with their request
timelines. Matches from different identifier aliases remain candidates and
are marked ambiguous when multiple aliases match; identifier equality alone
does not confirm business identity.

```bash
curl -s 'http://127.0.0.1:8000/leads/12345/investigation?env=uat&days=7' \
  -H 'X-Request-Investigation-Token: YOUR_TOKEN' | jq .
curl -s -X POST \
  'http://127.0.0.1:8000/leads/12345/analyze?env=uat&days=7' \
  -H 'X-Request-Investigation-Token: YOUR_TOKEN' | jq .
```

Both endpoints require the configured investigation token when
`REQUEST_INVESTIGATION_TOKEN` is set. `env` defaults to `uat`; Production
investigation fails closed unless `REQUEST_INVESTIGATION_TOKEN` is configured,
and Production log endpoints require that token. Production AI analysis is
disabled unless the server explicitly sets `ALLOW_PROD_AI=true`.
Before a Groq request, evidence is redacted and capped; no Groq request is
made for an empty evidence set.

Lead retrieval limits are configurable through `LEAD_MAX_DAYS` (30),
`LEAD_MAX_REQUEST_IDS` (20), `LEAD_MAX_RETRIEVED_LINES` (2000),
`LEAD_MAX_EVIDENCE` (300),
`LEAD_LOKI_PAGE_SIZE` (500), `LEAD_MAX_LOKI_QUERIES` (120), and
`LEAD_AI_MAX_CONTEXT_CHARS` (10000), and `LEAD_SECURITY_ACCESS_LOGGER`
(`LeadSecurityService`) identifies routine access-check logs. Range, pagination, request-ID, and AI
context truncation are reflected in the response limitations and retrieval
statistics. The query parameters accept `days` from 1 through 30; a lower
`LEAD_MAX_DAYS` setting caps the searched window.

Lead evidence uses separate `INTERNAL_INVESTIGATION` and `EXTERNAL_AI`
redaction policies. The API response masks customer information and secrets in
log evidence before returning concise summaries, while retaining authorized
correlation and technical diagnostic fields. The Groq context pseudonymizes identifiers and uses only
structured, allowlisted event attributes; malformed or unsupported payload
bodies are omitted and noted as limitations. Set `LEAD_PSEUDONYM_KEY` to keep
pseudonyms stable independently of Groq credential rotation; when unset, the
configured `API_TOKEN` is used as the HMAC key.

Known `saveLoan`/`getLoanStatus` Feign events and `External ReverseMapping
Payload` webhook logs are compacted during Loki retrieval. Their full payloads
are excluded from evidence and AI input; only bounded header metadata is kept,
with `payloadOmitted=true` and distinct `API_REQUEST`, `API_RESPONSE`, or
`WEBHOOK_RECEIVED` event types when recognizable. HTTP 200 is reported only as
an observed status, not as proof of business success.

Evidence is the canonical compact collection; raw log lines are not returned,
and each summary is limited to 240 characters. Request timelines contain only
request IDs, first/last observed timestamps, event/failure counts, and evidence
references. Correlation batches selected request IDs into one exact MDC-boundary
query and filters routine lines in LogQL for failures, business actions, stage
changes, rework, external APIs, and request markers. Evidence selection
prioritizes those meaningful categories and retains chronological coverage;
limits and truncation are reported. `timingsMs` reports Loki discovery, request
correlation, preprocessing, and total duration.
