from datetime import datetime, timedelta, timezone

import httpx
from fastapi import HTTPException

from core.config import LOKI_URL
from lens.parser import parse_entry


async def loki_query(query: str, minutes: int, limit: int, direction: str = "BACKWARD",
                     window_end: datetime | None = None,
                     window_start: datetime | None = None) -> list[dict]:
    end = window_end or datetime.now(timezone.utc)
    start = window_start or end - timedelta(minutes=minutes)
    params = {"query": query, "start": str(int(start.timestamp() * 1_000_000_000)),
              "end": str(int(end.timestamp() * 1_000_000_000)), "limit": limit,
              "direction": direction}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params)
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"Loki query failed: {type(exc).__name__}") from exc
    if data.get("status") != "success":
        raise HTTPException(status_code=502, detail="Loki returned unsuccessful status")
    entries = [parse_entry(ns, line) for stream in data.get("data", {}).get("result", [])
               for ns, line in stream.get("values", [])]
    entries.sort(key=lambda x: x["timestamp"])
    return entries