"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import time
import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input and start timestamp keyed by request_id/user_id."""
        key = request_id or user_id
        now = time.time()

        self._open[key] = now

        self.logs.append({
            "request_id": request_id,
            "user_id": user_id,
            "input": text,
            "started_at": datetime.fromtimestamp(
                now, timezone.utc
            ).isoformat(),
            "output": None,
            "blocked": False,
            "layer": None,
            "latency_ms": None,
        })

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, decision, and latency."""
        key = request_id or user_id
        now = time.time()
        started = self._open.pop(key, now)

        # Find the latest matching input record without an output.
        entry = next(
            (
                log for log in reversed(self.logs)
                if log["user_id"] == user_id
                and log["request_id"] == request_id
                and log["output"] is None
            ),
            None,
        )

        if entry is None:
            entry = {
                "request_id": request_id,
                "user_id": user_id,
                "input": None,
                "started_at": datetime.fromtimestamp(
                    started, timezone.utc
                ).isoformat(),
            }
            self.logs.append(entry)

        entry.update({
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": round((now - started) * 1000, 2),
            "completed_at": datetime.fromtimestamp(
                now, timezone.utc
            ).isoformat(),
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk as a JSON array."""
        path = Path(filepath or default_audit_log_path())

        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as f:
            json.dump(
                self.logs,
                f,
                indent=2,
                ensure_ascii=False,
            )

        return str(path)

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
