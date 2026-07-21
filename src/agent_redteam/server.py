"""Optional FastAPI surface.

Exists so a control plane can drive the harness over HTTP and store/serve
reports, without shelling out to the CLI. It is a thin wrapper over the same
library entrypoints the CLI uses — the authorization gate in the runner still
applies, so exposing this endpoint does not create a way to bypass scope-of-use.
Install with the ``server`` extra: ``pip install "agent-redteam[server]"``.
"""

# NOTE: deliberately no ``from __future__ import annotations`` here. FastAPI must
# resolve the request-model annotation to a real class at import time to treat it
# as a request body; stringised annotations would make it misread the body as a
# query parameter.

import uuid
from typing import Any

from agent_redteam.config import AuthorizationError, parse_run_config
from agent_redteam.oracles import default_oracle
from agent_redteam.registry import all_attacks
from agent_redteam.report import Report
from agent_redteam.runner import Runner
from agent_redteam.targets.factory import build_target


def create_app() -> Any:
    # Imported lazily so the core package does not hard-depend on FastAPI.
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel

    import agent_redteam.attacks  # noqa: F401  (register the corpus)

    app = FastAPI(title="agent-redteam", version="0.1.0")
    # A tiny in-memory report store. Deliberately not a database: reports are
    # ephemeral scan artifacts, and persistence is the caller's concern.
    reports: dict[str, Report] = {}

    class ScanRequest(BaseModel):
        target: dict[str, Any]
        run: dict[str, Any] = {}

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/attacks")
    def attacks() -> list[dict[str, Any]]:
        return [
            {"id": s.id, "category": s.category.value,
             "tags": sorted(s.tags), "summary": s.summary}
            for s in all_attacks()
        ]

    @app.post("/scan")
    async def scan(req: ScanRequest) -> dict[str, Any]:
        cfg = parse_run_config({"target": req.target, "run": req.run})
        target = build_target(cfg.target)
        try:
            report = await Runner(default_oracle(), cfg).run(target)
        except AuthorizationError as exc:
            # 403: the request is well-formed but out of authorized scope.
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        report_id = uuid.uuid4().hex
        reports[report_id] = report
        return {"id": report_id, **report.to_dict()}

    @app.get("/report/{report_id}")
    def report(report_id: str) -> dict[str, Any]:
        if report_id not in reports:
            raise HTTPException(status_code=404, detail="unknown report id")
        return reports[report_id].to_dict()

    return app
