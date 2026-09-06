"""`mlflow` — an MLflow-shaped model registry.

Matches kiyooo's `mlflow` fingerprint (body contains "mlflow") and the
`exposed-model-registry` category (`port_in: [5000]` in the real
deployment — bind this service to 5000 in compose). Experiment *names*
only — `fraud-model-v3` is the risk signal, no artifacts are servable.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from ..common import LAB_NOTICE, decoy_headers

app = FastAPI(title="mlflow (kiyoo-ai lab)", docs_url=None, redoc_url=None)


@app.get("/", response_class=HTMLResponse)
async def root() -> str:
    return f"<h1>MLflow</h1><p>{LAB_NOTICE}</p>"


@app.get("/api/2.0/mlflow/experiments/list")
async def experiments() -> JSONResponse:
    return JSONResponse(
        {
            "mlflow_version": "2.14.0-lab",
            "experiments": [
                {"experiment_id": "1", "name": "fraud-model-v3", "lifecycle_stage": "active"},
                {"experiment_id": "2", "name": "churn-prediction", "lifecycle_stage": "active"},
            ],
        },
        headers=decoy_headers(),
    )
