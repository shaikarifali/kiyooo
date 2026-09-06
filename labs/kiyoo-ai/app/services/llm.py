"""`llm` — an Ollama-shaped + OpenAI-compatible inference endpoint
. Real response shapes on purpose: kiyooo's `ollama` and
`openai_compatible` fingerprints match on the literal text a real server
returns (`GET /` -> "Ollama is running"; `/v1/models` -> the OpenAI list
envelope), so this is not a paraphrase of those responses, it's the same
bytes a live Ollama/vLLM instance would send.

`/api/generate` returns one canned string, always — this is a lab, not a
free inference backend for the internet (see the design, abuse
containment).
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse

from ..common import LAB_NOTICE, decoy_headers

app = FastAPI(title="llm (kiyoo-ai lab)", docs_url=None, redoc_url=None)

_MODEL_ID = "kiyoo-lab-llama3.2:1b"
_CANNED_REPLY = (
    "This is a canned lab response, not a real model. "
    "See http://" + "llm.kiyoo-ai.lab/_lab/notice for details."
)


@app.get("/", response_class=PlainTextResponse)
async def root() -> PlainTextResponse:
    return PlainTextResponse("Ollama is running", headers=decoy_headers())


@app.get("/api/tags")
async def tags() -> JSONResponse:
    return JSONResponse(
        {
            "models": [
                {
                    "name": _MODEL_ID,
                    "model": _MODEL_ID,
                    "size": 1234567,
                    "digest": "labfake0000000000000000000000000000000000000000000000000000000",
                    "details": {
                        "family": "llama",
                        "parameter_size": "1B",
                        "quantization_level": "lab",
                    },
                }
            ]
        },
        headers=decoy_headers(),
    )


@app.get("/v1/models")
async def v1_models() -> JSONResponse:
    return JSONResponse(
        {
            "object": "list",
            "data": [{"id": _MODEL_ID, "object": "model", "owned_by": "kiyoo-ai-lab"}],
        },
        headers=decoy_headers(),
    )


@app.post("/api/generate")
async def generate() -> JSONResponse:
    return JSONResponse(
        {"model": _MODEL_ID, "response": _CANNED_REPLY, "done": True, "lab_notice": LAB_NOTICE},
        headers=decoy_headers(),
    )
