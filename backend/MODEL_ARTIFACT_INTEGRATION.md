# Internal Model Artifact Integration Guide

This document defines the expected artifact layout for internal transformer providers.
It is intended for backend operators preparing model assets for phased rollout.

## Scope

- Internal-only Python inference providers
- No frontend/public API contract changes
- No rollout toggles are enabled by this document

## Canonical Directory Layout

Place model artifacts under `backend/` using these directories:

- `indicbert_model/` (already active)
- `securebert_model/` (optional, internal provider)
- `muril_model/` (optional, internal provider)

## Required Files Per Provider

Each provider directory must contain all of:

- `config.json`
- `tokenizer.json`
- `tokenizer_config.json`
- `model.safetensors`

These are the minimum files currently required by the backend loader checks.

## File Semantics

- `config.json`
  - Transformer architecture/config metadata
  - Must be compatible with `AutoModelForSequenceClassification`
- `tokenizer.json`
  - Serialized tokenizer graph/rules/vocab
- `tokenizer_config.json`
  - Tokenizer class and runtime behavior metadata
- `model.safetensors`
  - Inference weights
  - Preferred over legacy `.bin` for safer loading semantics

## Placement Process (SecureBERT/MuRIL)

1. Export fine-tuned artifacts using Hugging Face `save_pretrained(...)`.
2. Copy files into:
   - `securebert_model/` for SecureBERT
   - `muril_model/` for MuRIL (future use)
3. Validate file presence and exact names.
4. Restart backend service to pick up new assets.
5. Verify internal readiness using:
   - `GET /internal/model/status`
   - `GET /internal/health`
   - `POST /internal/infer` with selected provider

## Runtime Safety Expectations

- Missing/partial artifacts must not crash startup.
- Provider remains unavailable and returns safe `503` behavior on internal infer.
- Existing deterministic + fallback detector pipeline remains unchanged.

## Current Integration State

- `indicbert`: integrated
- `securebert`: integrated as optional internal provider (loads only when artifacts exist)
- `muril`: integrated as optional internal provider (loads only when artifacts exist)

## Provider health + circuit breaker visibility

When running the internal ensemble endpoint (`POST /analyze`), SecureBERT and MuRIL operate behind a circuit breaker. For debugging/QA:

- `GET /health`: returns provider lifecycle states (`uninitialized | ready | disabled`) and reasons
- `GET /debug/providers`: returns provider health plus circuit breaker fields (`circuit_fail_count`, `disabled_until`)
  - This is internal-only and guarded by `PHISHSHIELD_INTERNAL_API_KEY` when set.

## Operational Notes

- Keep Python service internal-only behind Express.
- Do not route frontend traffic to Python.
- Introduce provider rollout only after artifact quality/consistency validation.
