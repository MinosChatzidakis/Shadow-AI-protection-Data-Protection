import os
from datetime import datetime, timezone
from typing import List
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dlp import inspect_prompt, load_custom_rules, save_custom_rules

# db dependencies
from contextlib import asynccontextmanager
from db import init_db, log_incident, fetch_logs

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Shadow AI Gateway & DLP Judge", lifespan=lifespan)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"

# Temporary in-memory log (we'll swap this for PostgreSQL in Container 3)
INCIDENT_LOGS: List[dict] = []


class ChatRequest(BaseModel):
    prompt: str
    user: str = "anonymous"
    model: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")


DUMMY_LLM_URL = os.getenv("DUMMY_LLM_URL", "http://dummy-llm:8001/v1/chat")

async def forward_to_llm(prompt: str, model: str) -> str:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            DUMMY_LLM_URL,
            json={"prompt": prompt, "model": model},
        )
        resp.raise_for_status()
        return resp.json()["reply"]

@app.post("/chat")
async def chat_gateway(body: ChatRequest, request: Request):
    try:
        client_ip = request.client.host if request.client else "unknown"
        action, processed_prompt, findings = inspect_prompt(body.prompt)

        ai_reply = None
        if action == "BLOCK":
            ai_reply = "⛔ PROMPT WAS BLOCKED BY DLP - NEVER SENT TO LLM"
        else:
            ai_reply = await forward_to_llm(processed_prompt, body.model)

        log_incident(
            client_ip=client_ip,
            user=body.user,
            action=action,
            findings=findings,
            original_prompt=body.prompt,
            forwarded_prompt=None if action == "BLOCK" else processed_prompt,
            response=ai_reply,
        )
        print(f"[DLP {action}] user={body.user} ip={client_ip} findings={findings}")

        if action == "BLOCK":
            return JSONResponse(
                status_code=403,
                content={
                    "status": "BLOCKED",
                    "reason": f"Sensitive data detected: {', '.join(findings)}",
                    "response": ai_reply,
                },
            )

        return {
            "status": action,
            "findings": findings,
            "forwarded_prompt": processed_prompt,
            "response": ai_reply,
        }
    except Exception as e:
        print(f"[GATEWAY ERROR] {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "ERROR",
                "reason": f"Gateway processing error: {e}",
                "response": f"[GATEWAY ERROR] {e}",
            },
        )


@app.get("/logs")
async def get_logs(limit: int = 500):
    logs = fetch_logs(limit=limit)
    return {"total": len(logs), "logs": logs}


@app.get("/rules")
async def get_rules():
    return {"rules": load_custom_rules()}


@app.post("/rules")
async def add_or_update_rule(rule: dict):
    rules = load_custom_rules()
    rule_id = rule.get("id") or f"rule-{int(datetime.now().timestamp())}"
    rule["id"] = rule_id
    existing_idx = next((i for i, r in enumerate(rules) if r.get("id") == rule_id), None)
    if existing_idx is not None:
        rules[existing_idx] = rule
    else:
        rules.append(rule)
    save_custom_rules(rules)
    return {"status": "ok", "rule": rule, "rules": rules}


@app.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str):
    rules = load_custom_rules()
    filtered = [r for r in rules if r.get("id") != rule_id]
    save_custom_rules(filtered)
    return {"status": "ok", "deleted": rule_id, "rules": filtered}


@app.post("/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str):
    rules = load_custom_rules()
    target_rule = None
    for r in rules:
        if r.get("id") == rule_id:
            r["enabled"] = not r.get("enabled", True)
            target_rule = r
            break
    save_custom_rules(rules)
    return {"status": "ok", "rule": target_rule, "rules": rules}


@app.post("/webhook/alert")
async def dns_alert_webhook(request: Request):
    try:
        body = await request.json()
        client_ip = body.get("client_ip", "unknown")
        domain = body.get("target_domain", "unknown")
        action = body.get("action", "BLOCK")
        log_incident(
            client_ip=client_ip,
            user="dns-firewall",
            action=action,
            findings=[f"Domain: {domain}"],
            original_prompt=f"Direct DNS resolution attempt to blocked Shadow AI domain: {domain}",
            forwarded_prompt=None,
        )
        return {"status": "ok"}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    
""" @app.post("/v1/chat/completions")
async def openai_proxy(request: Request):
    body = await request.json()
    client_ip = request.client.host if request.client else "unknown"
    # Identify the developer from their internal Authorization header
    user = request.headers.get("authorization", "Bearer unknown").replace("Bearer ", "")

    all_findings = []
    final_action = "ALLOW"
    cleaned_messages = []

    # Scan every message in the conversation array
    for msg in body.get("messages", []):
        content = msg.get("content", "")
        action, processed, findings = inspect_prompt(content)

        if action == "BLOCK":
            INCIDENT_LOGS.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client_ip": client_ip,
                "user": user,
                "action": "BLOCK",
                "findings": findings,
                "original_prompt": content,
                "forwarded_prompt": None,
            })
            return JSONResponse(
                status_code=403,
                content={"error": {"message": f"DLP Blocked: {', '.join(findings)}"}},
            )

        if action == "REDACT":
            final_action = "REDACT"
            all_findings.extend(findings)

        cleaned_messages.append({**msg, "content": processed})

    # Log ALLOW / REDACT
    INCIDENT_LOGS.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "user": user,
        "action": final_action,
        "findings": list(set(all_findings)),
        "original_prompt": str(body.get("messages")),
        "forwarded_prompt": str(cleaned_messages),
    })

    # Swap in cleaned messages
    body["messages"] = cleaned_messages

    # Mock mode if no real OpenAI key is set
    if not GEMINI_API_KEY:
        return {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": f"[MOCK] Received: {cleaned_messages[-1]['content']}"},
                "finish_reason": "stop",
            }],
        }

    # Forward to real OpenAI with the gateway's real API key
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            GEMINI_URL,
            headers={"Authorization": f"Bearer {GEMINI_API_KEY}"},
            json=body,
        )
        return JSONResponse(status_code=resp.status_code, content=resp.json()) """