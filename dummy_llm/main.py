import random
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Dummy LLM")

PHRASES = [
    "Got it — here is a completely safe, simulated response.",
    "Acknowledged. Processing your request within approved policy.",
    "Simulated assistant reply: everything looks clear on my end.",
    "Dummy LLM online. Ready for the next governed prompt.",
]

class LLMRequest(BaseModel):
    prompt: str
    model: str = "dummy-model"

@app.post("/v1/chat")
async def generate(body: LLMRequest):
    return {
        "reply": f"{random.choice(PHRASES)} (Echo: {body.prompt})"
    }