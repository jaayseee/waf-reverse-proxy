from fastapi import FastAPI, Request

app = FastAPI(title="Demo Backend App")

@app.get("/")
def home():
    return {"status": "ok", "message": "Hello from backend"}

@app.get("/search")
def search(q: str = ""):
    return {"query": q, "result_count": 1}

@app.post("/login")
async def login(request: Request):
    body = await request.json()
    return {"received": body}
