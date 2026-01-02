from fastapi import FastAPI, Request

app = FastAPI(title="Demo Backend App")


@app.get("/")
def home():
    # This is a basic endpoint to prove the backend is running
    return {"status": "ok", "message": "Hello from backend"}


@app.get("/search")
def search(q: str = ""):
    # This simulates a common web app feature: searching with a query parameter
    # Example: /search?q=hello
    return {"query": q, "result_count": 1}


@app.post("/login")
async def login(request: Request):
    # This simulates a login endpoint that receives JSON in the request body
    # Example JSON: {"username": "jc", "password": "test"}
    body = await request.json()
    return {"received": body}
