from fastapi import FastAPI
from server.api.routes import router
from server.services.agent_manager import agent_manager
import threading

app = FastAPI()
app.include_router(router)

@app.on_event("startup")
def startup():
    print("---STARTING DETECTION ENGINE---", flush=True)
    threading.Thread(target=agent_manager.runall, daemon=True).start()
    print("---DETECTION ENGINE STARTED---", flush=True)
