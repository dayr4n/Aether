from fastapi import APIRouter
from server.services.agent_manager import agent_manager

router = APIRouter()

#ROUTE TO REGISTER AGENTS
@router.post("/agents/register")
def register(data: dict):
    print("========= REGISTER ==========")
    agent_manager.register(data)
    print("========= END REGISTER ==========")
    return {"Agent recieved , thank you we will start the monitorization .."}

#ROUTE TO CAPTURE DYNAMIC DATA
@router.post("/agents/dynamic")
def recieve_dynamic(data: dict):
    print("========= CAPTURING DYNAMIC ==========")
    agent_manager.dynamicinfo(data)
    print("========= END CAPTURING DYNAMIC ==========")
    return {"Dynamic info stored , thank you we will start the monitorization .."}

#ROUTE TO CAPTURE STATIC DATA 
@router.post("/agents/static")
def recieve_static(data: dict):
    print("========= CAPTURING STATIC ==========")
    agent_manager.staticinfo(data)
    print("========= END CAPTURING STATIC ==========")
    return {"Static info stored , thank you we will start the monitorization .."}

#ROUTE TO SEE AGENTS COMPLETE INFO , NOT SECURE JUST FOR DEBUG 
@router.get("/agents/info")
def agentsinfo():
    print("========= AGENTS INFO ==========")
    return {"agents": agent_manager.list_agents()}
    print("========= END AGENTS INFO ==========")
