from server.models.agent import Agent
from server.core.engine import CoreEngine
import time
class AgentManager:

    #Agent constructor , this only contains state info about the agents 
    def __init__(self):
        self.agents = {}
        self.total_agents = 0
        self.online_agents = 0
        self.registration_count = 0








# API DEFINIIONS / THIS DEFINITIONS ARE THE ONLY ONE CHARGED ABOUT REGISTER AGENTS AND GET INFO ABOUT THE AGENTS 

#FUNCTION TO REGISTER A NEW AGENT AS OBJECT Agent
    def register(self, data):
        ip = data["ip"]
        agent = data["agent"]
        version = data["version"]

        if ip not in self.agents:
            new_agent = Agent(ip=ip, version=version, name=agent)
            self.agents[ip] = new_agent
            self.total_agents += 1
            self.online_agents += 1
            self.registration_count += 1
            print(f"[+] Agent registered: {new_agent.name} ({new_agent.ip})")
            print(f"[*] Total agents: {self.total_agents}")
        else:
            return "The Agent already exists sorry you can't create it .."



#FUNCTION USED TO STORE THE STATIC INFO INTO THE AGENT 
    def staticinfo(self, data):
        ip = data["ip"]

        if ip not in self.agents:
            print("Sorry your agent is not registered..")
        else:
            agent = self.agents[ip]
            agent.users = data["users"]
            agent.system = data["system"]
            agent.cpu_core = data["cpu_core"]
            print("STATIC INFO STORED ON THE SERVER AGENT ..")


#FUNCTION USED TO STORE THE DYNAMIC INFO INTO THE AGENT 
    def dynamicinfo(self, data):
        ip = data["ip"]

        if ip not in self.agents:
            print("Sorry your agent is not registered..")
        else:
            agent = self.agents[ip]
            agent.cpu = data["cpu"]
            agent.ram = data["ram"]
            agent.processes = data["processes"]
            agent.network = data["network"]
            agent.disk = data["disk"]
            print("DYNAMIC INFO STORED ON THE SERVER AGENT ..")


#FUNCTION USED TO RETURN ALL THE INFO OF THE AGENTS , USED FOR THE WEB DASHBOARD
    def list_agents(self):
        return {
            ip: {
                "name": agent.name,
                "version": agent.version,
                "ram": agent.ram,
                "cpu": agent.cpu,
                "users": agent.users,
                "system": agent.system,
                "processes": agent.processes,
                "network": agent.network,
                "disk": agent.disk,
            }
            for ip, agent in self.agents.items()
        }









#FUNCTIONS FOR UTILITIES 

    #GET THE IP OF AN AGENT 
    def get_agent(self, ip):
        return self.agents.get(ip)


    # SYSTEM INFO
    def get_system(self, ip, field):
        agent = self.get_agent(ip)

        if not agent:
            return None
        else:
            return agent.system.get(field)


    # USERS INFO \ INCOMPLETE THERE IS MORE INFORMATION LEFT
    def get_users(self, ip):
        agent = self.get_agent(ip)

        if not agent:
            return None
        else:
            return agent.users


    # CPU INFO
    def get_cpu(self, ip):
        agent = self.get_agent(ip)

        if not agent:
            return None
        else:
            return agent.cpu


    # NETWORK INFO
    def get_network(self, ip, field):
        agent = self.get_agent(ip)

        if not agent:
            return None
        else:
            return agent.network.get(field)


    # DISK INFO
    def get_disk(self, ip, field):
        agent = self.get_agent(ip)

        if not agent:
            return None
        else:
            return agent.disk.get(field)


#RUN FUNCTIONS



#RUN FUNCTION TO SCAN A SPECIFIC AGENT , IT WILL BE CONVERTED AS A COMMAND OF THE SERVICE 
    def run(self, ip):
        agent = self.get_agent(ip)

        engine = CoreEngine()
        engine.cheking(ip, agent.cpu, agent.processes, agent.ram, agent.users )

#RUN FUNCTION TO SCAN WITH THE RULERS ALL THE AGENTS , DOING A FOR IN THE IP
    def runall(self):
        engine = CoreEngine()
        while True :
            for ip in self.agents:
                agent = self.get_agent(ip)
                print ("---CHECKING AGENTS---")
                engine.cheking(ip, agent.cpu, agent.processes, agent.ram, agent.users)
                print ("---AGENTS CHECKED---")
            time.sleep(4)
agent_manager = AgentManager()
