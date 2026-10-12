#AGENT STORE CLASS WITH THIS CLASS WE WILL CREATE THE PC AGENTS THAT WILL BE REGISTERED
class Agent:
    def __init__(self, ip, version, name):
        self.ip = ip
        self.version = version
        self.name = name
        self.users = {}
        self.system = {}
        self.cpu_core = {}
        self.cpu = {}
        self.ram = {}
        self.processes = {}
        self.network = {}
        self.disk = {}
