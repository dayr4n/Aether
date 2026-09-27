from server.rules.cpu_ruler import CPURuler
from server.rules.process_ruler import ProcessesRuler
from server.rules.ram_ruler import RAMRuler
from server.rules.user_ruler import UsersRuler
class CoreEngine:
    def __init__(self, cpu_ruler, process_ruler, ram_ruler, user_ruler):
        self.cpu_ruler = CPURuler()
        self.process_ruler = ProcessesRuler()
        self.ram_ruler = RAMRuler()
        self.user_ruler = UsersRuler()

    

    def cheking(self, ip, cpudata, processdata, ramdata, userdata):
        print("----Checking CPU----")
        self.cpu_ruler.check(ip, cpudata)
        print("----Cheking PROCESS----")
        self.process_ruler.check(ip, processdata)
        print("----Cheking RAM----")
        self.ram_ruler.check(ip, ramdata)
        print("----Cheking USER----")
        self.user_ruler.check(ip, userdata)



        
