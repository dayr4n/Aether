
#IMPORTING ALL THE RULERS , TO MAKE A CENTRALIZED SYSTEM 
from server.rules.cpu_ruler import CPURuler
from server.rules.process_ruler import ProcessesRuler
from server.rules.ram_ruler import RAMRuler
from server.rules.user_ruler import UsersRuler

#DEFINING THE CORE ENGINE AGENT
class CoreEngine:

  def __init__(self, cpu_ruler, process_ruler, ram_ruler, user_ruler):
    self.cpu_ruler = CPURuler()
    self.process_ruler = ProcessesRuler()
    self.ram_ruler = RAMRuler()
    self.user_ruler = UsersRuler()
#FUNCTION TO MAKE THE CHECK CICLE TO GET THE FINDINGS
  def cheking(self, ip, cpudata, processdata, ramdata, userdata):
    findings = []

    print("----Checking CPU----")
    cpu_findings = self.cpu_ruler.check(ip, cpudata)
    if cpu_findings:
      findings.extend(cpu_findings)

    print("----Cheking PROCESS----")
    process_findings = self.process_ruler.check(ip, processdata)
    if process_findings:
      findings.extend(process_findings)

    print("----Cheking RAM----")
    ram_findings = self.ram_ruler.check(ip, ramdata)
    if ram_findings:
      findings.extend(ram_findings)

    print("----Cheking USER----")
    user_findings = self.user_ruler.check(ip, userdata)
    if user_findings:
      findings.extend(user_findings)

    return findings
