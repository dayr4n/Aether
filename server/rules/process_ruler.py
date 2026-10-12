#DEFINING THE PROCESS RULER 
from server.core.finding import Finding


class ProcessesRuler:

  def find(self, ip, severity, title, description):
    #DEFINING THE FINDING 
    return Finding(
        ip=ip, severity=severity, title=title, description=description
    )

  def check(self, ip, process):
    # GETTING AND DEFINING ALL THE MEASURES 
    fprocesses = process.get("file_processes", [])
    processes = process.get("processes", [])

    ROOT_WHITELIST = {
        "systemd",
        "dbus-broker",
        "NetworkManager",
        "sshd",
        "tailscaled",
        "dockerd",
        "containerd",
        "chronyd",
        "polkitd",
        "systemd-journald",
        "systemd-logind",
        "systemd-udevd",
    }

    findings = []
    danger_zones = ("/tmp", "/dev/shm", "/var/tmp")
    # RUNNING ALL THE PROCESSES LOOKING FOR FINDINGS .
    for p in processes:
      exe_path = p.get("exe")

      # 1. LOOKING FOR PROCESS WITH NO PATH 
      if not exe_path:
        findings.append(
            self.find(
                ip,
                "WARNING",
                "Process is destroying itself, it has no path",
                f"The process {p['name']} doesn't have a path.",
            )
        )
        continue  

      # 2. LOOKING IF SOMEHTING IT'S BEING EXECUTED IN DANGER PATHS
      if any(zone in exe_path for zone in danger_zones):
        findings.append(
            self.find(
                ip,
                "WARNING",
                "Process being exec in danger zone",
                f"The process {p['name']} is being executed in {exe_path}.",
            )
        )

      # 3. LOOKING FOR PROCESS RUNNING WITH ROOT UID OUT OF ROOT_WHITELIST
      uids = p.get("uids")
      if uids and len(uids) > 1 and uids[1] == 0 and p["name"] not in ROOT_WHITELIST:
        findings.append(
            self.find(
                ip,
                "ADVICE",
                f"Process running as root {p['name']}",
                (
                    f"The process {p['name']} (PID: {p.get('pid')})"
                    " is running with root privileges."
                ),
            )
        )

    return findings
        
            
                

        # I have to think about how to itarate all this info ...
