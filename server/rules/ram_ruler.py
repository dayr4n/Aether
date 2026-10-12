#DEFINING THE RAM RULER 
from server.core.finding import Finding


class RAMRuler:

  def __init__(self):
    pass
#DEFINING THE FINDING ASPECT
  def find(self, ip, severity, title, description):
    return Finding(
        ip=ip, severity=severity, title=title, description=description
    )
#STARTING WITH THE CHECK 
  def check(self, ip, ram):
    findings = []
    # EXTRACTING RAM IF IT COMES AS A LIST 
    if isinstance(ram, list):
      if len(ram) > 0 and isinstance(ram[0], dict):
        vm = ram[0]
      else:
        # IF THERE IS NO LIST OR DICTIONARY WE RETURN THE PROGRAM FOR DON'T RETURN ERRORS .
        return findings
    elif isinstance(ram, dict):
      vm = ram.get("virtual_memory", ram)
    else:
      return findings

    # HERE WE GOT A SECURE DICTIONARY AND WE START DEFINING THE PARTS OF IT 
    usage = vm.get("percent", 0)
    total = vm.get("total", 1)

    # IF TOTAL IS 0 WE RETURN TO DON'T RETURN ERRORS
    if total == 0:
      return findings

    used = vm.get("used", 0)
    available = vm.get("available", 0)
    free = vm.get("free", 0)
    cached = vm.get("cached", 0)
    active = vm.get("active", 0)
    inactive = vm.get("inactive", 0)
    shared = vm.get("shared", 0)

    # Ratios
    used_ratio = used / total
    available_ratio = available / total
    free_ratio = free / total
    cached_ratio = cached / total
    active_ratio = active / total
    inactive_ratio = inactive / total
    shared_ratio = shared / total
#FUNCTIONS TO RETURN FINDINGS WITH THE RATIOS OF RAM 
    if used_ratio > 0.95:
      findings.append(
          self.find(
              ip,
              "CRITICAL",
              "RAM overused",
              f"The RAM is full {used_ratio:.1%}",
          )
      )
    elif used_ratio > 0.80:
      findings.append(
          self.find(
              ip, "HIGH", "RAM high used", f"The RAM it's high used {used_ratio:.1%}"
          )
      )
    elif used_ratio > 0.70:
      findings.append(
          self.find(
              ip,
              "HIGH",
              "RAM medium used",
              f"The RAM it's medium used {used_ratio:.1%}",
          )
      )

    if available_ratio < 0.05:
      findings.append(
          self.find(
              ip,
              "CRITICAL",
              "High memory usage",
              f"Memory usage is {used_ratio:.1%} ({used} bytes used of {total} bytes).",
          )
      )
    elif available_ratio < 0.10:
      findings.append(
          self.find(
              ip,
              "HIGH",
              "High memory utilisation",
              f"Memory usage is {used_ratio:.1%} ({used} bytes used of {total} bytes).",
          )
      )

    if active_ratio > 0.80:
      findings.append(
          self.find(
              ip,
              "WARNING",
              "High percent of memory is active",
              f"Memory active is {active_ratio:.1%} ({used} bytes used of {total} bytes).",
          )
      )

    if inactive_ratio < 0.02 and used_ratio > 0.90:
      findings.append(
          self.find(
              ip,
              "WARNING",
              "Low reclaimable memory",
              f"RAM usage is {used_ratio:.1%} and inactive memory is only {inactive_ratio:.1%}.",
          )
      )

    if shared_ratio > 0.20:
      findings.append(
          self.find(
              ip,
              "WARNING",
              "High shared memory",
              f"RAM shared is {shared_ratio:.1%} and used memory is {used_ratio:.1%}.",
          )
      )

    return findings
