from server.core.finding import Finding

class CPURuler:

    def find(self, ip, severity, title, description):
        return Finding(
            ip=ip,
            severity=severity,
            title=title,
            description=description
        )

    def check(self, ip, cpu):
        findings = []
        
        # Validación de seguridad para evitar KeyErrors si falta alguna clave
        if not isinstance(cpu, dict):
            return findings

        frequency = cpu.get("frequency", {})
        current = frequency.get("current", 0.0)
        maximum = frequency.get("max", 1.0)
        usage = cpu.get("usage", 0.0)
        
        usage_per_core = cpu.get("usage_per_core", [])
        cores = len(usage_per_core) if usage_per_core else 1
        
        load_avg = cpu.get("load_average", [0, 0, 0])
        # El índice 2 corresponde a los 15 minutos en load_average ([1m, 5m, 15m])
        load_15min = load_avg[2] if len(load_avg) > 2 else 0.0
        
        ratio = (current / maximum) if maximum > 0 else 0.0
        
        times = cpu.get("times", {})
        steal = times.get("steal", 0.0)

        if usage > 80 and ratio < 0.6:
            findings.append(self.find(
                ip=ip,
                severity="critical",
                title="CPU Overworking detected",
                description=(
                    f"CPU usage is {usage}% but frequency is "
                    f"{current}MHz/{maximum}MHz"
                )
            ))
            
        if load_15min > cores:
            findings.append(self.find(
                ip=ip,
                severity="warning",
                title="High CPU load",
                description=(
                    f"Load average {load_15min} "
                    f"is higher than CPU cores {cores}"
                )
            ))

        if steal > 30:
            findings.append(self.find(
                ip=ip,
                severity="warning",
                title="High CPU steal",
                description=f"Your steal CPU is {steal}%"
            ))
            
        return findings
        
#It's pendent to do the usage per core alert also the times alert ...
