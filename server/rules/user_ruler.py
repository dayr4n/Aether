#DEFINING USERS CLASS 
from server.core.finding import Finding


class UsersRuler:
#DEFINING THE FINDING FUNCTION 
    def find(self, ip, severity, title, description):
        return Finding(
            ip=ip,
            severity=severity,
            title=title,
            description=description
        )
#CHEKING FOR FINDINGS 
    def check(self, ip, users):
        findings = []

        if len(users) > 5:
            findings.append(
                self.find(
                    ip,
                    "MEDIUM",
                    "Many logged users",
                    f"There are {len(users)} logged users."
                )
            )

        for user in users:
            if user["host"] not in ("localhost", "127.0.0.1", None):
                findings.append(
                    self.find(
                        ip,
                        "HIGH",
                        "Remote login detected",
                        f"{user['username']} logged in from {user['host']}."
                    )
                )

        for user in users:
            if user["terminal"] is None:
                findings.append(
                    self.find(
                        ip,
                        "LOW",
                        "User without terminal",
                        f"{user['username']} has no associated terminal."
                    )
                )

        for user in users:
            if user["pid"] <= 0:
                findings.append(
                    self.find(
                        ip,
                        "WARNING",
                        "Invalid login PID",
                        f"{user['username']} has PID {user['pid']}."
                    )
                )

        return findings
