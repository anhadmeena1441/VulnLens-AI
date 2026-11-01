
EXPLANATIONS = {
    "B404": {
        "title": "Subprocess module imported",
        "risk": "The subprocess module can execute external programs. Its use should be reviewed carefully.",
        "attack": "If untrusted input is passed to an external command, an attacker may influence the command being executed.",
        "recommendation": "Avoid executing shell commands with untrusted input. Prefer safer APIs and fixed command arguments.",
        "example": '''# Safer approach: avoid shell=True
import subprocess

subprocess.run(
    ["echo", "Hello"],
    shell=False,
    check=True
)'''
    },
    "B602": {
        "title": "Subprocess with shell=True",
        "risk": "Executing a shell command with shell=True can introduce command injection vulnerabilities.",
        "attack": "An attacker may supply shell metacharacters or additional commands through untrusted input.",
        "recommendation": "Avoid shell=True. Use a fixed executable and pass arguments as a list. Validate user input.",
        "example": '''# Safer approach
import subprocess

subprocess.run(
    ["echo", user_input],
    shell=False,
    check=True
)'''
    },
    "B301": {
        "title": "Unsafe pickle deserialization",
        "risk": "Unpickling untrusted data can execute arbitrary code.",
        "attack": "A malicious pickle payload may execute code during deserialization.",
        "recommendation": "Never unpickle data from untrusted sources. Consider safer data formats such as JSON.",
        "example": '''import json

data = json.loads(json_string)'''
    },
    "B105": {
        "title": "Possible hardcoded password",
        "risk": "Hardcoded passwords can be exposed through source code or version control.",
        "attack": "Anyone who obtains the source code may discover and reuse the password.",
        "recommendation": "Use environment variables or a secure secrets manager.",
        "example": '''import os

password = os.getenv("APP_PASSWORD")'''
    }
}


def explain_finding(finding):
    code = finding.get("test_id", "UNKNOWN")
    details = EXPLANATIONS.get(code)

    if not details:
        return {
            "title": f"Security finding: {code}",
            "risk": finding.get("issue_text", "Review this security finding."),
            "attack": "The potential impact depends on the surrounding code.",
            "recommendation": "Review the scanner documentation and validate the finding manually.",
            "example": "Review the affected source code."
        }

    return details
