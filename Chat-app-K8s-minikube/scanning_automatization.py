import subprocess
import os
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "reports")
RAW_DIR = os.path.join(OUTPUT_DIR, "raw")
HTML_REPORT = os.path.join(OUTPUT_DIR, "k8s_vulnerability_report.html")

os.makedirs(RAW_DIR, exist_ok=True)

def run_command(command):
    print(f"--- Pokrećem: {' '.join(command)} ---")
    result = subprocess.run(command, capture_output=True)
    stdout_text = result.stdout.decode("utf-8", errors="ignore")
    stderr_text = result.stderr.decode("utf-8", errors="ignore")
    if result.returncode != 0:
        print(f"--- Greška: {stderr_text} ---")
        return None
    return stdout_text

# kube-bench parse
def parse_kube_bench_failures(json_text):
    data = json.loads(json_text)
    output = ""

    for control in data.get("Controls", []):
        for test in control.get("tests", []):
            for result in test.get("results", []):
                if result.get("status") == "FAIL":
                    output += (
                        f"ID: {result.get('test_number')}\n"
                        f"Severity: HIGH\n"
                        f"Description: {result.get('test_desc')}\n"
                        f"Remediation: {result.get('remediation')}\n"
                        f"{'-'*60}\n"
                    )

    return output

# trivy parse
def format_trivy(json_text):
    data = json.loads(json_text)
    output = ""
    for result in data.get("Results", []):
        target = result.get("Target")
        vulns = result.get("Vulnerabilities") or []
        filtered = [
            v for v in vulns
            if v.get("Status") not in ("fixed", "will_not_fix")
        ]
        if not filtered:
            continue

        output += f"\nImage: {target}\n"
        for v in filtered:
            output += (
                f" - {v.get('VulnerabilityID')} | {v.get('PkgName')} | "
                f"Severity: {v.get('Severity')} | Status: {v.get('Status')}\n"
            )

    return output

if __name__ == "__main__":
    sections = []

    # kube-bench
    kb_cmd = [
        "docker", "run", "--rm",
        "-e", "KUBECONFIG=/root/.kube/config",
        "-v", os.path.join(os.path.expanduser("~"), ".kube") + ":/root/.kube",
        "aquasec/kube-bench",
        "--benchmark", "cis-1.23",
        "--json"
    ]

    kb_json = run_command(kb_cmd)
    if kb_json:
        with open(os.path.join(RAW_DIR, "kube-bench.json"), "w", encoding="utf-8") as f:
            f.write(kb_json)

        sections.append(
            ("kube-bench (FAIL findings)", parse_kube_bench_failures(kb_json))
        )

    # kube-hunter
    run_command([
        "kubectl", "apply", "-f",
        "https://raw.githubusercontent.com/aquasecurity/kube-hunter/main/job.yaml"
    ])
    run_command([
        "kubectl", "wait",
        "--for=condition=complete",
        "job/kube-hunter",
        "--timeout=120s"
    ])
    kh_text = run_command(["kubectl", "logs", "job/kube-hunter"])
    if kh_text:
        with open(os.path.join(RAW_DIR, "kube-hunter.txt"), "w", encoding="utf-8") as f:
            f.write(kh_text)
        sections.append(("kube-hunter", kh_text))

    # trivy backend i frontend
    for name, image in [
        ("trivy-backend", "krishna026/chat-app-backend-image:latest"),
        ("trivy-frontend", "krishna026/chat-app-frontend-image:latest")
    ]:
        trivy_cmd = [
            "docker", "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "aquasec/trivy", "image",
            "--format", "json",
            image
        ]
        trivy_json = run_command(trivy_cmd)
        if trivy_json:
            with open(
                os.path.join(RAW_DIR, f"{name}.json"),
                "w",
                encoding="utf-8"
            ) as f:
                f.write(trivy_json)

            sections.append((name, format_trivy(trivy_json)))

    # html
    html = "<html><head><title>K8s Scan Report</title></head><body>"
    html += f"<h1>Kubernetes Vulnerability Report</h1>"
    html += f"<p>Generated: {datetime.now()}</p>"

    for title, content in sections:
        html += f"<h2>{title}</h2><pre>{content}</pre>"

    html += "</body></html>"

    with open(HTML_REPORT, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[--- Izvješća generirana u '{OUTPUT_DIR}' ---")
