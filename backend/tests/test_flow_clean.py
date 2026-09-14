import httpx
import time

def run_test():
    client = httpx.Client(base_url="http://localhost:8000/api/v1", timeout=30.0)

    # 1. Login
    res = client.post("/auth/login", json={"email": "qa_tester@sentineltrace.io", "password": "SentinelQAPass123!"})
    print(f"1. Login Status: {res.status_code}")
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Get Workspaces
    ws_res = client.get("/workspaces", headers=headers)
    print(f"2. Workspaces Status: {ws_res.status_code}")
    workspaces = ws_res.json()
    workspace_id = workspaces[0]["id"]
    print(f"   Active Workspace: {workspaces[0]['name']} ({workspace_id})")

    # 3. Upload Sample EML
    eml_sample = b"""From: Security Operations <notifications@identity-security-check.org>
To: analyst@sentineltrace.io
Subject: Urgent Security Alert: Account Verification Needed
Date: Thu, 10 Sep 2026 14:22:15 +0000
Content-Type: text/plain; charset="UTF-8"

Please verify your credentials at our identity gateway:
https://identity-security-check.org/portal/verify
"""
    files = {"file": ("security_alert.eml", eml_sample, "message/rfc822")}
    data = {"notes": "Automated security alert test", "priority": "HIGH"}
    up_res = client.post(f"/emails/upload?workspace_id={workspace_id}", headers=headers, files=files, data=data)
    print(f"3. Upload Status: {up_res.status_code}")
    analysis_id = up_res.json()["analysis_id"]
    print(f"   Analysis ID: {analysis_id}")

    # 4. Polling Analysis
    for attempt in range(20):
        time.sleep(1.5)
        detail_res = client.get(f"/emails/{analysis_id}?workspace_id={workspace_id}", headers=headers)
        detail = detail_res.json()
        status = detail["status"]
        print(f"   [Poll #{attempt+1}] Status: {status}")
        if status in ("COMPLETE", "FAILED"):
            print("================ ANALYSIS RESULT ================")
            print(f"Status: {detail.get('status')}")
            print(f"Threat Category: {detail.get('threat_category')}")
            print(f"Severity: {detail.get('severity')}")
            print(f"Threat Score: {detail.get('threat_score')}")
            print(f"AI Summary: {detail.get('ai_summary', '')[:120]}...")
            print(f"IOCs: {len(detail.get('iocs', []))}")
            print("=================================================")
            break

if __name__ == "__main__":
    run_test()
