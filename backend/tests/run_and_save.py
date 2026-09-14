import httpx
import time

with open("test_results.txt", "w", encoding="utf-8") as f:
    f.write("=== STARTING FULL SIMULATION ===\n")
    client = httpx.Client(base_url="http://localhost:8000/api/v1")

    # 1. Login
    res = client.post("/auth/login", json={"email": "qa_tester@sentineltrace.io", "password": "SentinelQAPass123!"})
    f.write(f"1. Login Status: {res.status_code}\n")
    auth_data = res.json()
    token = auth_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Get Workspaces
    ws_res = client.get("/workspaces", headers=headers)
    f.write(f"2. Workspaces Status: {ws_res.status_code}\n")
    workspaces = ws_res.json()
    workspace_id = workspaces[0]["id"]
    f.write(f"   Active Workspace: {workspaces[0]['name']} ({workspace_id})\n")

    # 3. Upload Sample EML
    eml_sample = b"""From: Security Alert <alert@security-service-update.org>
To: target.user@enterprise.com
Subject: Action Required: Immediate Password Verification Due to Suspicious Login
Date: Thu, 10 Sep 2026 14:22:15 +0000
Content-Type: text/plain; charset="UTF-8"

Dear User,
Our automated SOC systems detected an unauthorized sign-in attempt to your account from IP: 198.51.100.42.
Please verify your credentials immediately: http://security-portal-login.xyz/auth/verify?id=992812
"""
    files = {"file": ("sample_phishing_alert.eml", eml_sample, "message/rfc822")}
    data = {"notes": "Automated verification test", "priority": "HIGH"}
    up_res = client.post(f"/emails/upload?workspace_id={workspace_id}", headers=headers, files=files, data=data)
    f.write(f"3. Upload Status: {up_res.status_code}\n")
    analysis_id = up_res.json()["analysis_id"]
    f.write(f"   Analysis ID: {analysis_id}\n")

    # 4. Polling Analysis
    for attempt in range(15):
        time.sleep(1.5)
        detail_res = client.get(f"/emails/{analysis_id}?workspace_id={workspace_id}", headers=headers)
        detail = detail_res.json()
        status = detail["status"]
        f.write(f"4. Poll #{attempt+1}: Status = {status}\n")
        f.flush()
        if status in ("COMPLETE", "FAILED"):
            f.write("=== ANALYSIS COMPLETED ===\n")
            f.write(f"Status: {detail.get('status')}\n")
            f.write(f"Threat Category: {detail.get('threat_category')}\n")
            f.write(f"Severity: {detail.get('severity')}\n")
            f.write(f"Threat Score: {detail.get('threat_score')}\n")
            f.write(f"Confidence: {detail.get('confidence_score')}\n")
            f.write(f"AI Summary: {detail.get('ai_summary')}\n")
            f.write(f"IOCs: {len(detail.get('iocs', []))}\n")
            break

    f.write("=== SIMULATION FINISHED SUCCESSFULLY ===\n")
