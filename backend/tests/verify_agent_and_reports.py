import asyncio
import json
import urllib.request
import urllib.parse

BASE_URL = "http://localhost:8000/api/v1"

# 1. Login as admin
login_data = json.dumps({"email": "admin@sentineltrace.io", "password": "Admin@123456!"}).encode("utf-8")
req = urllib.request.Request(f"{BASE_URL}/auth/login", data=login_data, headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req) as resp:
    token_resp = json.loads(resp.read().decode("utf-8"))
    token = token_resp["access_token"]
    user = token_resp["user"]
    ws_id = user.get("active_workspace_id")
    print(f"Logged in successfully. User: {user['email']}, Workspace: {ws_id}")

headers = {
    "Authorization": f"Bearer {token}",
}

# 2. Test Threat Intel IOCs
req_iocs = urllib.request.Request(f"{BASE_URL}/intel/iocs", headers=headers)
with urllib.request.urlopen(req_iocs) as resp:
    iocs_data = json.loads(resp.read().decode("utf-8"))
    print(f"Threat Intel IOCs (Status: {resp.status}): Total = {iocs_data.get('total')}, Items count = {len(iocs_data.get('items', []))}")

# 3. Test Campaign Graph
req_graph = urllib.request.Request(f"{BASE_URL}/graph/campaign", headers=headers)
with urllib.request.urlopen(req_graph) as resp:
    graph_data = json.loads(resp.read().decode("utf-8"))
    print(f"Campaign Graph (Status: {resp.status}): Nodes = {len(graph_data.get('nodes', []))}, Edges = {len(graph_data.get('edges', []))}")

# 4. Upload an urgent phishing sample email
sample_eml = b"""From: security-alert@paypa1-update.com
To: victim@company.com
Subject: URGENT: Your PayPal Account Has Been Suspended!
Date: Fri, 11 Sep 2026 10:00:00 +0000
Message-ID: <threat-test-2026@paypa1-update.com>
Authentication-Results: spf=fail (sender IP is 198.51.100.42) smtp.mailfrom=paypa1-update.com; dkim=fail; dmarc=fail
Received: from mail.attacker-node.net (198.51.100.42) by mx.company.com; Fri, 11 Sep 2026 10:00:01 +0000
Content-Type: text/plain; charset=utf-8

Dear Customer,

We detected unauthorized access to your account from IP 203.0.113.19.
You must immediately verify your identity and credit card details at:
http://paypal-security-verification.badsite.ru/login.php

If you do not verify within 24 hours, your account will be permanently closed.

Security Team
"""

# Prepare multipart/form-data
boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
body = bytearray()
body.extend(f"--{boundary}\r\n".encode("utf-8"))
body.extend(b'Content-Disposition: form-data; name="file"; filename="phishing_alert.eml"\r\n')
body.extend(b"Content-Type: message/rfc822\r\n\r\n")
body.extend(sample_eml)
body.extend(b"\r\n")
body.extend(f"--{boundary}--\r\n".encode("utf-8"))

upload_headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": f"multipart/form-data; boundary={boundary}",
}

req_upload = urllib.request.Request(f"{BASE_URL}/emails/upload", data=bytes(body), headers=upload_headers)
with urllib.request.urlopen(req_upload) as resp:
    upload_res = json.loads(resp.read().decode("utf-8"))
    analysis_id = upload_res["analysis_id"]
    print(f"Email uploaded successfully. Analysis ID: {analysis_id}, Status: {upload_res.get('status')}")

# 5. Fetch full analysis details
req_analysis = urllib.request.Request(f"{BASE_URL}/emails/{analysis_id}", headers=headers)
with urllib.request.urlopen(req_analysis) as resp:
    analysis_detail = json.loads(resp.read().decode("utf-8"))
    print("\n--- Forensic Analysis Result ---")
    print(f"Status: {analysis_detail.get('status')}")
    print(f"Verdict / Category: {analysis_detail.get('threat_category')}")
    print(f"Severity: {analysis_detail.get('severity')}")
    print(f"Composite Threat Score: {analysis_detail.get('threat_score')}/100")
    print(f"AI Model Used: {analysis_detail.get('ai_model_used')}")
    print(f"AI Summary: {analysis_detail.get('ai_summary')[:200]}...")
    print(f"Extracted IOCs: {len(analysis_detail.get('iocs', []))} indicators")
    for ioc in analysis_detail.get('iocs', []):
        print(f"  - [{ioc.get('ioc_type')}] {ioc.get('value')}")

# 6. Test PDF report download
req_pdf = urllib.request.Request(f"{BASE_URL}/reports/{analysis_id}/pdf", headers=headers)
with urllib.request.urlopen(req_pdf) as resp:
    pdf_bytes = resp.read()
    print(f"\n--- PDF Evidence Report ---")
    print(f"HTTP Status: {resp.status}")
    print(f"Content-Type: {resp.headers.get('Content-Type')}")
    print(f"Content-Disposition: {resp.headers.get('Content-Disposition')}")
    print(f"PDF Size: {len(pdf_bytes)} bytes")
    assert pdf_bytes.startswith(b"%PDF"), "Response is not a valid PDF document!"
    print("SUCCESS: Valid PDF document generated and downloaded!")
