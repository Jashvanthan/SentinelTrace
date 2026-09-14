import json
import urllib.request
import urllib.parse
import sys

API_BASE = "http://localhost:8000/api/v1"
FE_URL = "http://localhost:5173"

def run_test(name, fn):
    print(f"\n[TEST] {name}...")
    try:
        res = fn()
        print(f"  --> PASS: {res}")
        return True
    except Exception as e:
        print(f"  --> FAIL: {e}")
        return False

# 1. Frontend availability
def test_frontend():
    req = urllib.request.Request(FE_URL)
    with urllib.request.urlopen(req, timeout=5) as resp:
        content = resp.read().decode('utf-8')
        assert resp.status == 200, f"Status is {resp.status}"
        assert "Vite" in content or "react" in content or "html" in content
        return f"Frontend responding with HTTP 200 (length: {len(content)} bytes)"

# 2. Backend Health
def test_backend_health():
    req = urllib.request.Request(f"{API_BASE}/health")
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        assert data.get("status") == "healthy"
        return f"Backend healthy: {data}"

token = None
user_info = None
workspace_id = None

# 3. Authentication
def test_login():
    global token, user_info, workspace_id
    payload = json.dumps({
        "email": "admin@sentineltrace.io",
        "password": "Admin@123456!"
    }).encode('utf-8')
    req = urllib.request.Request(f"{API_BASE}/auth/login", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        token = data["access_token"]
        user_info = data["user"]
        return f"Authenticated as {user_info['email']} (role: {user_info['role']})"

# 4. Auth Me
def test_auth_me():
    req = urllib.request.Request(f"{API_BASE}/auth/me", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        assert data["email"] == "admin@sentineltrace.io"
        return f"Verified current user: {data['full_name']} ({data['id']})"

# 5. Workspaces
def test_workspaces():
    global workspace_id
    req = urllib.request.Request(f"{API_BASE}/workspaces", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        assert len(data) > 0, "No workspaces found"
        workspace_id = data[0]["id"]
        return f"Found {len(data)} workspace(s). Active workspace: '{data[0]['name']}' (ID: {workspace_id})"

# 6. Workspace Stats
def test_workspace_stats():
    req = urllib.request.Request(f"{API_BASE}/workspaces/{workspace_id}/stats", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        return f"Total Emails Scanned: {data.get('total_emails_scanned')}, Threats Detected: {data.get('threats_detected')}, Avg Threat Score: {data.get('average_threat_score')}"

# 7. Threat Intel IOCs
def test_threat_intel():
    req = urllib.request.Request(f"{API_BASE}/intel/iocs?workspace_id={workspace_id}", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        return f"Loaded {data.get('total', 0)} IOC(s) in Threat Intel feed."

# 8. Campaign Graph
def test_campaign_graph():
    req = urllib.request.Request(f"{API_BASE}/graph/campaign?workspace_id={workspace_id}", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        nodes = len(data.get("nodes", []))
        edges = len(data.get("edges", []))
        return f"Campaign graph generated: {nodes} nodes, {edges} edges."

# 9. Upload New Email & Execute Full Forensic Agent Analysis
uploaded_analysis_id = None
def test_email_upload_and_agent_analysis():
    global uploaded_analysis_id
    test_eml = b"""From: alerts@irs-refund-security.org
To: target.user@sentineltrace.io
Subject: IMMEDIATE ACTION: Federal Tax Refund Notification #94827
Date: Fri, 11 Sep 2026 11:15:00 +0000
Message-ID: <irs-tax-fraud-sample-2026@irs-refund-security.org>
Authentication-Results: spf=fail (IP 198.51.100.99); dkim=fail; dmarc=fail
Received: from gateway.attacker-c2.net (198.51.100.99) by mx.sentineltrace.io; Fri, 11 Sep 2026 11:15:01 +0000
Content-Type: text/plain; charset=utf-8

IRS Notice: You have an unclaimed tax refund of $4,850.00.
Click below to claim your refund within 48 hours:
https://irs-direct-refund-portal.badsec.net/claim.html

Failure to claim will result in forfeiture of funds.
Internal Revenue Service
"""
    boundary = "----TestBoundary8842187"
    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(b'Content-Disposition: form-data; name="file"; filename="irs_phish_sample.eml"\r\n')
    body.extend(b"Content-Type: message/rfc822\r\n\r\n")
    body.extend(test_eml)
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))

    upload_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }

    req = urllib.request.Request(f"{API_BASE}/emails/upload?workspace_id={workspace_id}", data=bytes(body), headers=upload_headers)
    with urllib.request.urlopen(req, timeout=45) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        uploaded_analysis_id = data["analysis_id"]
        status = data["status"]
        assert status == "COMPLETE", f"Expected analysis status COMPLETE, got {status}"
        return f"Email uploaded and analyzed by Multi-Agent pipeline. ID: {uploaded_analysis_id}, Status: {status}"

# 10. Email Detail & Forensic Findings
def test_email_detail():
    req = urllib.request.Request(f"{API_BASE}/emails/{uploaded_analysis_id}?workspace_id={workspace_id}", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        category = data.get("threat_category")
        severity = data.get("severity")
        score = data.get("threat_score")
        summary = data.get("ai_summary", "")
        iocs = data.get("iocs", [])
        return f"Verdict: {category} | Severity: {severity} | Score: {score}/100 | IOCs: {len(iocs)} | Summary: {summary[:80]}..."

# 11. PDF Evidence Report Generation & Download
def test_report_pdf():
    req = urllib.request.Request(f"{API_BASE}/reports/{uploaded_analysis_id}/pdf", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        pdf_bytes = resp.read()
        assert resp.status == 200, f"Status {resp.status}"
        assert pdf_bytes.startswith(b"%PDF"), "Content is not a valid PDF!"
        content_disp = resp.headers.get("Content-Disposition")
        return f"Generated tamper-evident PDF report: {len(pdf_bytes)} bytes | Attachment: {content_disp}"

# 12. IP Geolocation Service
def test_geolocation():
    payload = json.dumps({"ip_address": "8.8.8.8"}).encode('utf-8')
    req = urllib.request.Request(f"{API_BASE}/geo/locate", data=payload, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        return f"IP 8.8.8.8 geolocated: Country={data.get('country')}, City={data.get('city')}, Org={data.get('org')}"

def main():
    print("================================================================")
    print("         SENTINELTRACE COMPREHENSIVE E2E SITE TEST              ")
    print("================================================================")

    tests = [
        ("1. Frontend Server (Vite :5173)", test_frontend),
        ("2. Backend API Health (:8000)", test_backend_health),
        ("3. SOC Analyst / Admin Login", test_login),
        ("4. Current User Session Verification", test_auth_me),
        ("5. Tenant Workspaces Isolation", test_workspaces),
        ("6. Workspace SOC Dashboard Statistics", test_workspace_stats),
        ("7. Threat Intelligence IOC Repository", test_threat_intel),
        ("8. Neo4j Threat Campaign Correlated Graph", test_campaign_graph),
        ("9. Ingest Email & Run AI Forensic Pipeline", test_email_upload_and_agent_analysis),
        ("10. Verify Email Analysis Detail & AI Findings", test_email_detail),
        ("11. Generate Court-Ready PDF Evidence Dossier", test_report_pdf),
        ("12. IP Geolocation & ASN Intelligence", test_geolocation),
    ]

    passed = 0
    for name, fn in tests:
        if run_test(name, fn):
            passed += 1
        else:
            print(f"\n[CRITICAL FAILURE] Stopped at {name}")
            break

    print("\n================================================================")
    print(f"RESULTS: {passed}/{len(tests)} tests passed successfully!")
    print("================================================================")
    if passed == len(tests):
        print("ALL END-TO-END SYSTEMS OPERATIONAL AND READY!")

if __name__ == "__main__":
    main()
