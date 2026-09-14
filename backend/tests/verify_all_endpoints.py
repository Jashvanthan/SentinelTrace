import json
import urllib.request

BASE_URL = "http://localhost:8000/api/v1"

# 1. Login
login_data = json.dumps({"email": "admin@sentineltrace.io", "password": "Admin@123456!"}).encode("utf-8")
req = urllib.request.Request(f"{BASE_URL}/auth/login", data=login_data, headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req) as resp:
    token = json.loads(resp.read().decode("utf-8"))["access_token"]

headers = {"Authorization": f"Bearer {token}"}

# 2. Test list emails (no workspace_id passed)
req_emails = urllib.request.Request(f"{BASE_URL}/emails/", headers=headers)
with urllib.request.urlopen(req_emails) as resp:
    emails_data = json.loads(resp.read().decode("utf-8"))
    print(f"List emails without workspace_id param: Status {resp.status}, Total = {emails_data['total']}, Count = {len(emails_data['items'])}")
    assert len(emails_data['items']) > 0, "Expected at least 1 analyzed email"
    first_analysis_id = emails_data['items'][0]['id']

# 3. Test get single email analysis
req_single = urllib.request.Request(f"{BASE_URL}/emails/{first_analysis_id}", headers=headers)
with urllib.request.urlopen(req_single) as resp:
    detail = json.loads(resp.read().decode("utf-8"))
    print(f"Get single analysis: Status {resp.status}, Subject: {detail.get('subject')}, Threat Score: {detail.get('threat_score')}")

# 4. Test report download info endpoint
req_report_dl = urllib.request.Request(f"{BASE_URL}/reports/{first_analysis_id}/download", headers=headers)
with urllib.request.urlopen(req_report_dl) as resp:
    dl_info = json.loads(resp.read().decode("utf-8"))
    print(f"Report download route: Status {resp.status}, Download URL: {dl_info.get('download_url')}")

# 5. Test direct PDF report stream
req_pdf = urllib.request.Request(f"{BASE_URL}/reports/{first_analysis_id}/pdf", headers=headers)
with urllib.request.urlopen(req_pdf) as resp:
    pdf_bytes = resp.read()
    print(f"Report PDF download: Status {resp.status}, Size = {len(pdf_bytes)} bytes, starts with %PDF = {pdf_bytes.startswith(b'%PDF')}")
    assert pdf_bytes.startswith(b"%PDF"), "Invalid PDF binary"

# 6. Test Threat Intel IOCs endpoint
req_iocs = urllib.request.Request(f"{BASE_URL}/intel/iocs", headers=headers)
with urllib.request.urlopen(req_iocs) as resp:
    iocs = json.loads(resp.read().decode("utf-8"))
    print(f"Threat Intel IOCs: Status {resp.status}, Total = {iocs['total']}")

# 7. Test Campaign Graph endpoint
req_graph = urllib.request.Request(f"{BASE_URL}/graph/campaign", headers=headers)
with urllib.request.urlopen(req_graph) as resp:
    graph = json.loads(resp.read().decode("utf-8"))
    print(f"Campaign Graph: Status {resp.status}, Nodes = {len(graph['nodes'])}, Edges = {len(graph['edges'])}")

print("\n>>> ALL CHECKS PASSED SUCCESSFULLY! <<<")
