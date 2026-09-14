"""
End-to-End Live Verification of Email -> Observed IP -> Geolocation Tracing
"""
import httpx
import sys
import uuid

API_BASE = "http://localhost:8000/api/v1"

def run_e2e_tests():
    print("\n========================================================")
    print(" SentinelTrace: Email -> IP Geolocation Live E2E Suite")
    print("========================================================\n")

    client = httpx.Client(timeout=15.0)

    # 1. Login
    print("[1/8] Authenticating Admin User...")
    login_resp = client.post(f"{API_BASE}/auth/login", json={
        "email": "admin@sentineltrace.io",
        "password": "Admin@123456!"
    })
    if login_resp.status_code != 200:
        print(f"FAILED: Login error {login_resp.status_code}: {login_resp.text}")
        sys.exit(1)
    
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("  [OK] Authenticated successfully.")

    # 2. Workspaces
    print("\n[2/8] Fetching Workspaces...")
    ws_resp = client.get(f"{API_BASE}/workspaces", headers=headers)
    assert ws_resp.status_code == 200, f"Failed to get workspaces: {ws_resp.text}"
    workspaces = ws_resp.json()
    if len(workspaces) == 0:
        create_ws = client.post(f"{API_BASE}/workspaces", headers=headers, json={"name": "Primary SOC Workspace"})
        workspace_id = create_ws.json()["id"]
        print(f"  [OK] Created Workspace ID: {workspace_id} (Primary SOC Workspace)")
    else:
        workspace_id = workspaces[0]["id"]
        print(f"  [OK] Active Workspace ID: {workspace_id} ({workspaces[0]['name']})")

    # 3. Email Analyses
    print("\n[3/8] Querying Email Analyses for Workspace...")
    emails_resp = client.get(f"{API_BASE}/emails/", headers=headers, params={"workspace_id": workspace_id})
    assert emails_resp.status_code == 200, f"Failed to list emails: {emails_resp.text}"
    email_items = emails_resp.json()["items"]
    print(f"  [OK] Found {len(email_items)} analyzed emails in workspace.")

    if len(email_items) == 0:
        print("  ! No emails exist in workspace, creating a sample analysis via upload...")
        sample_eml = b"""From: alerts@paypal-security-update.com
To: victim@company.com
Subject: Urgency: Account Compromise Detected
Date: Mon, 10 Sep 2026 12:00:00 +0000
Message-ID: <12345@paypal-security-update.com>
Received: from mail.attacker-server.net ([185.220.101.5]) by mx.google.com with ESMTPS; Mon, 10 Sep 2026 12:00:01 +0000
Received: from internal-node ([10.0.4.15]) by mail.attacker-server.net; Mon, 10 Sep 2026 11:59:58 +0000

Please verify your credentials immediately at http://paypal-credential-harvest.ru/login
Observed transit node: 104.21.5.10
"""
        upload_resp = client.post(
            f"{API_BASE}/emails/upload",
            headers=headers,
            params={"workspace_id": workspace_id},
            files={"file": ("urgent_alert.eml", sample_eml, "message/rfc822")}
        )
        assert upload_resp.status_code in (200, 201, 202), f"Upload failed: {upload_resp.text}"
        analysis_id = upload_resp.json()["analysis_id"]
        print(f"  [OK] Created & Analyzed sample email with ID: {analysis_id}")
    else:
        analysis_id = email_items[0]["id"]
        print(f"  [OK] Using existing email analysis ID: {analysis_id}")

    # 4. Email Observed IPs Endpoint
    print(f"\n[4/8] Testing GET /emails/{analysis_id}/ips...")
    ips_resp = client.get(f"{API_BASE}/emails/{analysis_id}/ips", headers=headers, params={"workspace_id": workspace_id})
    assert ips_resp.status_code == 200, f"Failed to retrieve observed IPs: {ips_resp.text}"
    ips_data = ips_resp.json()
    print(f"  [OK] Analysis ID: {ips_data['analysis_id']}")
    print(f"  [OK] Total Observed IPs: {ips_data['total_ips_count']}, Public IPs: {ips_data['public_ips_count']}")
    
    for ip_item in ips_data["ips"]:
        print(f"    - IP: {ip_item['ip_address']} | Source: {ip_item['source']} | Private: {ip_item['is_private']} | Desc: {ip_item['description']}")

    # 5. Geolocation Lookup on Observed IP
    target_ip = None
    for ip_item in ips_data["ips"]:
        if not ip_item["is_private"]:
            target_ip = ip_item["ip_address"]
            break
    
    if not target_ip:
        target_ip = "185.220.101.5"

    print(f"\n[5/8] Tracing Target Observed IP: {target_ip} in /geo/locate...")
    geo_resp = client.post(f"{API_BASE}/geo/locate", headers=headers, json={"ip_address": target_ip})
    assert geo_resp.status_code == 200, f"Geolocation failed: {geo_resp.text}"
    geo_data = geo_resp.json()
    print(f"  [OK] Returned IP: {geo_data['ip_address']} (matches requested IP)")
    print(f"  [OK] Country: {geo_data.get('country')}, City: {geo_data.get('city')}")
    print(f"  [OK] ASN: {geo_data.get('asn')}, ISP: {geo_data.get('isp')}")
    print(f"  [OK] Routing Type: {geo_data.get('routing_type')}, Label: {geo_data.get('routing_label')}")
    print(f"  [OK] Provider: {geo_data.get('provider')}")
    assert geo_data["ip_address"] == target_ip, "Returned IP did not match requested IP!"
    assert geo_data["ip_address"] != "8.8.8.8" or target_ip == "8.8.8.8", "Unexpected 8.8.8.8 substitution!"

    # 6. Invalid IP Validation
    print("\n[6/8] Testing Invalid IP Rejection...")
    invalid_resp = client.post(f"{API_BASE}/geo/locate", headers=headers, json={"ip_address": "not-a-valid-ip"})
    assert invalid_resp.status_code in (400, 422), f"Expected 400/422 but got {invalid_resp.status_code}"
    print(f"  [OK] Invalid IP safely rejected with status {invalid_resp.status_code}.")

    # 7. Private IP Local Handling
    print("\n[7/8] Testing Private IP Local Handling (192.168.1.1)...")
    private_resp = client.post(f"{API_BASE}/geo/locate", headers=headers, json={"ip_address": "192.168.1.1"})
    assert private_resp.status_code == 200, f"Private IP resolution failed: {private_resp.text}"
    priv_data = private_resp.json()
    print(f"  [OK] Provider: {priv_data['provider']} | Routing: {priv_data.get('routing_label')}")
    assert priv_data["ip_address"] == "192.168.1.1"
    assert priv_data["routing_type"] == "INTERNAL_LAN"

    # 8. Cross-Workspace Tenant Boundary Isolation (BOLA)
    print("\n[8/8] Testing Tenant Isolation on Email Observed IPs...")
    fake_ws_id = str(uuid.uuid4())
    cross_resp = client.get(f"{API_BASE}/emails/{analysis_id}/ips", headers=headers, params={"workspace_id": fake_ws_id})
    assert cross_resp.status_code in (403, 404), f"Cross workspace expected 403/404 but got {cross_resp.status_code}"
    print(f"  [OK] Cross-workspace IP request rejected with status {cross_resp.status_code}.")

    print("\n========================================================")
    print(" ALL 8 LIVE E2E GEOLOCATION TESTS PASSED SUCCESSFULLY!")
    print("========================================================\n")

if __name__ == "__main__":
    run_e2e_tests()
