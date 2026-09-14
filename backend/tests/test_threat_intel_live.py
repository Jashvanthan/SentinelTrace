import httpx

def test_threat_intel():
    client = httpx.Client(base_url="http://localhost:8000/api/v1", timeout=30.0)
    login = client.post("/auth/login", json={"email": "qa_tester@sentineltrace.io", "password": "SentinelQAPass123!"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test live lookup
    enrich = client.post("/intel/enrich", json={"indicator": "8.8.8.8", "indicator_type": "ip"}, headers=headers)
    print(f"1. Enrich 8.8.8.8: Status = {enrich.status_code}")
    print(f"   Result: {enrich.json()}")

    # 2. Test Geolocation
    geo = client.post("/geo/locate", json={"ip_address": "8.8.8.8"}, headers=headers)
    print(f"2. Geo 8.8.8.8: Status = {geo.status_code}")
    print(f"   Country: {geo.json().get('country')}, City: {geo.json().get('city')}")

    # 3. Test IOCs list
    ws_res = client.get("/workspaces", headers=headers)
    ws_id = ws_res.json()[0]["id"]
    iocs = client.get(f"/intel/iocs?workspace_id={ws_id}", headers=headers)
    print(f"3. Workspace IOCs List: Status = {iocs.status_code}")
    print(f"   Total IOCs in DB: {iocs.json().get('total')}")

if __name__ == "__main__":
    test_threat_intel()
