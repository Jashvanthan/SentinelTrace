import httpx
import json

client = httpx.Client(base_url="http://localhost:8000/api/v1")

# 1. Login
res = client.post("/auth/login", json={"email": "qa_tester@sentineltrace.io", "password": "SentinelQAPass123!"})
print("Login status:", res.status_code)
auth_data = res.json()
token = auth_data["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# 2. Workspaces
ws_res = client.get("/workspaces", headers=headers)
print("Workspaces status:", ws_res.status_code, ws_res.json())
workspaces = ws_res.json()
workspace_id = workspaces[0]["id"] if workspaces else None

# 3. Test /intel/iocs with workspace_id
ioc_res1 = client.get(f"/intel/iocs?workspace_id={workspace_id}", headers=headers)
print("GET /intel/iocs with ws_id status:", ioc_res1.status_code, ioc_res1.text[:200])

# 4. Test /intel/iocs WITHOUT workspace_id
ioc_res2 = client.get("/intel/iocs", headers=headers)
print("GET /intel/iocs without ws_id status:", ioc_res2.status_code, ioc_res2.text[:200])

# 5. Test /intel/enrich (IP)
enrich_res = client.post("/intel/enrich", headers=headers, json={"indicator": "8.8.8.8", "indicator_type": "ip"})
print("POST /intel/enrich status:", enrich_res.status_code, enrich_res.text[:200])

# 6. Test /geo/locate (IP)
geo_res = client.post("/geo/locate", headers=headers, json={"ip_address": "8.8.8.8"})
print("POST /geo/locate status:", geo_res.status_code, geo_res.text[:200])

# 7. Test /workspaces/{id}/stats
if workspace_id:
    stats_res = client.get(f"/workspaces/{workspace_id}/stats", headers=headers)
    print("GET /workspaces/{id}/stats status:", stats_res.status_code, stats_res.text[:200])
