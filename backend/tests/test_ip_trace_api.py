"""
SentinelTrace Backend — Full API Integration Tests for IP Trace & Map
"""
import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from httpx import ASGITransport, AsyncClient
from app.main import create_app
from app.services.auth_service import create_access_token


async def run_api_tests():
    app = create_app()

    from app.db.session import AsyncSessionLocal
    from app.models.user import User
    from app.models.workspace import WorkspaceMember
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        user = await db.scalar(select(User).limit(1))
        if not user:
            user = User(
                id=uuid.uuid4(),
                email="analyst@sentineltrace.io",
                full_name="Forensic Analyst",
                role="ANALYST",
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

        member = await db.scalar(select(WorkspaceMember).where(WorkspaceMember.user_id == user.id))
        workspace_id = member.workspace_id if member else uuid.uuid4()

    token = create_access_token(subject=str(user.id), email=user.email, role=str(user.role))
    headers = {"Authorization": f"Bearer {token}"}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        print("\n--- 1. Testing Single IP Trace Endpoint ---")

        # Test Public IP
        pub_resp = await client.post(
            "/api/v1/ip-trace/trace",
            json={"ip": "8.8.8.8", "workspace_id": str(workspace_id)},
            headers=headers,
        )
        assert pub_resp.status_code == 200, f"Public trace failed: {pub_resp.text}"
        pub_data = pub_resp.json()
        assert pub_data["classification"] == "PUBLIC"
        assert pub_data["is_public"] is True
        assert pub_data["is_geolocatable"] is True
        assert pub_data["location_accuracy"] == "approximate"
        print(f"  [PASS] Public IP Trace (8.8.8.8) -> {pub_data['classification']} ({pub_data['routing_role']})")

        # Test Private LAN IP
        priv_resp = await client.post(
            "/api/v1/ip-trace/trace",
            json={"ip": "192.168.1.45", "workspace_id": str(workspace_id)},
            headers=headers,
        )
        assert priv_resp.status_code == 200, f"Private trace failed: {priv_resp.text}"
        priv_data = priv_resp.json()
        assert priv_data["classification"] == "PRIVATE"
        assert priv_data["is_public"] is False
        assert priv_data["is_geolocatable"] is False
        assert priv_data["internal_network"]["location_confidence"] == "UNKNOWN"
        print(f"  [PASS] Private IP Trace (192.168.1.45) -> {priv_data['classification']} (Zero-fabrication status: {priv_data['status']})")

        # Test Loopback
        loop_resp = await client.post(
            "/api/v1/ip-trace/trace",
            json={"ip": "127.0.0.1", "workspace_id": str(workspace_id)},
            headers=headers,
        )
        assert loop_resp.status_code == 200
        loop_data = loop_resp.json()
        assert loop_data["classification"] == "LOOPBACK"
        print(f"  [PASS] Loopback Trace (127.0.0.1) -> {loop_data['classification']}")

        # Test IPv6 Unique Local
        ula_resp = await client.post(
            "/api/v1/ip-trace/trace",
            json={"ip": "fc00::1", "workspace_id": str(workspace_id)},
            headers=headers,
        )
        assert ula_resp.status_code == 200
        ula_data = ula_resp.json()
        assert ula_data["classification"] == "UNIQUE_LOCAL"
        print(f"  [PASS] IPv6 ULA Trace (fc00::1) -> {ula_data['classification']}")

        # Test Link-Local APIPA
        link_resp = await client.post(
            "/api/v1/ip-trace/trace",
            json={"ip": "169.254.10.20", "workspace_id": str(workspace_id)},
            headers=headers,
        )
        assert link_resp.status_code == 200
        link_data = link_resp.json()
        assert link_data["classification"] == "LINK_LOCAL"
        print(f"  [PASS] Link-Local Trace (169.254.10.20) -> {link_data['classification']}")

    print("\n=======================================================")
    print("ALL API ENDPOINT INTEGRATION TESTS PASSED (100% SUCCESS)!")
    print("=======================================================\n")


if __name__ == "__main__":
    asyncio.run(run_api_tests())
