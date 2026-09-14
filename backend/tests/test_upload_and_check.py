import asyncio
import httpx

async def main():
    async with httpx.AsyncClient() as client:
        # 1. Login
        r = await client.post('http://localhost:8000/api/v1/auth/login', json={'email': 'qa_tester@sentineltrace.io', 'password': 'SentinelQAPass123!'})
        print('Login:', r.status_code)
        token = r.json().get('access_token')

        # 2. Get Workspaces
        r_ws = await client.get('http://localhost:8000/api/v1/workspaces', headers={'Authorization': f'Bearer {token}'})
        print('Workspaces:', r_ws.status_code, r_ws.json())
        ws_id = r_ws.json()[0]['id']

        # 3. Upload raw .eml
        eml_content = b'''From: attacker@evil-corp.com
To: victim@company.com
Subject: Urgent: Verify your payroll account
Date: Thu, 10 Sep 2026 10:00:00 +0000
Content-Type: text/plain

Please click here to verify: http://phishing-site.xyz/login
'''
        files = {'file': ('phishing_test.eml', eml_content, 'message/rfc822')}
        data = {'notes': 'Test upload from script', 'priority': 'NORMAL'}

        r_up = await client.post(
            f'http://localhost:8000/api/v1/emails/upload?workspace_id={ws_id}',
            headers={'Authorization': f'Bearer {token}'},
            files=files,
            data=data
        )
        print('Upload status:', r_up.status_code, r_up.json())
        analysis_id = r_up.json().get('analysis_id')

        # 4. Poll analysis status
        for _ in range(15):
            await asyncio.sleep(1)
            r_detail = await client.get(
                f'http://localhost:8000/api/v1/emails/{analysis_id}?workspace_id={ws_id}',
                headers={'Authorization': f'Bearer {token}'}
            )
            data = r_detail.json()
            print(f"Polling analysis status: {data.get('status')} | severity: {data.get('severity_level')} | threat: {data.get('threat_category')}")
            if data.get('status') in ['COMPLETE', 'FAILED']:
                break

if __name__ == '__main__':
    asyncio.run(main())
