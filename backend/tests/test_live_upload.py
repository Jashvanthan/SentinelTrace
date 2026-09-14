import httpx
import time

def test_live_upload():
    client = httpx.Client(base_url='http://localhost:8000/api/v1', timeout=30.0)
    res = client.post('/auth/login', json={'email': 'qa_tester@sentineltrace.io', 'password': 'SentinelQAPass123!'})
    token = res.json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    ws_res = client.get('/workspaces', headers=headers)
    ws_id = ws_res.json()[0]['id']

    eml = b"""From: alerts@sentineltrace-test.org
To: user@org.com
Subject: Standard Enterprise Notification
Date: Thu, 10 Sep 2026 10:00:00 +0000
Content-Type: text/plain

Please review the latest system updates.
"""
    up = client.post(
        f'/emails/upload?workspace_id={ws_id}',
        headers=headers,
        files={'file': ('notice.eml', eml, 'message/rfc822')}
    )
    print('Uploaded:', up.json())
    a_id = up.json()['analysis_id']

    for i in range(10):
        time.sleep(1)
        det = client.get(f'/emails/{a_id}?workspace_id={ws_id}', headers=headers).json()
        print(f'Check #{i+1}: {det.get("status")}')
        if det.get('status') == 'COMPLETE':
            print('DONE! Severity:', det.get('severity'), 'Threat:', det.get('threat_category'))
            break

if __name__ == '__main__':
    test_live_upload()
