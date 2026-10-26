import pytest
from app.services.gmail_service import gmail_service

def test_get_authorization_url():
    url, verifier = gmail_service.get_authorization_url(state="test_state")
    assert ("https://accounts.google.com/o/oauth2/v2/auth" in url or "https://accounts.google.com/o/oauth2/auth" in url)
    assert "state=test_state" in url
    assert verifier is None or isinstance(verifier, str)

