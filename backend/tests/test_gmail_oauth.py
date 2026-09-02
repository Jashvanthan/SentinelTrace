import pytest
from app.services.gmail_service import gmail_service

def test_get_authorization_url():
    url = gmail_service.get_authorization_url(state="test_state")
    assert "https://accounts.google.com/o/oauth2/auth" in url
    assert "state=test_state" in url
    assert "access_type=offline" in url
