import os
from pathlib import Path
from app.services.email_service import parse_eml

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "emails"

def test_parse_benign_email():
    eml_path = FIXTURES_DIR / "benign.eml"
    with open(eml_path, "rb") as f:
        email_content = f.read()
        parsed = parse_eml(email_content)
        
    assert parsed.subject == "Weekly System Update"
    assert parsed.sender_email == "admin@example.com"
    assert parsed.sender_display_name == "Admin"
    assert "user@sentineltrace.local" in parsed.recipients
    assert parsed.message_id == "<1234567890.example.com@mail.example.com>"
    
    # Auth results
    assert parsed.spf_result == "pass"
    assert parsed.dkim_result == "pass"
    assert parsed.dmarc_result == "pass"
    
    # Body
    assert parsed.body_text and "This is a benign test email." in parsed.body_text

def test_parse_spf_fail_email():
    eml_path = FIXTURES_DIR / "spf_fail.eml"
    with open(eml_path, "rb") as f:
        email_content = f.read()
        parsed = parse_eml(email_content)
        
    assert parsed.subject == "URGENT: Your account has been compromised!"
    assert parsed.sender_email == "attacker@evil.com"
    assert parsed.reply_to == "support-fake@evil.com"
    
    # Auth results
    assert parsed.spf_result == "fail"
    assert parsed.dkim_result == "neutral"
    assert parsed.dmarc_result == "fail"
    
    # IOCs / URLs
    assert any("malicious-phishing.com" in url for url in parsed.extracted_urls)
