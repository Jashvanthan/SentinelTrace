import os
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.core.config import get_settings
from app.models.integrations import GmailConnection
from app.services.encryption_service import decrypt_token, encrypt_token

logger = logging.getLogger(__name__)

class GmailService:
    def __init__(self):
        self.settings = get_settings()
        self.scopes = self.settings.GMAIL_SCOPES.split(" ")

    def _get_flow(self, state: str | None = None) -> Flow:
        client_config = {
            "web": {
                "client_id": self.settings.GOOGLE_CLIENT_ID,
                "client_secret": self.settings.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        }
        flow = Flow.from_client_config(
            client_config,
            scopes=self.scopes,
            state=state,
        )
        flow.redirect_uri = self.settings.GMAIL_REDIRECT_URI
        return flow

    def get_authorization_url(self, state: str) -> tuple[str, str | None]:
        """Generate the authorization URL and PKCE code_verifier for Gmail."""
        flow = self._get_flow(state=state)
        auth_url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        return auth_url, flow.code_verifier

    async def exchange_code(self, code: str, code_verifier: str | None = None) -> dict:
        """Exchange the OAuth authorization code for credentials."""
        def _exchange():
            flow = self._get_flow()
            if code_verifier:
                flow.code_verifier = code_verifier
            flow.fetch_token(code=code)
            return flow.credentials

        creds = await asyncio.to_thread(_exchange)
        return {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes,
            "expiry": creds.expiry,
        }

    async def _get_credentials(self, db: AsyncSession, connection: GmailConnection) -> Credentials:
        """
        Reconstruct Credentials object from the database, decrypting tokens.
        If the token has expired, it attempts to refresh it and securely stores the new encrypted token.
        """
        if not connection.encrypted_access_token or not connection.encrypted_refresh_token:
            raise ValueError("GmailConnection is missing encrypted credentials")
            
        plain_access = decrypt_token(connection.encrypted_access_token)
        plain_refresh = decrypt_token(connection.encrypted_refresh_token)

        creds = Credentials(
            token=plain_access,
            refresh_token=plain_refresh,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=self.settings.GOOGLE_CLIENT_ID,
            client_secret=self.settings.GOOGLE_CLIENT_SECRET,
            scopes=connection.scopes,
            expiry=connection.token_expires_at.replace(tzinfo=None) if connection.token_expires_at else None
        )

        if creds.expired and creds.refresh_token:
            def _refresh():
                import google.auth.transport.requests
                request = google.auth.transport.requests.Request()
                creds.refresh(request)
            
            logger.info(f"Refreshing Gmail token for connection {connection.id}")
            try:
                await asyncio.to_thread(_refresh)
                # Encrypt and save new tokens
                connection.encrypted_access_token = encrypt_token(creds.token)
                if creds.refresh_token and creds.refresh_token != plain_refresh:
                    connection.encrypted_refresh_token = encrypt_token(creds.refresh_token)
                
                if creds.expiry:
                    connection.token_expires_at = creds.expiry.replace(tzinfo=timezone.utc)
                
                db.add(connection)
                await db.commit()
            except Exception as e:
                logger.error(f"Failed to refresh token: {e}")
                connection.status = "REVOKED"
                connection.revoked_at = datetime.now(timezone.utc)
                connection.error_message = str(e)
                db.add(connection)
                await db.commit()
                raise HTTPException(status_code=401, detail="Gmail authentication expired/revoked")

        return creds

    async def list_messages(self, db: AsyncSession, connection: GmailConnection, max_results: int = 100, page_token: str | None = None) -> dict[str, Any]:
        """Lists messages in the user's mailbox."""
        creds = await self._get_credentials(db, connection)
        
        def _list():
            service = build('gmail', 'v1', credentials=creds)
            return service.users().messages().list(userId='me', maxResults=max_results, pageToken=page_token).execute()
        
        try:
            return await asyncio.to_thread(_list)
        except HttpError as e:
            logger.error(f"Gmail API error (list_messages): {e}")
            raise
            
    async def get_message(self, db: AsyncSession, connection: GmailConnection, message_id: str) -> dict[str, Any]:
        """Gets a full message payload in the default format."""
        creds = await self._get_credentials(db, connection)
        
        def _get():
            service = build('gmail', 'v1', credentials=creds)
            return service.users().messages().get(userId='me', id=message_id).execute()
        
        try:
            return await asyncio.to_thread(_get)
        except HttpError as e:
            logger.error(f"Gmail API error (get_message): {e}")
            raise

    async def get_raw_message(self, db: AsyncSession, connection: GmailConnection, message_id: str) -> bytes:
        """Gets a message in raw MIME format."""
        import base64
        creds = await self._get_credentials(db, connection)
        
        def _get_raw():
            service = build('gmail', 'v1', credentials=creds)
            msg = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
            raw_data = msg['raw']
            return base64.urlsafe_b64decode(raw_data)
            
        try:
            return await asyncio.to_thread(_get_raw)
        except HttpError as e:
            logger.error(f"Gmail API error (get_raw_message): {e}")
            raise

    async def revoke_connection(self, db: AsyncSession, connection: GmailConnection) -> None:
        """Revokes the OAuth token from Google and updates the database."""
        creds = await self._get_credentials(db, connection)
        
        def _revoke():
            import requests
            requests.post('https://oauth2.googleapis.com/revoke',
                params={'token': creds.token},
                headers={'content-type': 'application/x-www-form-urlencoded'})
                
        try:
            await asyncio.to_thread(_revoke)
        except Exception as e:
            logger.warning(f"Google revoke API call failed: {e}")
            
        connection.status = "REVOKED"
        connection.revoked_at = datetime.now(timezone.utc)
        connection.encrypted_access_token = None
        connection.encrypted_refresh_token = None
        db.add(connection)
        await db.commit()

gmail_service = GmailService()
