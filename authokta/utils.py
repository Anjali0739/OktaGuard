import requests
from django.conf import settings

class Auth0Client:
    def __init__(self):
        self.domain = settings.AUTH0_DOMAIN
        self.client_id = settings.AUTH0_CLIENT_ID
        self.client_secret = settings.AUTH0_CLIENT_SECRET
        self.audience = settings.AUTH0_AUDIENCE
        self.preloaded_token = getattr(settings, "AUTH0_MGMT_TOKEN", None)

    # Get Management API Token
    def get_token(self):
        if self.preloaded_token:
            print("Using AUTH0_MGMT_TOKEN from environment.")
            return self.preloaded_token
        
        url = f"{self.domain}/oauth/token"
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": self.audience,
            "grant_type": "client_credentials",
        }

        r = requests.post(url, json=payload)

        print("TOKEN STATUS:", r.status_code)
        print("TOKEN RESPONSE:", r.text)

        try:
            return r.json()["access_token"]
        except:
            return None

    # Fetch logs
    def get_logs(self, page=0, per_page=50):
        token = self.get_token()
        if not token:
            return {"error": "Failed to retrieve token"}

        url = f"{self.domain}/api/v2/logs"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        params = {"page": page, "per_page": per_page}

        response = requests.get(url, headers=headers, params=params)

        print("\n===== AUTH0 LOG RESPONSE =====")
        print("STATUS:", response.status_code)
        print("BODY:", response.text[:500])
        print("==============================\n")

        try:
            return response.json()
        except:
            return {
                "error": "Invalid JSON returned from Auth0",
                "status": response.status_code,
                "body": response.text,
            }