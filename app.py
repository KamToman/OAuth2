from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from msal import ConfidentialClientApplication
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TENANT_ID = os.getenv("TENANT_ID")
REDIRECT_URI = os.getenv("REDIRECT_URI")
AUTHORITY = f"https://login.microsoftonline.com/92490e38-49cf-409e-97cc-9de5194809ba"
SCOPES = ["User.Read", "api://{CLIENT_ID}/access_as_user"]

# Konfiguracja MSAL
msal_app = ConfidentialClientApplication(
    CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET
)

# Zabezpieczenie dostępu do tokenu
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Funkcja sprawdzająca role użytkownika
def check_user_role(token: dict, required_role: str):
    roles = token.get("roles", [])
    if required_role not in roles:
        raise HTTPException(status_code=403, detail="Access forbidden")

@app.get("/")
async def root():
    return {"message": "Welcome to OAuth2 secured app!"}

@app.get("/login")
async def login():
    auth_url = msal_app.get_authorization_request_url(SCOPES, redirect_uri=REDIRECT_URI)
    return RedirectResponse(auth_url)

@app.get("/callback")
async def callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Code not found in callback request")

    token_response = msal_app.acquire_token_by_authorization_code(
        code, scopes=SCOPES, redirect_uri=REDIRECT_URI
    )

    if "error" in token_response:
        raise HTTPException(status_code=400, detail=token_response["error_description"])

    return {"access_token": token_response["access_token"], "id_token": token_response.get("id_token", None)}

@app.get("/admin")
async def admin(access_token: str = Depends(oauth2_scheme)):
    token = msal_app.acquire_token_silent(SCOPES, account=None)
    if not token or "access_token" not in token:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    check_user_role(token, "Admin")
    return {"message": "Welcome Admin!"}

@app.get("/user")
async def user(access_token: str = Depends(oauth2_scheme)):
    token = msal_app.acquire_token_silent(SCOPES, account=None)
    if not token or "access_token" not in token:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    check_user_role(token, "User")
    return {"message": "Welcome User!"}
