from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from msal import ConfidentialClientApplication
import os

app = FastAPI()

# Fetch environment variables directly from Azure
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TENANT_ID = os.getenv("TENANT_ID")
REDIRECT_URI = os.getenv("REDIRECT_URI")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["User.Read", f"api://{CLIENT_ID}/access_as_user"]

# Ensure the environment variables are set
if not all([CLIENT_ID, CLIENT_SECRET, TENANT_ID, REDIRECT_URI]):
    raise ValueError("One or more environment variables are missing. Please check your Azure configuration.")

# Configure MSAL
msal_app = ConfidentialClientApplication(
    CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET
)

# OAuth2 token bearer security
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

@app.get("/logout")
async def logout():
    # Redirect user to the login page to log in again
    return RedirectResponse(url="/login")

@app.get("/login")
async def login():
    # Generate the authorization URL
    auth_url = msal_app.get_authorization_request_url(SCOPES, redirect_uri=REDIRECT_URI)
    return RedirectResponse(auth_url)

@app.get("/callback")
async def callback(request: Request):
    # Extract the authorization code from the callback
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Code not found in callback request")

    # Exchange the authorization code for an access token
    token_response = msal_app.acquire_token_by_authorization_code(
        code, scopes=SCOPES, redirect_uri=REDIRECT_URI
    )

    if "error" in token_response:
        raise HTTPException(status_code=400, detail=token_response["error_description"])

    # Store the access token (this could be in the session, database, or JWT)
    access_token = token_response["access_token"]
    return {"access_token": access_token}
