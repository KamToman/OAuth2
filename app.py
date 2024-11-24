from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
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

# Function to check user roles
def check_user_role(token: dict, required_role: str):
    roles = token.get("roles", [])
    if required_role not in roles:
        raise HTTPException(status_code=403, detail="Access forbidden")

@app.get("/")
async def root():
    return {"message": "Welcome to OAuth2 secured app!"}

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

    return {"access_token": token_response["access_token"], "id_token": token_response.get("id_token", None)}

@app.get("/admin")
async def admin(access_token: str = Depends(oauth2_scheme)):
    # Use MSAL to acquire the token silently
    token = msal_app.acquire_token_silent(SCOPES, account=None)
    if not token or "access_token" not in token:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # Decode the token to check for roles
    decoded_token = msal_app._deserialize_token(token['access_token'])
    check_user_role(decoded_token, "Admin")
    
    return {"message": "Welcome Admin!"}

@app.get("/user")
async def user(access_token: str = Depends(oauth2_scheme)):
    # Use MSAL to acquire the token silently
    token = msal_app.acquire_token_silent(SCOPES, account=None)
    if not token or "access_token" not in token:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # Decode the token to check for roles
    decoded_token = msal_app._deserialize_token(token['access_token'])
    check_user_role(decoded_token, "User")
    
    return {"message": "Welcome User!"}

@app.get("/logout")
async def logout(request: Request):
    # Clear the token from the session (or headers if using a different method)
    request.session.clear()  # if you are using session management, else remove the token from headers

    # Redirect to the login page for re-authentication
    return RedirectResponse(url="/login")
