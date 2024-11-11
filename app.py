# app.py
from flask import Flask, session, abort, redirect, request, url_for
from google_auth_oauthlib.flow import Flow
import os
import pathlib
import requests
import google.auth.transport.requests
from google.oauth2 import id_token
import cachecontrol
from functools import wraps  # Import wraps

app = Flask("Google Login App")
app.secret_key = "CodeSpecialList.com"
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

Google_client_id = "222550221933-ft2hqpuiq4c0d6mrqu5nr8qmbuvntrrf.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

def login_is_required(function):
    @wraps(function)  # Preserves original function name
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            abort(401)
        else:
            return function(*args, **kwargs)
    return wrapper

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    if not session["state"] == request.args["state"]:
        abort(500)

    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    request_session = requests.Session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,
        request=token_request,
        audience=Google_client_id
    )

    session["google_id"] = id_info.get("sub")
    session["user_info"] = id_info

    return redirect(url_for("protected_area"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
def index():
    return "Hello world <a href='/login'><button>login</button></a>"

@app.route("/protected_area")
@login_is_required
def protected_area():
    user_info = session.get("user_info", {})
    return f"Protected area. Hello, {user_info.get('name')}! , sd{user_info} "

if __name__ == "__main__":
    app.run(debug=True)
