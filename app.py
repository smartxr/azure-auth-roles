from flask import Flask, render_template, session, request, redirect, url_for
from msal import ConfidentialClientApplication
import requests
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Azure AD configuration
CLIENT_ID = '653834f9-16e7-4e41-8839-529e903f1911'
CLIENT_SECRET = 'UDB8Q~SWM_4oIXkLdWjz_n0vSTirAcngZsIwBbog'
AUTHORITY = 'https://login.microsoftonline.com/04c24e67-e995-4780-8c97-288bab5f8eee'
SCOPE = ["openid", "profile", "User.Read"]

# Routes
@app.route('/')
def home():
    if 'user' in session and 'token' in session:
        user = session['user']
        token = session['token']
        return render_template('index.html', user=user, token=token)
    else:
        return redirect(url_for('login'))

@app.route('/login')
def login():
    redirect_uri = url_for('authorized', _external=True)
    auth_url = _build_auth_url(authority=AUTHORITY, client_id=CLIENT_ID, redirect_uri=redirect_uri, scope=SCOPE)
    return redirect(auth_url)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/get_token')
def authorized():
    token = _get_token_from_code(request.args['code'], url_for('authorized', _external=True))
    session['token'] = token
    session['user'] = _get_user_info(token)
    return redirect(url_for('home'))

# Helper functions
def _build_auth_url(authority, client_id, redirect_uri, scope):
    return f"{authority}/oauth2/v2.0/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope={' '.join(scope)}&response_type=code"

def _get_token_from_code(code, redirect_uri):
    app = ConfidentialClientApplication(
        CLIENT_ID, authority=AUTHORITY,
        client_credential=CLIENT_SECRET,
    )
    token_response = app.acquire_token_by_authorization_code(code, redirect_uri, SCOPE)
    return token_response['access_token']

def _get_user_info(token):
    graph_api_endpoint = 'https://graph.microsoft.com/v1.0/me'
    headers = {'Authorization': 'Bearer ' + token}
    response = requests.get(graph_api_endpoint, headers=headers)
    user_info = response.json()
    return user_info

if __name__ == '__main__':
    app.run(debug=True)
