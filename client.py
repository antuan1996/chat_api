#!/usr/bin/env python
from flask import Flask, abort, request, jsonify, Response
import json
from uuid import uuid4
import requests
import requests.auth
from urllib.parse import urlencode as urlencode

CLIENT_ID = "dev" # Fill this in with your client ID
CLIENT_SECRET = "dev" # Fill this in with your client secret
REDIRECT_URI = "http://localhost:65010/callback"

USERNAME = "admin"
PASSWORD = "admin"

def base_headers(access_token=None):
    if access_token is not None:
        return {"Authorization": "bearer " + access_token}
    return {}
    #return {"User-Agent": user_agent()}

app = Flask(__name__)
@app.route('/')
def homepage():
    text = '<a href="%s">Authenticate me</a>'
    return text % make_authorization_url()


def make_authorization_url():
    # Generate a random string for the state parameter
    # Save it for use later to prevent xsrf attacks
    state = str(uuid4())
    save_created_state(state)
    params = {"client_id": CLIENT_ID,
              "response_type": "code",
              "state": state,
              "redirect_uri": REDIRECT_URI,
              "duration": "temporary",
              "scope": "email",
              "username": USERNAME,
              "password": PASSWORD
              }
    url = "http://127.0.0.1:5000/oauth/authorize?" + urlencode(params)
    return url


def save_created_state(state):
    pass
def is_valid_state(state):
    return True

@app.route('/callback')
def auth_callback():
    error = request.args.get('error', '')
    if error:
        return "Error: " + error
    state = request.args.get('state', '')
    if not is_valid_state(state):
        # Uh-oh, this request wasn't started by us!
        abort(403)
    code = request.args.get('code')
    print("got code", code)

    token = get_token(code)
    access_token = token["access_token"]

    send_message(access_token, "global", "Here I am")
    send_message(access_token, "global", "second attempt")


    create_room(access_token, "local")
    add_human(access_token, "local", "waiter")
    send_message(access_token, "local", "Api Test")
    send_message(access_token, "local", "Second attempt")
    messages = get_messages(access_token, "local")

    headers = base_headers(access_token)
    response = requests.get("http://127.0.0.1:5000/rooms", headers=headers)
    return response.text
    # return jsonify(signed_texts)

def get_token(code):
    client_auth = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    post_data = {"grant_type": "authorization_code",
                 "code": code,
                 "redirect_uri": REDIRECT_URI}
    headers = base_headers()
    response = requests.post("http://127.0.0.1:5000/oauth/token",
                             auth=client_auth,
                             headers=headers,
                             data=post_data)
    token_json = response.json()
    print("Got token", token_json)
    return token_json
    
    
def send_message(access_token, room_name, text):
    params={
        "text": text,
    }
    headers = base_headers(access_token)
    response = requests.post("http://127.0.0.1:5000/rooms/"+room_name+"/messages", headers=headers, params=params)
    print(response.text)

def get_messages(access_token, room_name):
    headers = base_headers(access_token)
    response = requests.get("http://127.0.0.1:5000/rooms/"+room_name+"/messages", headers=headers)
    print(response.json())
    return response.json()


def create_room(access_token, room_name):
    headers = base_headers(access_token)
    response = requests.post("http://127.0.0.1:5000/rooms", headers=headers,
                            params=dict(room_name=room_name))
    print(response.json())
    return response.json()


def delete_room(access_token, room_name):
    headers = base_headers(access_token)
    response = requests.delete("http://127.0.0.1:5000/rooms", headers=headers,
                            params=dict(room_name=room_name))
    print(response.json())
    return response.json()



def add_human(access_token, room_name, username):
    headers = base_headers(access_token)
    response = requests.post("http://127.0.0.1:5000/rooms/" + room_name + "/users", headers=headers,
                            params=dict(username=username))
    print(response.json())
    return response.json()


def delete_human(access_token, room_name, username):
    headers = base_headers(access_token)
    response = requests.delete("http://127.0.0.1:5000/rooms/" + room_name + "/users", headers=headers,
                            params=dict(username=username))
    print(response.json())
    return response.json()


if __name__ == '__main__':
    resp = requests.post("http://127.0.0.1:5000/users", params=dict(username="admin", password="admin"))
    resp = resp.json()

    CLIENT_ID = resp["client_id"]
    CLIENT_SECRET = resp["client_secret"]

    app.run(debug=True, port=65010)
