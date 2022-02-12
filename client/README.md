# Test Client

A very simple test Client for the OAuth Server

It uses the OAuth server to logon and request openid id_token, and an access/refresh token.

The id_token contains details on the user and the access token can be used to make requests to the Resource Server

## Initial Setup

Note - it is assumed that you are using Python 3.8 (tested with Python 3.8.12).

The instance folder contains:
- a public key that is used to verify the openid JWT token. This MUST be the same public key as used by the OAuth Server!

Then create a python virtual environment (strongly recommended) and upgrade PIP:<br>
`python -m venv venv ; cd . ; pip install --upgrade pip`

Then install the dependancies<br>
`pip install -r requirements.txt`

## Running
To start the server running, simply run:
`python run.py`

This will start the server running on Port 8000


