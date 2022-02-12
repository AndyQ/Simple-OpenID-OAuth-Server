# Test Resource Server

A very simple test Resource Server for the OAuth Server

It recieves a request from the client server which MUST contain an access token received from the OAuth Server.

This token is then verified with the OAuth server, and access roles retrieved.

If the users role is either Admin or Developer, then the sample service is allowed to be called.  If the role is User role, then the call is rejected.

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

This will start the server running on Port 8002


