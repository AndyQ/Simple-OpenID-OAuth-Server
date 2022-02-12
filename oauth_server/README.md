# Test OAuth Server

A very simple test OAuth server

## Initial Setup

Note - it is assumed that you are using Python 3.8 (tested with Python 3.8.12).

The instance folder contains:
- a public and private RSA key pair that is used to sign the JWT tokens used when OpenID is specificied as a scope (see later).
- A data folder containing a list of user details (users.json) and a list of registered applications (apps.json).

Note - the public.pem file will need to be included in each Resource server that you deploy in order to verify the JWT tokens

### Public/Private Keys
You can use the default public/private keys quite happily, however if you wish to generate a new set then you can using the following:<br>
1. Generate private key<br>
`openssl genrsa -out private.pem 2048`
2. Create public key<br>
`openssl rsa -in private.pem -pubout -outform PEM -out public.pem`


### Data files
These data files can be configured to as necessary.<br>
**By default, the users passwords are ALL set as "password".**

You can use the `hashPassword.py` script to get a hashed password and the salt used.<br>
`python hash_password.py <password>`

Then create a python virtual environment (strongly recommended) and upgrade PIP:<br>
`python -m venv venv ; cd . ; pip install --upgrade pip`

Then install the dependancies<br>
`pip install -r requirements.txt`

## Running
To start the server running, simply run:
`python run.py`

This will start the server running on Port 8001


