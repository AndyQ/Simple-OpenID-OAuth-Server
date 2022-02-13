#!/bin/bash

# Initial setup script for the project

# Create instance folders
mkdir oauth_server/instance
mkdir client/instance
mkdir resource_server/instance

# Generate RSA Private key
openssl genrsa -out oauth_server/instance/private.pem 2048

# Generate Public key
openssl rsa -in oauth_server/instance/private.pem -pubout -outform PEM -out oauth_server/instance/public.pem

# copy public key to client and resource server
cp oauth_server/instance/public.pem client/instance/public.pem
cp oauth_server/instance/public.pem resource_server/instance/public.pem