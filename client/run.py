#!/usr/bin/env python
from app import app

app.secret_key = 'super secret client app key'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['ENV'] = 'development'
app.config['DEBUG'] = True

app.run(host="0.0.0.0", port=8000)
