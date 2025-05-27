#!/usr/bin/env python
from app import app

app.secret_key = 'super secret client app key'

app.run(host="0.0.0.0", port=8000)
