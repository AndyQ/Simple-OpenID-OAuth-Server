#!/usr/bin/env python
from app import app

app.secret_key = 'super secret key'
app.run(host="0.0.0.0", port=8001)
