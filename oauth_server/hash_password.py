import sys
from app.user_management import hash_new_password

if len(sys.argv) < 1:
    print( "Usage: hash_password.py <password>" )
    sys.exit(1)

(salt, password_hash) = hash_new_password(sys.argv[1])
print( "Salt: " + salt )
print( "Password hash: " + password_hash )