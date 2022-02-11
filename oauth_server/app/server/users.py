from app import app
from app import user_management

def get_user_details( user_id ):
    return user_management.get_user_details( user_id )

def authenticate_user_credentials(user_id, password):
    user = user_management.get_user_details( user_id )
    if user is None:
        return False
    
    if user_management.is_correct_password( user["password_salt"], user["password_hash"], password ):
        return True

    return False



if __name__ == "__main__":
    print( "This is a module for use with oauth_server.py" )