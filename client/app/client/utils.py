import jwt

with open('../public.pem', 'rb') as f:
  public_key = f.read()
ISSUER = 'sample-auth-server'
AUDIENCE = "sample-client-id"

def extractJWT( token ):
    data = {}

    claims = jwt.decode(token, public_key,
                            issuer = ISSUER,
                            audience = AUDIENCE,
                            algorithms = ['RS256'])

    header = jwt.get_unverified_header(token)

    return ( header, claims )
    # print( decoded_token )
    # claims = jwt.get_unverified_header(token)
    print( claims )
    firstName = claims["given_name"]
    lastName = claims["family_name"]
    roles = claims["iairgroup.roles"]
    validRoles = "#".join([role[9:] for role in roles if role.startswith( "IAGStore." )])

    data["userId"] = claims["sub"]
    data["role"] = validRoles
    data["firstName"] = firstName
    data["lastName"] = lastName

    print( f"claims - {claims}" )
    print( f"Valid roles - {validRoles}" )
    print( f"roles - {roles}" )
    return claims