
from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBasicCredentials
import jwt
from fastapi import HTTPException, Security, HTTPException, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from odmantic import ObjectId
from passlib.context import CryptContext
from datetime import datetime, timedelta
from settings import SESSION_EXP_MIN, SESSION_EXP_SEC, SESSION_EXP_DAYS, \
                REFRESHED_EXP_MIN, REFRESHED_EXP_SEC, REFRESHED_EXP_DAYS, dbg, engine
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel
from schemas import AuthDetails, AuthToken


class Settings(BaseModel):
    authjwt_secret_key: str = "secret"

@AuthJWT.load_config
def get_config():
    return Settings()

def api_key_from_header():
    return Header(None, alias="X-API-Key")

def check_api_key(api_key ,inner_api_key):
    if api_key != inner_api_key: raise HTTPException(detail="Permission denied", status_code=403)
    
class AuthHandler():
    security = HTTPBearer()
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret = 'SECRET_token'

    def get_password_hash(self, password):
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)

    def encode_token(self, user_id):
        payload = {
            'exp': datetime.utcnow() + timedelta( days=SESSION_EXP_DAYS, minutes=SESSION_EXP_MIN, seconds=SESSION_EXP_SEC),
            # 'ref': datetime.utcnow() + timedelta( days=REFRESHED_EXP_DAYS, minutes=REFRESHED_EXP_MIN, seconds=REFRESHED_EXP_SEC),
            'iat': datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256'
        )

    def encode_refresh_token(self, user_id):
        payload = {
            'exp': datetime.utcnow() + timedelta( days=REFRESHED_EXP_DAYS, minutes=REFRESHED_EXP_MIN, seconds=REFRESHED_EXP_SEC),
            'iat': datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256'
        )


    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            # {'exp': 1647268595, 'iat': 1647268415, 'sub': 'username'}
            # dbg(payload)
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Signature has expired')
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail='Invalid token')

    async def auth_wrapper(self, auth: HTTPAuthorizationCredentials = Security(security)):
        # scheme='Bearer' credentials='eyJ0eXAiOiJKV1QqTWrFZt0gW5RT4'
       
        clnt = await engine.find_one(AuthDetails, AuthDetails.username == self.decode_token(auth.credentials))
        clnt_token = await engine.find_one(AuthToken, AuthToken.id == clnt.id)
        dbg(clnt_token)
        dbg( self.decode_token(auth.credentials))
        # auth.credentials = clnt_token.refresh_token
        return self.decode_token(auth.credentials)








