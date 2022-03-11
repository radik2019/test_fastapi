
from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBasicCredentials
import jwt
from fastapi import HTTPException, Security, HTTPException, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
from settings import SESSION_EXP_MIN, SESSION_EXP_SEC, SESSION_EXP_DAYS
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel


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
    secret = 'SECRET'

    def get_password_hash(self, password):
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)

    def encode_token(self, user_id):
        payload = {
            'exp': datetime.utcnow() + timedelta(
                days=SESSION_EXP_DAYS, minutes=SESSION_EXP_MIN, seconds=SESSION_EXP_SEC
                ),
            'iat': datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256'
        )
    
    def update_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Signature has expired')
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail='Invalid token')
        payload = {
            'exp': datetime.utcnow() + timedelta(
                days=SESSION_EXP_DAYS, minutes=SESSION_EXP_MIN, seconds=SESSION_EXP_SEC
                ),
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
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Signature has expired')
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail='Invalid token')

    def auth_wrapper(self, auth: HTTPAuthorizationCredentials = Security(security)):
        return self.decode_token(auth.credentials)








