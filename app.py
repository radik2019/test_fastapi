from typing import List, Optional, Dict
from fastapi import FastAPI, HTTPException, Header, Depends, Security
from fastapi.security import HTTPBearer, APIKeyHeader, HTTPBasic, HTTPBasicCredentials,  HTTPAuthorizationCredentials
from schemas import Appliances, Person, Room, House, Street, Municipality, AuthDetails
import jwt
from odmantic import AIOEngine, Model, ObjectId, Reference
from pydantic import BaseModel
import stat
from fastapi import FastAPI, Depends, HTTPException
from auth import AuthHandler, check_api_key, api_key_from_header
from settings import engine, client, dbg
from starlette.requests import Request
from fastapi_jwt_auth import AuthJWT
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

app = FastAPI()


auth_handler = AuthHandler()
users = []


@app.get("/api/test")
def test_call(
    req: Request, 
    auth: str = Header(None, alias="Authorization")):
    dbg(dir(jwt))
    dbg(jwt.get_unverified_header)
    return req.method


@app.post('/api/register', status_code=201)
async def register(auth_details: AuthDetails):
    inst = await engine.find_one(AuthDetails, AuthDetails.username == auth_details.username)
    if inst:
        raise HTTPException(status_code=400, detail='Chosen username is not available')
    hashed_password = auth_handler.get_password_hash(auth_details.password)
    data = AuthDetails(**{
        'username': auth_details.username,
        'password': hashed_password    
    })
    await engine.save(data)
    return {"detail": "registered"}


@app.post('/api/login')
async def login(auth_details: AuthDetails):

    q = () if not auth_details else AuthDetails.username == auth_details.username
    collection = await engine.find(AuthDetails, q)
    user = None
    for user_ in collection:
        if user_.username == auth_details.username:
            user = user_
            break
    if (user is None) or (not auth_handler.verify_password(auth_details.password, user.password)):
        raise HTTPException(status_code=401, detail='Invalid username and/or password')
    token = auth_handler.encode_token(user.username)
    return { 'token': token }


@app.post("/api/municipalities", response_model=Municipality)
async def create_municipality(data: Municipality):
    inst = await engine.save(data)
    return inst

##############################################################################
#                                                                            #
##############################################################################




@app.get("/api/municipalities", response_model=List[Municipality])
async def list_municipality(from_value: Optional[str] = None,
                            username=Depends(auth_handler.auth_wrapper),
                            Authorize: AuthJWT = Depends(),
                            auth: str = Header(None, alias="Authorization")
                            ):
    # @app.get("/api/test")
    # def test_call(
    #     req: Request, 
    #     auth: str = Header(None, alias="Authorization")):
    #     dbg(dir(jwt))
    #     dbg(jwt.get_unverified_header)
    #     return req.method
    dbg(auth)
    q = () if not from_value else Municipality.city_name == from_value

    collection = await engine.find(Municipality, q)
    # dbg(auth_handler.update_token(username))
    return collection

@app.get("/api/municipalities/{municipality_id}", response_model=Municipality)
async def fetch_municipality(municipality_id: str):

    inst = await engine.find_one(Municipality, Municipality.id == ObjectId(municipality_id))
    if not inst: raise HTTPException(detail="Municipality not found", status_code=404)
    return inst

@app.delete("/api/municipalities/{municipality_id}", response_model=dict)
async def delete_municipality(municipality_id: str, api_key: str = api_key_from_header()):
    check_api_key(api_key ,API_KEY)
    inst = await engine.find_one(Municipality, Municipality.id == ObjectId(municipality_id))
    if not inst: raise HTTPException(detail="Municipality not found", status_code=404)
    await engine.delete(inst)
    return {"detail": "deleted"}


@app.get("/api/houses", response_model=List[House])
async def list_house(from_value: Optional[str] = None):
    q = () if not from_value else House.city_name == from_value
    print(q)
    collection = await engine.find(House, q)
    return collection

@app.post("/api/houses", response_model=House)
async def create_home(data: House):

    inst = await engine.save(data)
    return inst


@app.delete("/api/houses/{house_id}", response_model=dict)
async def delete_house(house_id: str, api_key: str = api_key_from_header()):
    
    check_api_key(api_key ,API_KEY)
    inst = await engine.find_one(House, House.id == ObjectId(house_id))
    if not inst: raise HTTPException(detail="House not found", status_code=404)
    await engine.delete(inst)
    return {"detail": "deleted"}


@app.put("/api/houses/{house_id}", response_model=House)
async def fetch_house(data: House ,house_id: str):

    inst = await engine.find_one(House, House.id == ObjectId(house_id))
    if not inst: raise HTTPException(detail="Municipality not found", status_code=404)
    print(inst.dict())
    return inst










