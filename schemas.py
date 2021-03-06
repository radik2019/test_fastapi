from typing import List, Optional, Dict
from pydantic import Field
from odmantic import AIOEngine, Model, ObjectId, Reference,EmbeddedModel
from odmantic.field import Field

# *****************************************************

class AuthDetails(Model):
    username: str
    password: str

class AuthToken(Model):
    access_token: str
    refresh_token: str
    user :AuthDetails = Reference()
    
# ********************************************************

class User(Model):
    username: str
    password: str
    token: Optional[str]
    class Config:
        collection = "users"

class Municipality(Model):
    city_name: str = Field(..., max_length=15, )
    population: int
    zip_cod: str = Field(..., regex=r'\d{5}')
    class Config:
        collection = "municipality"

class Room(EmbeddedModel):
    name: str
    class Config:
        collection = "rooms"

class Street(Model):
    name: str   
    municipality: Municipality = Reference()
    class Config:
        collection = "streets"

class House(Model):
    street_number: int
    rooms:  List[Room] = [Room(name='stanza')]
    street: Street = Reference()
    class Config:
        collection = "houses"


