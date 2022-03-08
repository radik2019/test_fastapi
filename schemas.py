from typing import List, Optional, Dict
from pydantic import Field
from odmantic import AIOEngine, Model, ObjectId
from odmantic.field import Field
# from motor.motor_asyncio import AsyncIOMotorClient


# client = AsyncIOMotorClient("mongodb://localhost:27017")
# engine = AIOEngine(motor_client=client, database="raduDB")

class Appliances(Model):
    brand: str
    model: str
    
class Person(Model):
    f_name: str
    l_name: str
    age: int
    appliances: Optional[List[Appliances]] = None
    class Config:
        collection = "person"
    
class Room(Model):
    count_room: int
class HouseNumber(Model):
    number_house: int
    persons: Optional[List[Room]] = None

class Street(Model):
    name: str
    houses: List[HouseNumber]
    
class Municipality(Model):
    city_name: str = Field(..., max_length=15, )
    population: int
    zip_cod: str = Field(..., regex=r'\d{5}')
    streets: Optional[List[Street]] = None
    class Config:
        collection = "municipality"
