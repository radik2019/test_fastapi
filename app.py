from typing import List, Optional, Dict
from fastapi import FastAPI, HTTPException
from schemas import Appliances, Person, Room, HouseNumber, Street, Municipality
from motor.motor_asyncio import AsyncIOMotorClient
from odmantic import AIOEngine, Model, ObjectId

client = AsyncIOMotorClient("mongodb://localhost:27017")
engine = AIOEngine(motor_client=client, database="raduDB")



app = FastAPI()

@app.post("/api/resistors", response_model=Municipality)
async def create_resistor(data: Municipality):
    inst = await engine.save(data)
    return inst

@app.get("/api/resistors", response_model=List[Municipality])
async def list_resistors(from_value: Optional[str] = None):
    q = () if not from_value else Municipality.city_name == from_value
    print(q)
    collection = await engine.find(Municipality, q)
    return collection

@app.get("/api/resistors/{municipality_id}", response_model=Municipality)
async def fetch_resistor(municipality_id: str):
    """Ritorna il dettaglio di una resistenza

    Args:
        municipality_id (str): Id della resistenza
    """
    inst = await engine.find_one(Municipality, Municipality.id == ObjectId(municipality_id))
    if not inst: raise HTTPException(detail="Resistor not found", status_code=404)
    return inst

@app.get("/api/persons", response_model=List[Person])
async def list_persons(from_value: Optional[str] = None):
    q = () if not from_value else Person.f_name == from_value
    inst = await engine.find(Person, q)
    return inst

@app.post("/api/persons", response_model=Person)
async def create_person(data: Person):
    print(dir(engine))
    print(engine.get_collection(Person))
    inst = await engine.save(data)
    return inst























"""from fastapi import FastAPI, Query, Path
from schemas import Continent, Country
import uvicorn
lst = []
MAX_ID: int = 1
app = FastAPI()

@app.get('/')
def root():
    return lst

@app.get('/{pk}/')
def get_item(pk: int = Path(
    None, le=12, ge=1), ):

    return lst[pk]


@app.post("/create/")
def create_continent(item: Continent):
    global lst
    global MAX_ID
    try:
        lst.append(item)
        MAX_ID = max([i["id"] for i in lst])
        print(MAX_ID)
    except TypeError:
        pass
    print(MAX_ID)
    return item

@app.delete("/delete/")
def delete_continent(item: Continent):
    global lst
    if item in lst:
        lst.remove(item)
    print(lst)
    return item

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)"""