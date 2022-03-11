from motor.motor_asyncio import AsyncIOMotorClient
from odmantic import AIOEngine


SESSION_EXP_SEC = 60
SESSION_EXP_MIN = 10
SESSION_EXP_DAYS = 0

client = AsyncIOMotorClient("mongodb://localhost:27017")
engine = AIOEngine(motor_client=client, database="raduDB")


def dbg(*args):
    print("\n\n\n")
    for i in args: print(i)
    print("\n\n\n")





