# app/db.py
import motor.motor_asyncio
from .config import Config

MONGO_URI = Config.mongo_uri
MONGO_DB_NAME = Config.mongo_db_name

client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client[MONGO_DB_NAME]

# Collections
users_collection = db["users"]
questions_collection = db["questions"]
# Basic analytics/telemetry collection
metrics_collection = db["metrics"]
training_datasets_collection = db["training_datasets"]
kpi_events_collection = db["kpi_events"]
