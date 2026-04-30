import os
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ["INTERNAL_SECRET"] = "test-secret-value"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["REDIS_URL"] = "redis://localhost:6379"

from routers.admin import router

app = FastAPI()
app.include_router(router)
client = TestClient(app)


def test_trigger_rejects_missing_token():
    response = client.post("/trigger")
    assert response.status_code == 401


def test_trigger_rejects_wrong_token():
    response = client.post("/trigger", headers={"X-Internal-Token": "wrong"})
    assert response.status_code == 401


def test_trigger_accepts_correct_token():
    response = client.post("/trigger", headers={"X-Internal-Token": "test-secret-value"})
    assert response.status_code == 200
    assert response.json() == {"triggered": True}
