import os
import tempfile

os.environ["MAYOCSPM_STATE_DIR"] = tempfile.mkdtemp(prefix="mayocspm-tests-")
os.environ["DATABASE_URL"] = os.getenv("MAYOCSPM_TEST_DATABASE_URL", "sqlite://")
os.environ["PUBLIC_URL"] = "http://testserver"
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
os.environ["BOOTSTRAP_EMAIL"] = "owner@example.com"
os.environ["BOOTSTRAP_PASSWORD"] = "local-fixture-password-only"

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.db as database_module
import app.main as main_module
import app.worker as worker_module
from app.db import Base

os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
if os.environ["DATABASE_URL"] == "sqlite://":
    test_engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
else:
    test_engine = create_engine(os.environ["DATABASE_URL"])
TestSession = sessionmaker(test_engine, expire_on_commit=False)
database_module.engine = main_module.engine = worker_module.engine = test_engine
database_module.Session = main_module.Session = worker_module.Session = TestSession


@pytest.fixture
def client():
    Base.metadata.drop_all(test_engine)
    Base.metadata.create_all(test_engine)
    with TestClient(main_module.app) as instance:
        instance.headers["Origin"] = "http://testserver"
        yield instance


@pytest.fixture
def owner(client):
    assert client.post("/api/auth/login", json={"email": "owner@example.com", "password": "local-fixture-password-only"}).status_code == 200
    workspace = client.post("/api/workspaces", json={"name": "First"}).json()
    return client, workspace["id"]


@pytest.fixture
def populated(owner):
    client, workspace = owner
    connection = client.post(f"/api/workspaces/{workspace}/connections", json={"name": "Demo", "kind": "demo"}).json()
    job = client.post(f"/api/workspaces/{workspace}/connections/{connection['id']}/scan").json()
    assert worker_module.work_once()
    assert client.get(f"/api/workspaces/{workspace}/jobs").json()[0]["status"] == "completed"
    return client, workspace, connection["id"], job["id"]
