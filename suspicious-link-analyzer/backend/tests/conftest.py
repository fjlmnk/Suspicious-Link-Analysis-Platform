"""Pytest configuration and shared fixtures."""
import asyncio
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.main import app
from app.database import Base, get_db


TEST_DATABASE_URL = "sqlite+aiosqlite:///./test_suspicious_links.db"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


@pytest_asyncio.fixture
async def setup_database():
    """Create tables before test and drop after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    """Provide a test database session."""
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncClient:
    """Provide an async HTTP test client with overridden DB dependency."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def sample_session_id():
    """Provide a test session ID."""
    return "test-session-12345"


@pytest.fixture
def employee_session_id():
    """Provide a test employee session ID."""
    return "employee-session-67890"


@pytest.fixture
def auth_headers(sample_session_id):
    """Provide headers with session ID for regular user."""
    return {"X-Session-Id": sample_session_id}


@pytest.fixture
def employee_headers(employee_session_id):
    """Provide headers with session ID for employee user."""
    return {"X-Session-Id": employee_session_id}
