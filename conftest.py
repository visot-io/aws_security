import pytest
import os
import configparser
import psycopg2
from cloudtrail_1_optimized import get_aws_clients

@pytest.fixture(scope="session")
def config():
    """Load test configuration"""
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(__file__), 'config.ini')
    if not os.path.exists(config_path):
        pytest.fail(f"Config file not found at {config_path}")
    config.read(config_path)
    return config

@pytest.fixture(scope="session")
def db_connection(config):
    """Create database connection for testing"""
    try:
        conn = psycopg2.connect(
            host=config['PostgreSQL']['HOST'],
            database=config['PostgreSQL']['DATABASE'],
            user=config['PostgreSQL']['USER'],
            password=config['PostgreSQL']['PASSWORD']
        )
        yield conn
        conn.close()
    except Exception as e:
        pytest.fail(f"Database connection failed: {e}")

@pytest.fixture(scope="session")
def aws_clients():
    """Initialize AWS clients for testing"""
    try:
        return get_aws_clients()
    except Exception as e:
        pytest.fail(f"AWS client initialization failed: {e}")
