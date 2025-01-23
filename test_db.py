import pytest
import psycopg2
import logging
import os
import configparser
from datetime import datetime
import boto3
from cloudtrail_1_optimized import (
    get_aws_clients,
    get_all_trails,
    get_all_s3_buckets,
    check_cloudtrail_bucket_public_access,
    check_cloudtrail_multi_region_read_write,
    check_cloudtrail_multi_region_trail,
    check_cloudtrail_logs_integration,
    check_cloudtrail_s3_logging,
    check_cloudtrail_s3_data_events,
    check_cloudtrail_s3_object_read_events,
    check_cloudtrail_s3_object_write_events
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@pytest.fixture
def config():
    """Load test configuration"""
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(__file__), 'config.ini')
    if not os.path.exists(config_path):
        pytest.fail(f"Config file not found at {config_path}")
    config.read(config_path)
    return config

@pytest.fixture
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

@pytest.fixture
def aws_clients():
    """Initialize AWS clients for testing"""
    try:
        return get_aws_clients()
    except Exception as e:
        pytest.fail(f"AWS client initialization failed: {e}")

def test_config_file_exists():
    """Test if config.ini exists and has required sections"""
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(__file__), 'config.ini')
    assert os.path.exists(config_path), "config.ini not found"
    
    config.read(config_path)
    assert 'AWS' in config.sections(), "AWS section missing in config.ini"
    assert 'PostgreSQL' in config.sections(), "PostgreSQL section missing in config.ini"

def test_config_aws_credentials(config):
    """Test if AWS credentials are properly configured"""
    assert config['AWS']['AWS_ACCESS_KEY_ID'], "AWS access key missing"
    assert config['AWS']['AWS_SECRET_ACCESS_KEY'], "AWS secret key missing"
    assert config['AWS']['AWS_REGION'], "AWS region missing"

def test_config_postgresql_credentials(config):
    """Test if PostgreSQL credentials are properly configured"""
    assert config['PostgreSQL']['HOST'], "PostgreSQL host missing"
    assert config['PostgreSQL']['DATABASE'], "PostgreSQL database missing"
    assert config['PostgreSQL']['USER'], "PostgreSQL user missing"
    assert config['PostgreSQL']['PASSWORD'], "PostgreSQL password missing"

def test_db_connection(db_connection):
    """Test database connection"""
    cur = db_connection.cursor()
    cur.execute("SELECT 1")
    result = cur.fetchone()
    assert result[0] == 1, "Database query failed"
    cur.close()

def test_aws_client_initialization(aws_clients):
    """Test AWS client initialization"""
    assert aws_clients.cloudtrail, "CloudTrail client not initialized"
    assert aws_clients.s3, "S3 client not initialized"
    assert aws_clients.sts, "STS client not initialized"
    assert aws_clients.account_id, "Account ID not retrieved"

def test_cloudtrail_checks_performance(aws_clients, is_test=False):
    """Test performance of CloudTrail security checks"""
    start_time = datetime.now()
    
    # Get cached data
    trails = get_all_trails(aws_clients.cloudtrail)
    try:
        buckets = get_all_s3_buckets(aws_clients.s3)
    except Exception as e:
        logger.warning(f"S3 bucket listing failed, using empty set: {e}")
        buckets = set()
    
    # Run all checks
    checks = [
        (check_cloudtrail_bucket_public_access, [aws_clients.cloudtrail, aws_clients.s3, aws_clients.account_id, trails, buckets]),
        (check_cloudtrail_multi_region_read_write, [aws_clients.cloudtrail, aws_clients.account_id, trails]),
        (check_cloudtrail_multi_region_trail, [aws_clients.cloudtrail, aws_clients.account_id, trails]),
        (check_cloudtrail_logs_integration, [aws_clients.cloudtrail, aws_clients.account_id, trails]),
        (check_cloudtrail_s3_logging, [aws_clients.cloudtrail, aws_clients.s3, aws_clients.account_id, trails, buckets]),
        (check_cloudtrail_s3_data_events, [aws_clients.cloudtrail, aws_clients.s3, aws_clients.account_id, trails, buckets]),
        (check_cloudtrail_s3_object_read_events, [aws_clients.cloudtrail, aws_clients.s3, aws_clients.account_id, trails, buckets]),
        (check_cloudtrail_s3_object_write_events, [aws_clients.cloudtrail, aws_clients.s3, aws_clients.account_id, trails, buckets])
    ]
    
    all_results = []
    for check_func, args in checks:
        result = check_func(*args)
        if isinstance(result, list):
            all_results.extend(result)
        else:
            all_results.append(result)
    
    duration = (datetime.now() - start_time).total_seconds()
    
    # Verify performance improvements
    assert duration < 240, f"Performance not improved: {duration} seconds (target: < 240 seconds)"
    assert len(all_results) > 0, "No check results returned"
    
    # Add test prefix if needed
    if is_test:
        for result in all_results:
            result['reason'] = f"TEST_{result['reason']}"
    
    # Log performance metrics
    logger.info(f"CloudTrail checks completed in {duration:.2f} seconds")
    logger.info(f"Total results: {len(all_results)}")
    
    return duration, len(all_results), all_results

def test_database_inserts(aws_clients, db_connection):
    """Test database inserts for CloudTrail check results"""
    cur = db_connection.cursor()
    
    try:
        # Clear existing test data
        cur.execute("DELETE FROM aws_project_status WHERE description LIKE 'TEST_%'")
        db_connection.commit()
        
        # Run checks and insert results
        duration, result_count, results = test_cloudtrail_checks_performance(aws_clients, is_test=True)
        
        # Batch insert results
        insert_data = [(r['reason'], r['resource'], r['status']) for r in results]
        cur.executemany(
            """
            INSERT INTO aws_project_status (description, resource, status)
            VALUES (%s, %s, %s)
            """,
            insert_data
        )
        db_connection.commit()
        
        # Verify inserts
        cur.execute("SELECT COUNT(*) FROM aws_project_status WHERE description LIKE 'TEST_%'")
        count = cur.fetchone()[0]
        assert count > 0, "No results inserted into database"
        assert count == len(results), f"Expected {len(results)} inserts, got {count}"
        
        logger.info(f"Successfully inserted and verified {count} test results")
    finally:
        cur.close()

if __name__ == "__main__":
    pytest.main([__file__, '-v'])
