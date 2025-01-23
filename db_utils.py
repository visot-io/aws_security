import psycopg2
import logging
from typing import List, Dict, Any, Optional
import os
import configparser
from datetime import datetime

logger = logging.getLogger(__name__)

def get_db_connection(config_path: str) -> Optional[psycopg2.extensions.connection]:
    """Create database connection using config file"""
    try:
        # Load configuration
        config = configparser.ConfigParser()
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found at {config_path}")
        
        config.read(config_path)
        logger.info(f"Reading PostgreSQL credentials from: {config_path}")
        
        try:
            host = config['PostgreSQL']['HOST']
            database = config['PostgreSQL']['DATABASE']
            user = config['PostgreSQL']['USER']
            password = config['PostgreSQL']['PASSWORD']
        except KeyError as e:
            raise ValueError(f"Missing PostgreSQL configuration in config.ini: {e}")
            
        if not all([host, database, user, password]):
            raise ValueError("Empty PostgreSQL credentials in config.ini")
            
        conn = psycopg2.connect(
            host=host,
            database=database,
            user=user,
            password=password
        )
        logger.info("Successfully connected to database")
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

def batch_insert_results(results: List[Dict[str, Any]], config_path: str) -> bool:
    """Batch insert results into database"""
    if not results:
        return True
        
    conn = None
    cur = None
    try:
        conn = get_db_connection(config_path)
        if not conn:
            return False
            
        cur = conn.cursor()
        
        # Prepare data for batch insert
        insert_data = [
            (result['reason'], result['resource'], result['status'])
            for result in results
            if all(k in result for k in ['reason', 'resource', 'status'])
        ]
        
        if not insert_data:
            logger.warning("No valid results to insert")
            return True
        
        # Perform batch insert
        cur.executemany(
            """
            INSERT INTO aws_project_status (description, resource, status)
            VALUES (%s, %s, %s)
            """,
            insert_data
        )
        
        conn.commit()
        logger.info(f"Successfully inserted {len(insert_data)} results in batch")
        return True
        
    except Exception as e:
        logger.error(f"Error in batch insert: {e}")
        if conn:
            conn.rollback()
        return False
        
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
