import boto3
from flask import Flask, jsonify
import configparser
import psycopg2
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
import re
import os
import logging
from logging.config import dictConfig

# Configure logging
dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://sys.stdout',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)
logger = app.logger

# Load configuration
current_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(current_dir, 'config.ini')
config = configparser.ConfigParser()
config.read(config_path)

def get_aws_credentials() -> Tuple[str, str, str]:
    """Get AWS credentials from config file"""
    try:
        logger.info(f"Reading AWS credentials from: {config_path}")
        logger.info(f"Config file exists: {os.path.exists(config_path)}")
        logger.info(f"Config sections found: {config.sections()}")
        
        aws_key = config['AWS']['AWS_ACCESS_KEY_ID']
        aws_secret = config['AWS']['AWS_SECRET_ACCESS_KEY']
        aws_region = config['AWS']['AWS_REGION']
        
        if not aws_key or not aws_secret or not aws_region:
            raise ValueError("Empty AWS credentials in config.ini")
        
        logger.info("Successfully loaded AWS credentials from config.ini")    
        return aws_key, aws_secret, aws_region
    except (KeyError, ValueError) as e:
        logger.error(f"Error reading config.ini: {str(e)}")
        raise Exception(f"Error loading AWS credentials from config.ini: {str(e)}")

def get_aws_session() -> boto3.Session:
    """Create a boto3 session with credentials from config file"""
    aws_key, aws_secret, aws_region = get_aws_credentials()
    return boto3.Session(
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret,
        region_name=aws_region
    )

def get_db_connection():
    try:
        # Read PostgreSQL configuration from config.ini
        config = configparser.ConfigParser()
        config.read(config_path)
        
        try:
            host = config['PostgreSQL']['HOST']
            database = config['PostgreSQL']['DATABASE']
            user = config['PostgreSQL']['USER']
            password = config['PostgreSQL']['PASSWORD']
        except KeyError as e:
            print(f"Missing PostgreSQL configuration in config.ini: {str(e)}")
            return None

        return psycopg2.connect(
            host=host,
            database=database,
            user=user,
            password=password
        )
    except psycopg2.Error as e:
        print(f"Error connecting to PostgreSQL: {str(e)}")
        return None

def check_multiple_az(autoscaling_client, asg: Dict[str, Any], account_id: str) -> Optional[Dict[str, Any]]:
    """Check if AutoScaling group is configured with multiple AZs"""
    try:
        asg_name = asg.get('AutoScalingGroupName', 'Unknown')
        asg_arn = asg.get('AutoScalingGroupARN')
        region = autoscaling_client.meta.region_name
        availability_zones = asg.get('AvailabilityZones', [])
        az_count = len(availability_zones)

        if az_count > 1:
            status = "ok"
        else:
            status = "alarm"

        return {
            "type": "autoscaling_group_multiple_az",
            "resource": asg_arn,
            "status": status,
            "reason": f"{asg_name} has {az_count} availability zone(s).",
            "region": region,
            "account": account_id
        }
    except Exception as e:
        print(f"Error checking multiple AZs for ASG {asg.get('AutoScalingGroupName')}: {str(e)}")
        return None

@app.route('/check-autoscaling')
def check_autoscaling():
    try:
        logger.info("=== Starting check_autoscaling endpoint ===")
        logger.info(f"Current working directory: {os.getcwd()}")
        logger.info(f"Config path being used: {config_path}")
        logger.info(f"Config file exists: {os.path.exists(config_path)}")
        
        # Get AWS session with credentials from config file
        try:
            session = get_aws_session()
            logger.info("AWS session created successfully")
        except Exception as e:
            logger.error(f"Failed to create AWS session: {str(e)}")
            return jsonify({
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 500
        
        # Get AWS account ID using session with explicit credentials
        try:
            sts_client = session.client('sts',
                aws_access_key_id=session.get_credentials().access_key,
                aws_secret_access_key=session.get_credentials().secret_key,
                region_name=session.region_name
            )
            account_id = sts_client.get_caller_identity()['Account']
        except Exception as e:
            return jsonify({
                "error": f"Error getting AWS account ID: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 500
        
        # Get database connection
        all_results = []
        conn = get_db_connection()
        if conn is None:
            return jsonify({
                "error": "Unable to connect to PostgreSQL database",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 500

        cur = conn.cursor()
    except Exception as e:
        return jsonify({
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500

if __name__ == '__main__':
    logger.info("Starting server on port 5001...")
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.run(debug=True, port=5001, use_reloader=False)
