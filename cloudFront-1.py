import boto3
from flask import Flask, jsonify
import configparser
import psycopg2
from datetime import datetime, timezone
import json
import os
import logging
from typing import Dict, Any, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cloudfront_checks.log')
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load configuration
config = configparser.ConfigParser()
config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini')
if not os.path.exists(config_path):
    raise FileNotFoundError(f"Config file not found at {config_path}")

config.read(config_path)
logger.info(f"Reading configuration from: {config_path}")

# Database connection function
def get_db_connection():
    try:
        logger.info("Establishing database connection...")
        conn = psycopg2.connect(
            host=config['PostgreSQL']['HOST'],
            database=config['PostgreSQL']['DATABASE'],
            user=config['PostgreSQL']['USER'],
            password=config['PostgreSQL']['PASSWORD']
        )
        logger.info("Database connection established successfully")
        return conn
    except (KeyError, psycopg2.Error) as e:
        logger.error(f"Database connection error: {str(e)}")
        raise ValueError(f"Failed to connect to database: {str(e)}")

def check_cloudfront_distribution_no_non_existent_s3_origin(cloudfront_client, s3_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if CloudFront distributions point to non-existent S3 buckets"""
    try:
        # Get all distributions
        distributions = []
        paginator = cloudfront_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions.extend(page['DistributionList']['Items'])

        # Get all S3 buckets
        existing_buckets = set()
        try:
            response = s3_client.list_buckets()
            existing_buckets = {bucket['Name'] for bucket in response['Buckets']}
        except Exception as e:
            logger.error(f"Error listing S3 buckets: {str(e)}")

        results = []
        for dist in distributions:
            try:
                dist_id = dist['Id']
                dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
                
                # Get detailed distribution config
                config = cloudfront_client.get_distribution_config(Id=dist_id)
                origins = config['DistributionConfig'].get('Origins', {}).get('Items', [])
                
                # Find non-existent S3 origins
                non_existent_buckets = []
                for origin in origins:
                    domain_name = origin.get('DomainName', '')
                    if '.s3.' in domain_name:
                        # Extract bucket name from origin ID or domain name
                        bucket_name = origin.get('Id', '').split('.s3')[0]
                        if not bucket_name:
                            bucket_name = domain_name.split('.s3.')[0]
                        
                        if bucket_name and bucket_name not in existing_buckets:
                            non_existent_buckets.append(bucket_name)

                if non_existent_buckets:
                    # Format reason message based on number of non-existent buckets
                    if len(non_existent_buckets) > 2:
                        reason = f"{dist_id} point to non-existent S3 origins {non_existent_buckets[0]}, {non_existent_buckets[1]} and {len(non_existent_buckets) - 2} more."
                    elif len(non_existent_buckets) == 2:
                        reason = f"{dist_id} point to non-existent S3 origins {non_existent_buckets[0]} and {non_existent_buckets[1]}."
                    else:
                        reason = f"{dist_id} point to non-existent S3 origin {non_existent_buckets[0]}."
                    
                    results.append({
                        "type": "cloudfront_distribution_no_non_existent_s3_origin",
                        "resource": dist_arn,
                        "status": "alarm",
                        "reason": reason,
                        "region": "global",
                        "account": account_id
                    })
                else:
                    results.append({
                        "type": "cloudfront_distribution_no_non_existent_s3_origin",
                        "resource": dist_arn,
                        "status": "ok",
                        "reason": f"{dist_id} does not point to any non-existent S3 origins.",
                        "region": "global",
                        "account": account_id
                    })

            except Exception as e:
                logger.error(f"Error processing distribution {dist_id}: {str(e)}")
                continue

        logger.info(f"Completed S3 origin check for {len(distributions)} distributions")
        return results

    except Exception as e:
        logger.error(f"Error checking CloudFront distributions: {str(e)}")
        return []

def check_cloudfront_distribution_encryption_in_transit(cloudfront_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if CloudFront distributions enforce encryption in transit"""
    try:
        # Get all distributions
        distributions = []
        paginator = cloudfront_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions.extend(page['DistributionList']['Items'])

        results = []
        for dist in distributions:
            try:
                dist_id = dist['Id']
                dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
                
                # Get detailed distribution config
                config = cloudfront_client.get_distribution_config(Id=dist_id)
                dist_config = config['DistributionConfig']
                
                # Check default cache behavior
                default_policy = dist_config.get('DefaultCacheBehavior', {}).get('ViewerProtocolPolicy')
                allows_unencrypted = default_policy == 'allow-all'
                
                # Check cache behaviors
                cache_behaviors = dist_config.get('CacheBehaviors', {}).get('Items', [])
                for behavior in cache_behaviors:
                    if behavior.get('ViewerProtocolPolicy') == 'allow-all':
                        allows_unencrypted = True
                        break
                
                if allows_unencrypted:
                    results.append({
                        "type": "cloudfront_distribution_encryption_in_transit_enabled",
                        "resource": dist_arn,
                        "status": "alarm",
                        "reason": f"{dist_id} data not encrypted in transit.",
                        "region": "global",
                        "account": account_id
                    })
                else:
                    results.append({
                        "type": "cloudfront_distribution_encryption_in_transit_enabled",
                        "resource": dist_arn,
                        "status": "ok",
                        "reason": f"{dist_id} data encrypted in transit.",
                        "region": "global",
                        "account": account_id
                    })

            except Exception as e:
                logger.error(f"Error processing distribution {dist_id}: {str(e)}")
                continue

        logger.info(f"Completed encryption check for {len(distributions)} distributions")
        return results

    except Exception as e:
        logger.error(f"Error checking CloudFront distributions encryption: {str(e)}")
        return []

def check_cloudfront_distribution_geo_restrictions(cloudfront_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if CloudFront distributions have geo restrictions enabled"""
    try:
        # Get all distributions
        distributions = []
        paginator = cloudfront_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions.extend(page['DistributionList']['Items'])

        results = []
        for dist in distributions:
            try:
                dist_id = dist['Id']
                dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
                
                # Get detailed distribution config
                config = cloudfront_client.get_distribution_config(Id=dist_id)
                dist_config = config['DistributionConfig']
                
                # Check geo restriction settings
                restrictions = dist_config.get('Restrictions', {})
                geo_restriction = restrictions.get('GeoRestriction', {})
                restriction_type = geo_restriction.get('RestrictionType', 'none')
                
                if restriction_type == 'none':
                    results.append({
                        "type": "cloudfront_distribution_geo_restrictions_enabled",
                        "resource": dist_arn,
                        "status": "alarm",
                        "reason": f"{dist_id} Geo Restriction disabled.",
                        "region": "global",
                        "account": account_id
                    })
                else:
                    results.append({
                        "type": "cloudfront_distribution_geo_restrictions_enabled",
                        "resource": dist_arn,
                        "status": "ok",
                        "reason": f"{dist_id} Geo Restriction enabled.",
                        "region": "global",
                        "account": account_id
                    })

            except Exception as e:
                logger.error(f"Error processing distribution {dist_id}: {str(e)}")
                continue

        logger.info(f"Completed geo restrictions check for {len(distributions)} distributions")
        return results

    except Exception as e:
        logger.error(f"Error checking CloudFront distributions geo restrictions: {str(e)}")
        return []

def check_cloudfront_distribution_use_secure_cipher(cloudfront_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if CloudFront distributions use secure ciphers"""
    try:
        # Get all distributions
        distributions = []
        paginator = cloudfront_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions.extend(page['DistributionList']['Items'])

        results = []
        for dist in distributions:
            try:
                dist_id = dist['Id']
                dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
                
                # Get detailed distribution config
                config = cloudfront_client.get_distribution_config(Id=dist_id)
                dist_config = config['DistributionConfig']
                
                # Check origins for insecure protocols
                origins = dist_config.get('Origins', {}).get('Items', [])
                uses_insecure_cipher = False
                
                for origin in origins:
                    custom_origin_config = origin.get('CustomOriginConfig', {})
                    if custom_origin_config:
                        ssl_protocols = custom_origin_config.get('OriginSslProtocols', {}).get('Items', [])
                        
                        # Check for insecure protocols (TLSv1 or SSLv3)
                        if 'TLSv1' in ssl_protocols or 'SSLv3' in ssl_protocols:
                            uses_insecure_cipher = True
                            break
                
                if uses_insecure_cipher:
                    results.append({
                        "type": "cloudfront_distribution_use_secure_cipher",
                        "resource": dist_arn,
                        "status": "alarm",
                        "reason": f"{dist_id} does not use secure cipher.",
                        "region": "global",
                        "account": account_id
                    })
                else:
                    results.append({
                        "type": "cloudfront_distribution_use_secure_cipher",
                        "resource": dist_arn,
                        "status": "ok",
                        "reason": f"{dist_id} uses secure cipher.",
                        "region": "global",
                        "account": account_id
                    })

            except Exception as e:
                logger.error(f"Error processing distribution {dist_id}: {str(e)}")
                continue

        logger.info(f"Completed secure cipher check for {len(distributions)} distributions")
        return results

    except Exception as e:
        logger.error(f"Error checking CloudFront distributions secure cipher: {str(e)}")
        return []

def check_cloudfront_distribution_non_s3_origins_encryption(cloudfront_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if CloudFront distributions enforce encryption in transit for non-S3 origins"""
    try:
        # Get all distributions
        distributions = []
        paginator = cloudfront_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions.extend(page['DistributionList']['Items'])

        results = []
        for dist in distributions:
            try:
                dist_id = dist['Id']
                dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
                
                # Get detailed distribution config
                config = cloudfront_client.get_distribution_config(Id=dist_id)
                dist_config = config['DistributionConfig']
                
                # Check viewer protocol policies
                default_viewer_policy = dist_config.get('DefaultCacheBehavior', {}).get('ViewerProtocolPolicy')
                allows_unencrypted_viewer = default_viewer_policy == 'allow-all'
                
                cache_behaviors = dist_config.get('CacheBehaviors', {}).get('Items', [])
                for behavior in cache_behaviors:
                    if behavior.get('ViewerProtocolPolicy') == 'allow-all':
                        allows_unencrypted_viewer = True
                        break
                
                # Check origin protocol policies for non-S3 origins
                origins = dist_config.get('Origins', {}).get('Items', [])
                not_encrypted = False
                
                for origin in origins:
                    # Skip S3 origins
                    if 'S3OriginConfig' in origin:
                        continue
                        
                    custom_origin_config = origin.get('CustomOriginConfig', {})
                    if custom_origin_config:
                        origin_protocol_policy = custom_origin_config.get('OriginProtocolPolicy')
                        
                        if origin_protocol_policy == 'http-only':
                            not_encrypted = True
                            break
                        elif origin_protocol_policy == 'match-viewer' and allows_unencrypted_viewer:
                            not_encrypted = True
                            break
                
                if not_encrypted:
                    results.append({
                        "type": "cloudfront_distribution_non_s3_origins_encryption",
                        "resource": dist_arn,
                        "status": "alarm",
                        "reason": f"{dist_id} origins traffic not encrypted in transit.",
                        "region": "global",
                        "account": account_id
                    })
                else:
                    results.append({
                        "type": "cloudfront_distribution_non_s3_origins_encryption",
                        "resource": dist_arn,
                        "status": "ok",
                        "reason": f"{dist_id} origins traffic encrypted in transit.",
                        "region": "global",
                        "account": account_id
                    })

            except Exception as e:
                logger.error(f"Error processing distribution {dist_id}: {str(e)}")
                continue

        logger.info(f"Completed non-S3 origins encryption check for {len(distributions)} distributions")
        return results

    except Exception as e:
        logger.error(f"Error checking CloudFront distributions non-S3 origins encryption: {str(e)}")
        return []

def check_cloudfront_distribution_no_deprecated_ssl_protocol(cloudfront_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if CloudFront distributions use deprecated SSL protocols"""
    try:
        # Get all distributions
        distributions = []
        paginator = cloudfront_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions.extend(page['DistributionList']['Items'])

        results = []
        for dist in distributions:
            try:
                dist_id = dist['Id']
                dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
                
                # Get detailed distribution config
                config = cloudfront_client.get_distribution_config(Id=dist_id)
                dist_config = config['DistributionConfig']
                
                # Check origins for deprecated SSL protocols
                origins = dist_config.get('Origins', {}).get('Items', [])
                has_deprecated_ssl = False
                
                for origin in origins:
                    custom_origin_config = origin.get('CustomOriginConfig', {})
                    if custom_origin_config:
                        ssl_protocols = custom_origin_config.get('OriginSslProtocols', {}).get('Items', [])
                        
                        # Check specifically for SSLv3
                        if 'SSLv3' in ssl_protocols:
                            has_deprecated_ssl = True
                            break
                
                if has_deprecated_ssl:
                    results.append({
                        "type": "cloudfront_distribution_no_deprecated_ssl_protocol",
                        "resource": dist_arn,
                        "status": "alarm",
                        "reason": f"{dist_id} has deprecated SSL protocols.",
                        "region": "global",
                        "account": account_id
                    })
                else:
                    results.append({
                        "type": "cloudfront_distribution_no_deprecated_ssl_protocol",
                        "resource": dist_arn,
                        "status": "ok",
                        "reason": f"{dist_id} does not have deprecated SSL protocols.",
                        "region": "global",
                        "account": account_id
                    })

            except Exception as e:
                print(f"Error processing distribution {dist_id}: {str(e)}")
                continue

        return results

    except Exception as e:
        print(f"Error checking CloudFront distributions deprecated SSL: {str(e)}")
        return []

def check_cloudfront_distribution_custom_origins_encryption(cloudfront_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if CloudFront distributions enforce encryption in transit for custom origins"""
    try:
        # Get all distributions
        distributions = []
        paginator = cloudfront_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions.extend(page['DistributionList']['Items'])

        results = []
        for dist in distributions:
            try:
                dist_id = dist['Id']
                dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
                
                # Get detailed distribution config
                config = cloudfront_client.get_distribution_config(Id=dist_id)
                dist_config = config['DistributionConfig']
                
                # Check viewer protocol policies
                default_viewer_policy = dist_config.get('DefaultCacheBehavior', {}).get('ViewerProtocolPolicy')
                allows_unencrypted_viewer = default_viewer_policy == 'allow-all'
                
                cache_behaviors = dist_config.get('CacheBehaviors', {}).get('Items', [])
                for behavior in cache_behaviors:
                    if behavior.get('ViewerProtocolPolicy') == 'allow-all':
                        allows_unencrypted_viewer = True
                        break
                
                # Check origin protocol policies for custom origins
                origins = dist_config.get('Origins', {}).get('Items', [])
                not_encrypted = False
                
                for origin in origins:
                    custom_origin_config = origin.get('CustomOriginConfig', {})
                    if custom_origin_config:
                        origin_protocol_policy = custom_origin_config.get('OriginProtocolPolicy')
                        
                        if origin_protocol_policy == 'http-only':
                            not_encrypted = True
                            break
                        elif origin_protocol_policy == 'match-viewer' and allows_unencrypted_viewer:
                            not_encrypted = True
                            break
                
                if not_encrypted:
                    results.append({
                        "type": "cloudfront_distribution_custom_origins_encryption",
                        "resource": dist_arn,
                        "status": "alarm",
                        "reason": f"{dist_id} custom origins traffic not encrypted in transit.",
                        "region": "global",
                        "account": account_id
                    })
                else:
                    results.append({
                        "type": "cloudfront_distribution_custom_origins_encryption",
                        "resource": dist_arn,
                        "status": "ok",
                        "reason": f"{dist_id} custom origins traffic encrypted in transit.",
                        "region": "global",
                        "account": account_id
                    })

            except Exception as e:
                print(f"Error processing distribution {dist_id}: {str(e)}")
                continue

        return results

    except Exception as e:
        print(f"Error checking CloudFront distributions custom origins encryption: {str(e)}")
        return []

def check_cloudfront_distribution_logging(cloudfront_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if CloudFront distributions have logging enabled"""
    try:
        # Get all distributions
        distributions = []
        paginator = cloudfront_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions.extend(page['DistributionList']['Items'])

        results = []
        for dist in distributions:
            try:
                dist_id = dist['Id']
                dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
                
                # Get detailed distribution config
                config = cloudfront_client.get_distribution_config(Id=dist_id)
                dist_config = config['DistributionConfig']
                
                # Check logging configuration
                logging_config = dist_config.get('Logging', {})
                logging_enabled = logging_config.get('Enabled', False)
                
                if logging_enabled:
                    results.append({
                        "type": "cloudfront_distribution_logging",
                        "resource": dist_arn,
                        "status": "ok",
                        "reason": f"{dist_id} logging enabled.",
                        "region": "global",
                        "account": account_id
                    })
                else:
                    results.append({
                        "type": "cloudfront_distribution_logging",
                        "resource": dist_arn,
                        "status": "alarm",
                        "reason": f"{dist_id} logging disabled.",
                        "region": "global",
                        "account": account_id
                    })

            except Exception as e:
                print(f"Error processing distribution {dist_id}: {str(e)}")
                continue

        return results

    except Exception as e:
        print(f"Error checking CloudFront distributions logging: {str(e)}")
        return []

@app.route('/check-cloudfront-1')
def check_cloudfront():
    try:
        # Get AWS credentials from config
        try:
            aws_key = config['AWS']['AWS_ACCESS_KEY_ID']
            aws_secret = config['AWS']['AWS_SECRET_ACCESS_KEY']
            aws_region = config['AWS'].get('AWS_REGION', 'us-east-1')
            
            if not aws_key or not aws_secret:
                raise ValueError("Empty AWS credentials in config.ini")
                
            logger.info("AWS credentials loaded successfully")
        except KeyError as e:
            error_msg = f"Missing AWS credentials in config.ini: {e}"
            logger.error(error_msg)
            return jsonify({
                "error": error_msg,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 500
            
        # Initialize AWS clients
        session = boto3.Session(
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
            region_name=aws_region
        )
        
        s3_client = session.client('s3')
        cloudfront_client = session.client('cloudfront')
        
        # Get AWS account ID
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
        
        all_results = []
        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Run all CloudTrail checks
            check_results = [
                check_cloudfront_distribution_no_non_existent_s3_origin(cloudfront_client, s3_client, account_id),
                check_cloudfront_distribution_encryption_in_transit(cloudfront_client, account_id),
                check_cloudfront_distribution_geo_restrictions(cloudfront_client, account_id),
                check_cloudfront_distribution_use_secure_cipher(cloudfront_client, account_id),
                check_cloudfront_distribution_non_s3_origins_encryption(cloudfront_client, account_id),
                check_cloudfront_distribution_no_deprecated_ssl_protocol(cloudfront_client, account_id),
                check_cloudfront_distribution_custom_origins_encryption(cloudfront_client, account_id),
                check_cloudfront_distribution_logging(cloudfront_client, account_id)
            ]
            
            # Process all results
            for results in check_results:
                if results:
                    for result in results:
                        if result:
                            cur.execute(
                                """
                                INSERT INTO aws_project_status (description, resource, status)
                                VALUES (%s, %s, %s)
                                """,
                                (result['reason'], result['resource'], result['status'])
                            )
                            all_results.append(result)

            conn.commit()
            return jsonify(all_results)

        except Exception as e:
            logger.error(f"Error processing checks: {str(e)}")
            conn.rollback()
            raise ValueError(f"Error processing security checks: {str(e)}")

        finally:
            cur.close()
            conn.close()

    except Exception as e:
        if 'conn' in locals():
            conn.close()
        return jsonify({
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500

if __name__ == '__main__':
    logger.info("Starting server on port 5001...")
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.run(debug=True, port=5001, use_reloader=False)
