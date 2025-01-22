import boto3
from flask import Flask, jsonify
import configparser
import psycopg2
from datetime import datetime, timezone
import json
import os
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from functools import lru_cache
from dataclasses import dataclass
from collections import defaultdict

# Configure logging with more detail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

@dataclass
class AWSClients:
    """Class to hold AWS client instances"""
    session: boto3.Session
    cloudfront: Any
    s3: Any
    sts: Any
    account_id: str

def get_aws_clients() -> AWSClients:
    """Create and cache AWS client instances"""
    session = boto3.Session(
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID_AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY_AWS_SECRET_ACCESS_KEY'),
        region_name=os.environ.get('AWS_DEFAULT_REGION_AWS_DEFAULT_REGION', 'us-east-1')
    )
    
    cloudfront = session.client('cloudfront')
    s3 = session.client('s3')
    sts = session.client('sts')
    account_id = sts.get_caller_identity()['Account']
    
    return AWSClients(session, cloudfront, s3, sts, account_id)

@lru_cache(maxsize=1)
def get_all_distributions(cloudfront_client) -> List[Dict]:
    """Cache and return all CloudFront distributions"""
    distributions = []
    try:
        paginator = cloudfront_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions.extend(page['DistributionList']['Items'])
        return distributions
    except Exception as e:
        logger.error(f"Error fetching distributions: {e}")
        return []

@lru_cache(maxsize=1)
def get_all_s3_buckets(s3_client) -> Optional[set[str]]:
    """Cache and return all S3 bucket names"""
    try:
        response = s3_client.list_buckets()
        return {bucket['Name'] for bucket in response['Buckets']}
    except Exception as e:
        logger.error(f"Error listing S3 buckets: {e}")
        return None

def get_distribution_config(cloudfront_client, dist_id: str) -> Optional[Dict]:
    """Get distribution config with error handling"""
    try:
        return cloudfront_client.get_distribution_config(Id=dist_id)
    except Exception as e:
        logger.error(f"Error getting config for distribution {dist_id}: {e}")
        return None

def create_check_result(check_type: str, resource: str, status: str, reason: str, account_id: str) -> Dict[str, Any]:
    """Create a standardized check result"""
    return {
        "type": check_type,
        "resource": resource,
        "status": status,
        "reason": reason,
        "region": "global",
        "account": account_id
    }

def check_distribution(dist: Dict, config: Dict, check_type: str, account_id: str,
                      existing_buckets: Optional[set[str]] = None) -> Optional[Dict[str, Any]]:
    """Process a single distribution for a specific check type"""
    dist_id = dist['Id']
    dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
    dist_config = config['DistributionConfig']
    
    try:
        if check_type == "s3_origin":
            return check_s3_origins(dist_id, dist_arn, dist_config, existing_buckets, account_id)
        elif check_type == "encryption":
            return check_encryption(dist_id, dist_arn, dist_config, account_id)
        elif check_type == "geo_restrictions":
            return check_geo_restrictions(dist_id, dist_arn, dist_config, account_id)
        elif check_type == "secure_cipher":
            return check_secure_cipher(dist_id, dist_arn, dist_config, account_id)
        elif check_type == "logging":
            return check_logging(dist_id, dist_arn, dist_config, account_id)
        elif check_type == "non_s3_origins_encryption":
            return check_non_s3_origins_encryption(dist_id, dist_arn, dist_config, account_id)
        elif check_type == "deprecated_ssl_protocol":
            return check_deprecated_ssl_protocol(dist_id, dist_arn, dist_config, account_id)
        elif check_type == "custom_origins_encryption":
            return check_custom_origins_encryption(dist_id, dist_arn, dist_config, account_id)
        return None
    except Exception as e:
        logger.error(f"Error in {check_type} check for distribution {dist_id}: {e}")
        return None

def check_s3_origins(dist_id: str, dist_arn: str, dist_config: Dict, 
                    existing_buckets: Optional[set[str]], account_id: str) -> Dict[str, Any]:
    """Check S3 origins"""
    origins = dist_config.get('Origins', {}).get('Items', [])
    non_existent_buckets = []
    
    if existing_buckets is None:
        logger.warning(f"No S3 bucket information available for distribution {dist_id}")
        return create_check_result(
            "cloudfront_distribution_no_non_existent_s3_origin",
            dist_arn, "unknown", 
            f"{dist_id} S3 origin check skipped - bucket information unavailable",
            account_id
        )
    
    for origin in origins:
        domain_name = origin.get('DomainName', '')
        if '.s3.' in domain_name:
            bucket_name = origin.get('Id', '').split('.s3')[0]
            if not bucket_name:
                bucket_name = domain_name.split('.s3.')[0]
            if bucket_name and bucket_name not in existing_buckets:
                non_existent_buckets.append(bucket_name)
    
    if non_existent_buckets:
        reason = format_bucket_message(dist_id, non_existent_buckets)
        status = "alarm"
    else:
        reason = f"{dist_id} does not point to any non-existent S3 origins."
        status = "ok"
    
    return create_check_result("cloudfront_distribution_no_non_existent_s3_origin",
                             dist_arn, status, reason, account_id)

def check_encryption(dist_id: str, dist_arn: str, dist_config: Dict, account_id: str) -> Dict[str, Any]:
    """Check encryption settings"""
    default_policy = dist_config.get('DefaultCacheBehavior', {}).get('ViewerProtocolPolicy')
    allows_unencrypted = default_policy == 'allow-all'
    
    for behavior in dist_config.get('CacheBehaviors', {}).get('Items', []):
        if behavior.get('ViewerProtocolPolicy') == 'allow-all':
            allows_unencrypted = True
            break
    
    status = "alarm" if allows_unencrypted else "ok"
    reason = f"{dist_id} data {'not ' if allows_unencrypted else ''}encrypted in transit."
    
    return create_check_result("cloudfront_distribution_encryption_in_transit_enabled",
                             dist_arn, status, reason, account_id)

def check_geo_restrictions(dist_id: str, dist_arn: str, dist_config: Dict, account_id: str) -> Dict[str, Any]:
    """Check geo restrictions"""
    restriction_type = dist_config.get('Restrictions', {}).get('GeoRestriction', {}).get('RestrictionType', 'none')
    status = "alarm" if restriction_type == 'none' else "ok"
    reason = f"{dist_id} Geo Restriction {'disabled' if status == 'alarm' else 'enabled'}."
    
    return create_check_result("cloudfront_distribution_geo_restrictions_enabled",
                             dist_arn, status, reason, account_id)

def check_secure_cipher(dist_id: str, dist_arn: str, dist_config: Dict, account_id: str) -> Dict[str, Any]:
    """Check SSL/TLS configuration"""
    origins = dist_config.get('Origins', {}).get('Items', [])
    uses_insecure_cipher = False
    
    for origin in origins:
        custom_origin_config = origin.get('CustomOriginConfig', {})
        if custom_origin_config:
            ssl_protocols = custom_origin_config.get('OriginSslProtocols', {}).get('Items', [])
            if 'TLSv1' in ssl_protocols or 'SSLv3' in ssl_protocols:
                uses_insecure_cipher = True
                break
    
    status = "alarm" if uses_insecure_cipher else "ok"
    reason = f"{dist_id} {'does not use' if uses_insecure_cipher else 'uses'} secure cipher."
    
    return create_check_result("cloudfront_distribution_use_secure_cipher",
                             dist_arn, status, reason, account_id)

def check_logging(dist_id: str, dist_arn: str, dist_config: Dict, account_id: str) -> Dict[str, Any]:
    """Check logging configuration"""
    logging_enabled = dist_config.get('Logging', {}).get('Enabled', False)
    status = "ok" if logging_enabled else "alarm"
    reason = f"{dist_id} logging {'enabled' if logging_enabled else 'disabled'}."
    
    return create_check_result("cloudfront_distribution_logging",
                             dist_arn, status, reason, account_id)

def check_non_s3_origins_encryption(dist_id: str, dist_arn: str, dist_config: Dict, account_id: str) -> Dict[str, Any]:
    """Check encryption for non-S3 origins"""
    origins = dist_config.get('Origins', {}).get('Items', [])
    unencrypted_origins = []
    
    for origin in origins:
        domain_name = origin.get('DomainName', '')
        if '.s3.' not in domain_name:  # Only check non-S3 origins
            custom_origin_config = origin.get('CustomOriginConfig', {})
            if custom_origin_config:
                protocol_policy = custom_origin_config.get('OriginProtocolPolicy')
                if protocol_policy != 'https-only':
                    unencrypted_origins.append(domain_name)
    
    status = "alarm" if unencrypted_origins else "ok"
    reason = (f"{dist_id} has unencrypted non-S3 origins: {', '.join(unencrypted_origins)}" if unencrypted_origins 
             else f"{dist_id} all non-S3 origins use HTTPS.")
    
    return create_check_result("cloudfront_distribution_non_s3_origins_encryption",
                             dist_arn, status, reason, account_id)

def check_deprecated_ssl_protocol(dist_id: str, dist_arn: str, dist_config: Dict, account_id: str) -> Dict[str, Any]:
    """Check for deprecated SSL protocols"""
    origins = dist_config.get('Origins', {}).get('Items', [])
    deprecated_protocols = []
    
    for origin in origins:
        custom_origin_config = origin.get('CustomOriginConfig', {})
        if custom_origin_config:
            ssl_protocols = custom_origin_config.get('OriginSslProtocols', {}).get('Items', [])
            deprecated = [p for p in ssl_protocols if p in ['SSLv3', 'TLSv1', 'TLSv1.1']]
            if deprecated:
                deprecated_protocols.extend(deprecated)
    
    status = "alarm" if deprecated_protocols else "ok"
    reason = (f"{dist_id} uses deprecated protocols: {', '.join(set(deprecated_protocols))}" if deprecated_protocols 
             else f"{dist_id} uses only modern SSL/TLS protocols.")
    
    return create_check_result("cloudfront_distribution_no_deprecated_ssl_protocol",
                             dist_arn, status, reason, account_id)

def check_custom_origins_encryption(dist_id: str, dist_arn: str, dist_config: Dict, account_id: str) -> Dict[str, Any]:
    """Check encryption for custom origins"""
    origins = dist_config.get('Origins', {}).get('Items', [])
    unencrypted_custom_origins = []
    
    for origin in origins:
        custom_origin_config = origin.get('CustomOriginConfig', {})
        if custom_origin_config:  # Only check custom origins
            protocol_policy = custom_origin_config.get('OriginProtocolPolicy')
            if protocol_policy != 'https-only':
                unencrypted_custom_origins.append(origin.get('DomainName', 'Unknown'))
    
    status = "alarm" if unencrypted_custom_origins else "ok"
    reason = (f"{dist_id} has unencrypted custom origins: {', '.join(unencrypted_custom_origins)}" if unencrypted_custom_origins 
             else f"{dist_id} all custom origins use HTTPS.")
    
    return create_check_result("cloudfront_distribution_custom_origins_encryption",
                             dist_arn, status, reason, account_id)

def format_bucket_message(dist_id: str, buckets: List[str]) -> str:
    """Format message for non-existent buckets"""
    if len(buckets) > 2:
        return f"{dist_id} point to non-existent S3 origins {buckets[0]}, {buckets[1]} and {len(buckets) - 2} more."
    elif len(buckets) == 2:
        return f"{dist_id} point to non-existent S3 origins {buckets[0]} and {buckets[1]}."
    return f"{dist_id} point to non-existent S3 origin {buckets[0]}."

def batch_insert_results(results: List[Dict[str, Any]]) -> None:
    """Batch insert results into database"""
    if not results:
        return
        
    try:
        conn = psycopg2.connect(
            host=os.environ.get('POSTGRES_HOST', 'localhost'),
            database=os.environ.get('POSTGRES_DB', 'postgres'),
            user=os.environ.get('POSTGRES_USER', 'chaitras'),
            password=os.environ.get('POSTGRES_PASSWORD', 'post@123')
        )
        cur = conn.cursor()
        
        args = [(r['reason'], r['resource'], r['status']) for r in results if r]
        cur.executemany(
            """
            INSERT INTO aws_project_status (description, resource, status)
            VALUES (%s, %s, %s)
            """,
            args
        )
        
        conn.commit()
    except Exception as e:
        logger.error(f"Database error: {e}")
        if conn:
            conn.rollback()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/check-cloudfront-1')
def check_cloudfront():
    start_time = datetime.now()
    logger.info("Starting CloudFront checks")
    
    try:
        # Initialize AWS clients
        aws = get_aws_clients()
        logger.info("AWS clients initialized")
        
        # Get cached data
        distributions = get_all_distributions(aws.cloudfront)
        existing_buckets = get_all_s3_buckets(aws.s3)
        logger.info(f"Found {len(distributions)} distributions")
        
        if not distributions:
            return jsonify({"error": "No CloudFront distributions found"}), 404
        
        # Prepare distribution configs
        dist_configs = {}
        for dist in distributions:
            config = get_distribution_config(aws.cloudfront, dist['Id'])
            if config:
                dist_configs[dist['Id']] = config
        logger.info(f"Prepared {len(dist_configs)} distribution configs")
        
        # Define check types
        check_types = [
            "s3_origin", "encryption", "geo_restrictions", 
            "secure_cipher", "logging", "non_s3_origins_encryption",
            "deprecated_ssl_protocol", "custom_origins_encryption"
        ]
        
        all_results = []
        with ThreadPoolExecutor(max_workers=min(len(distributions), 10)) as executor:
            future_to_check = {}
            
            # Submit all checks for all distributions
            for dist in distributions:
                if dist['Id'] not in dist_configs:
                    continue
                    
                for check_type in check_types:
                    future = executor.submit(
                        check_distribution,
                        dist,
                        dist_configs[dist['Id']],
                        check_type,
                        aws.account_id,
                        existing_buckets if check_type == "s3_origin" else None
                    )
                    future_to_check[future] = (dist['Id'], check_type)
            
            logger.info(f"Submitted {len(future_to_check)} checks for processing")
            
            # Collect results as they complete
            for future in as_completed(future_to_check):
                dist_id, check_type = future_to_check[future]
                try:
                    result = future.result()
                    if result:
                        all_results.append(result)
                except Exception as e:
                    logger.error(f"Error in {check_type} check for {dist_id}: {e}")
        
        logger.info(f"Collected {len(all_results)} check results")
        
        if all_results:
            # Batch insert results
            try:
                batch_insert_results(all_results)
                logger.info("Successfully inserted results into database")
            except Exception as e:
                logger.error(f"Error inserting results into database: {e}")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        logger.info(f"Completed all checks in {duration} seconds")
        
        return jsonify({
            "results": all_results,
            "total_checks": len(future_to_check),
            "successful_checks": len(all_results),
            "duration_seconds": duration
        })
    
    except Exception as e:
        logger.error(f"Error in check_cloudfront: {e}")
        return jsonify({
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500

if __name__ == '__main__':
    logger.info("Starting server on port 5001...")
    app.run(debug=True, port=5001)
