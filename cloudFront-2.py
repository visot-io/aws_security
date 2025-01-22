import boto3
from flask import Flask, jsonify
import configparser
import psycopg2
from datetime import datetime, timezone
import os
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from logging.config import dictConfig
from functools import lru_cache
from dataclasses import dataclass

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
        logger.info(f"Successfully fetched {len(distributions)} distributions")
        return distributions
    except Exception as e:
        logger.error(f"Error fetching distributions: {e}")
        return []

@lru_cache(maxsize=256)
def get_distribution_config_cached(cloudfront_client, dist_id: str) -> Optional[Dict]:
    """Get and cache distribution config"""
    try:
        return cloudfront_client.get_distribution_config(Id=dist_id)
    except Exception as e:
        logger.error(f"Error getting config for distribution {dist_id}: {e}")
        return None

def get_distribution_config(cloudfront_client, dist_id: str) -> Optional[Dict]:
    """Get distribution config with caching"""
    return get_distribution_config_cached(cloudfront_client, dist_id)

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

def check_sni(cloudfront_client, dist: Dict, account_id: str, config: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
    """Check if SNI is enabled for the distribution"""
    try:
        dist_id = dist['Id']
        dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
        
        if not config:
            return None
            
        viewer_cert = config['DistributionConfig'].get('ViewerCertificate', {})
        ssl_support_method = viewer_cert.get('SSLSupportMethod')
        
        status = "ok" if ssl_support_method == 'sni-only' else "alarm"
        reason = f"{dist_id} {'uses' if status == 'ok' else 'does not use'} SNI-only SSL support method."
        
        return create_check_result("cloudfront_distribution_sni_only",
                                dist_arn, status, reason, account_id)
    except Exception as e:
        logger.error(f"Error checking SNI for distribution {dist_id}: {e}")
        return None

def check_waf(cloudfront_client, dist: Dict, account_id: str, config: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
    """Check if WAF is enabled for the distribution"""
    try:
        dist_id = dist['Id']
        dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
        
        if not config:
            return None
            
        web_acl_id = config['DistributionConfig'].get('WebACLId', '')
        
        status = "ok" if web_acl_id else "alarm"
        reason = f"{dist_id} {'has' if status == 'ok' else 'does not have'} WAF enabled."
        
        return create_check_result("cloudfront_distribution_waf_enabled",
                                dist_arn, status, reason, account_id)
    except Exception as e:
        logger.error(f"Error checking WAF for distribution {dist_id}: {e}")
        return None

def check_origin_failover(cloudfront_client, dist: Dict, account_id: str, config: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
    """Check if origin failover is configured"""
    try:
        dist_id = dist['Id']
        dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
        
        if not config:
            return None
            
        origin_groups = config['DistributionConfig'].get('OriginGroups', {}).get('Items', [])
        
        status = "ok" if origin_groups else "alarm"
        reason = f"{dist_id} {'has' if status == 'ok' else 'does not have'} origin failover configured."
        
        return create_check_result("cloudfront_distribution_origin_failover",
                                dist_arn, status, reason, account_id)
    except Exception as e:
        logger.error(f"Error checking origin failover for distribution {dist_id}: {e}")
        return None

def check_default_root(cloudfront_client, dist: Dict, account_id: str, config: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
    """Check if default root object is configured"""
    try:
        dist_id = dist['Id']
        dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
        
        if not config:
            return None
            
        default_root = config['DistributionConfig'].get('DefaultRootObject', '')
        
        status = "ok" if default_root else "alarm"
        reason = f"{dist_id} {'has' if status == 'ok' else 'does not have'} default root object configured."
        
        return create_check_result("cloudfront_distribution_default_root",
                                dist_arn, status, reason, account_id)
    except Exception as e:
        logger.error(f"Error checking default root for distribution {dist_id}: {e}")
        return None

def check_custom_ssl(cloudfront_client, dist: Dict, account_id: str, config: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
    """Check if custom SSL certificate is used"""
    try:
        dist_id = dist['Id']
        dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
        
        if not config:
            return None
            
        viewer_cert = config['DistributionConfig'].get('ViewerCertificate', {})
        cert_source = viewer_cert.get('CertificateSource', '')
        
        status = "ok" if cert_source == 'acm' else "alarm"
        reason = f"{dist_id} {'uses' if status == 'ok' else 'does not use'} ACM certificate."
        
        return create_check_result("cloudfront_distribution_custom_ssl",
                                dist_arn, status, reason, account_id)
    except Exception as e:
        logger.error(f"Error checking custom SSL for distribution {dist_id}: {e}")
        return None

def check_origin_access_identity(cloudfront_client, dist: Dict, account_id: str, config: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
    """Check if S3 origins use OAI"""
    try:
        dist_id = dist['Id']
        dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
        
        if not config:
            return None
            
        origins = config['DistributionConfig'].get('Origins', {}).get('Items', [])
        s3_origins_without_oai = []
        
        for origin in origins:
            if '.s3.' in origin.get('DomainName', ''):
                if not origin.get('S3OriginConfig', {}).get('OriginAccessIdentity'):
                    s3_origins_without_oai.append(origin.get('Id', 'Unknown'))
        
        status = "ok" if not s3_origins_without_oai else "alarm"
        reason = (f"{dist_id} S3 origins all use OAI." if status == "ok" 
                else f"{dist_id} has S3 origins without OAI: {', '.join(s3_origins_without_oai)}")
        
        return create_check_result("cloudfront_distribution_origin_access_identity",
                                dist_arn, status, reason, account_id)
    except Exception as e:
        logger.error(f"Error checking OAI for distribution {dist_id}: {e}")
        return None

def check_field_level_encryption(cloudfront_client, dist: Dict, account_id: str, config: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
    """Check if field-level encryption is configured"""
    try:
        dist_id = dist['Id']
        dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
        
        if not config:
            return None
            
        default_cache_behavior = config['DistributionConfig'].get('DefaultCacheBehavior', {})
        field_level_encryption_id = default_cache_behavior.get('FieldLevelEncryptionId', '')
        
        status = "ok" if field_level_encryption_id else "alarm"
        reason = f"{dist_id} {'has' if status == 'ok' else 'does not have'} field-level encryption configured."
        
        return create_check_result("cloudfront_distribution_field_level_encryption",
                                dist_arn, status, reason, account_id)
    except Exception as e:
        logger.error(f"Error checking field-level encryption for distribution {dist_id}: {e}")
        return None

def check_tls_version(cloudfront_client, dist: Dict, account_id: str, config: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
    """Check if latest TLS version is used"""
    try:
        dist_id = dist['Id']
        dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
        
        if not config:
            return None
            
        viewer_cert = config['DistributionConfig'].get('ViewerCertificate', {})
        min_protocol_version = viewer_cert.get('MinimumProtocolVersion', '')
        
        status = "ok" if min_protocol_version == 'TLSv1.2_2021' else "alarm"
        reason = f"{dist_id} {'uses' if status == 'ok' else 'does not use'} latest TLS version."
        
        return create_check_result("cloudfront_distribution_tls_version",
                                dist_arn, status, reason, account_id)
    except Exception as e:
        logger.error(f"Error checking TLS version for distribution {dist_id}: {e}")
        return None

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

@app.route('/check-cloudfront-2')
def check_cloudfront():
    """Main route to check CloudFront security"""
    start_time = datetime.now()
    logger.info("Starting CloudFront security checks")
    
    try:
        # Initialize AWS clients
        aws = get_aws_clients()
        logger.info("AWS clients initialized")
        
        # Get all distributions using cached function
        distributions = get_all_distributions(aws.cloudfront)
        
        if not distributions:
            return jsonify({"error": "No CloudFront distributions found"}), 404
        
        # Pre-fetch and cache all distribution configs
        logger.info("Pre-fetching distribution configurations...")
        dist_configs = {}
        for dist in distributions:
            config = get_distribution_config(aws.cloudfront, dist['Id'])
            if config:
                dist_configs[dist['Id']] = config
        logger.info(f"Cached {len(dist_configs)} distribution configurations")
        
        # Define all check functions
        check_functions = [
            check_sni,
            check_waf,
            check_origin_failover,
            check_default_root,
            check_custom_ssl,
            check_origin_access_identity,
            check_field_level_encryption,
            check_tls_version
        ]
        
        # Run all checks in parallel using ThreadPoolExecutor
        all_results = []
        max_workers = min(len(distributions) * len(check_functions), 10)  # Cap at 10 workers
        logger.info(f"Starting parallel execution with {max_workers} workers")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_check = {}
            
            # Submit all checks for all distributions
            for dist in distributions:
                if dist['Id'] not in dist_configs:
                    logger.warning(f"Skipping distribution {dist['Id']} - no config available")
                    continue
                    
                config = dist_configs[dist['Id']]
                
                for check_fn in check_functions:
                    future = executor.submit(
                        check_fn,
                        aws.cloudfront,
                        dist,
                        aws.account_id,
                        config
                    )
                    future_to_check[future] = (dist['Id'], check_fn.__name__)
            
            # Collect results as they complete
            for future in as_completed(future_to_check):
                dist_id, check_name = future_to_check[future]
                try:
                    result = future.result()
                    if result:
                        all_results.append(result)
                        logger.debug(f"Completed {check_name} for distribution {dist_id}")
                except Exception as e:
                    logger.error(f"Error in {check_name} for distribution {dist_id}: {e}")
                    
        logger.info(f"Completed {len(all_results)} checks successfully")
        
        # Insert results into database
        if all_results: 
            batch_insert_results(all_results)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        logger.info(f"Completed all checks in {duration} seconds")
        
        return jsonify({
            "results": all_results,
            "total_checks": len(distributions) * 8,  # 8 checks per distribution
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
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.run(debug=True, port=5001, use_reloader=False)
