from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import boto3
import os

app = FastAPI()

# In-memory storage for check results
class CheckResult(BaseModel):
    type: str
    resource: str
    status: str
    reason: str
    region: Optional[str] = None
    account: Optional[str] = None
    timestamp: Optional[datetime] = None

def check_s3_origin_existence(dist: Dict[str, Any], dist_config: Dict[str, Any], s3_client: Any, account_id: str) -> CheckResult:
    """Check if CloudFront distribution points to non-existent S3 buckets"""
    dist_id = dist['Id']
    dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
    origins = dist_config.get('Origins', {}).get('Items', [])
    non_existent_buckets = []
    
    for origin in origins:
        domain_name = origin.get('DomainName', '')
        if '.s3.' in domain_name:
            bucket_name = domain_name.split('.s3.')[0]
            try:
                s3_client.head_bucket(Bucket=bucket_name)
            except Exception:
                non_existent_buckets.append(bucket_name)
    
    return CheckResult(
        type="cloudfront_distribution_s3_origin",
        resource=dist_arn,
        status='alarm' if non_existent_buckets else 'ok',
        reason=f"{dist_id} {'points to non-existent S3 buckets: ' + ', '.join(non_existent_buckets) if non_existent_buckets else 'only points to existing S3 buckets'}.",
        region="global",
        account=account_id
    )

def check_encryption_in_transit(dist: Dict[str, Any], dist_config: Dict[str, Any], account_id: str) -> CheckResult:
    """Check if CloudFront distribution enforces HTTPS"""
    dist_id = dist['Id']
    dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
    viewer_protocol_policy = dist_config.get('DefaultCacheBehavior', {}).get('ViewerProtocolPolicy', '')
    cache_behaviors = dist_config.get('CacheBehaviors', {}).get('Items', [])
    unencrypted_behaviors = []
    
    if viewer_protocol_policy not in ['https-only', 'redirect-to-https']:
        unencrypted_behaviors.append('default')
    
    for behavior in cache_behaviors:
        if behavior.get('ViewerProtocolPolicy') not in ['https-only', 'redirect-to-https']:
            unencrypted_behaviors.append(behavior.get('PathPattern', 'unknown'))
    
    return CheckResult(
        type="cloudfront_distribution_encryption_in_transit",
        resource=dist_arn,
        status='alarm' if unencrypted_behaviors else 'ok',
        reason=f"{dist_id} {'has unencrypted traffic allowed for paths: ' + ', '.join(unencrypted_behaviors) if unencrypted_behaviors else 'enforces HTTPS for all paths'}.",
        region="global",
        account=account_id
    )

def check_ssl_protocol(dist: Dict[str, Any], dist_config: Dict[str, Any], account_id: str) -> CheckResult:
    """Check if CloudFront distribution uses deprecated SSL/TLS protocols"""
    dist_id = dist['Id']
    dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
    viewer_cert = dist_config.get('ViewerCertificate', {})
    minimum_protocol_version = viewer_cert.get('MinimumProtocolVersion', '')
    deprecated_protocols = ['SSLv3', 'TLSv1', 'TLSv1_2016', 'TLSv1.1_2016']
    
    return CheckResult(
        type="cloudfront_distribution_ssl_protocol",
        resource=dist_arn,
        status='alarm' if minimum_protocol_version in deprecated_protocols else 'ok',
        reason=f"{dist_id} uses {'deprecated' if minimum_protocol_version in deprecated_protocols else 'current'} SSL/TLS protocol version: {minimum_protocol_version}.",
        region="global",
        account=account_id
    )

def check_secure_cipher(dist: Dict[str, Any], dist_config: Dict[str, Any], account_id: str) -> CheckResult:
    """Check if CloudFront distribution uses secure cipher suites"""
    dist_id = dist['Id']
    dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
    viewer_cert = dist_config.get('ViewerCertificate', {})
    security_policy = viewer_cert.get('MinimumProtocolVersion', '')
    secure_policies = ['TLSv1.2_2019', 'TLSv1.2_2021']
    
    return CheckResult(
        type="cloudfront_distribution_secure_cipher",
        resource=dist_arn,
        status='ok' if security_policy in secure_policies else 'alarm',
        reason=f"{dist_id} uses {'secure' if security_policy in secure_policies else 'potentially insecure'} security policy: {security_policy}.",
        region="global",
        account=account_id
    )

def check_custom_origins_encryption(dist: Dict[str, Any], dist_config: Dict[str, Any], account_id: str) -> CheckResult:
    """Check if CloudFront distribution's custom origins use encryption"""
    dist_id = dist['Id']
    dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
    origins = dist_config.get('Origins', {}).get('Items', [])
    custom_origins = [o for o in origins if not o.get('DomainName', '').endswith('.s3.amazonaws.com')]
    unencrypted_custom_origins = []
    
    for origin in custom_origins:
        custom_origin_config = origin.get('CustomOriginConfig', {})
        if not custom_origin_config.get('HTTPSPort'):
            unencrypted_custom_origins.append(origin.get('DomainName', 'unknown'))
    
    return CheckResult(
        type="cloudfront_distribution_custom_origins_encryption",
        resource=dist_arn,
        status='alarm' if unencrypted_custom_origins else 'ok',
        reason=f"{dist_id} custom origins {'not encrypted in transit: ' + ', '.join(unencrypted_custom_origins) if unencrypted_custom_origins else 'properly encrypted'}.",
        region="global",
        account=account_id
    )

def check_non_s3_origins_encryption(dist: Dict[str, Any], dist_config: Dict[str, Any], account_id: str) -> CheckResult:
    """Check if CloudFront distribution's non-S3 origins use HTTPS"""
    dist_id = dist['Id']
    dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
    origins = dist_config.get('Origins', {}).get('Items', [])
    non_s3_origins = [o for o in origins if '.s3.' not in o.get('DomainName', '')]
    unencrypted_non_s3 = []
    
    for origin in non_s3_origins:
        origin_protocol = origin.get('CustomOriginConfig', {}).get('OriginProtocolPolicy', '')
        if origin_protocol != 'https-only':
            unencrypted_non_s3.append(origin.get('DomainName', 'unknown'))
    
    return CheckResult(
        type="cloudfront_distribution_non_s3_origins_encryption",
        resource=dist_arn,
        status='alarm' if unencrypted_non_s3 else 'ok',
        reason=f"{dist_id} non-S3 origins {'not using HTTPS-only: ' + ', '.join(unencrypted_non_s3) if unencrypted_non_s3 else 'using HTTPS-only'}.",
        region="global",
        account=account_id
    )

def check_logging(dist: Dict[str, Any], dist_config: Dict[str, Any], account_id: str) -> CheckResult:
    """Check if CloudFront distribution has logging enabled"""
    dist_id = dist['Id']
    dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
    logging_config = dist_config.get('Logging', {})
    logging_enabled = logging_config.get('Enabled', False)
    
    return CheckResult(
        type="cloudfront_distribution_logging",
        resource=dist_arn,
        status='ok' if logging_enabled else 'alarm',
        reason=f"{dist_id} logging {'enabled' if logging_enabled else 'disabled'}.",
        region="global",
        account=account_id
    )

def check_geo_restrictions(dist: Dict[str, Any], dist_config: Dict[str, Any], account_id: str) -> CheckResult:
    """Check if CloudFront distribution has geo restrictions enabled"""
    dist_id = dist['Id']
    dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
    geo_restriction = dist_config.get('Restrictions', {}).get('GeoRestriction', {})
    
    return CheckResult(
        type="cloudfront_distribution_geo_restrictions",
        resource=dist_arn,
        status='alarm' if geo_restriction.get('RestrictionType') == 'none' else 'ok',
        reason=f"{dist_id} Geo Restriction {'disabled' if geo_restriction.get('RestrictionType') == 'none' else 'enabled'}.",
        region="global",
        account=account_id
    )

# Disable CORS. Do not remove this for full-stack development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# AWS CloudFront security check endpoints

@app.get("/api/aws/test")
async def test_aws_connection():
    try:
        # Initialize STS client to test AWS credentials
        sts = boto3.client(
            'sts',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID_AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY_AWS_SECRET_ACCESS_KEY'),
            region_name=os.environ.get('AWS_DEFAULT_REGION_AWS_DEFAULT_REGION')
        )
        identity = sts.get_caller_identity()
        return {
            "status": "ok",
            "account": identity['Account'],
            "arn": identity['Arn'],
            "credentials": {
                "access_key_present": bool(os.environ.get('AWS_ACCESS_KEY_ID_AWS_ACCESS_KEY_ID')),
                "secret_key_present": bool(os.environ.get('AWS_SECRET_ACCESS_KEY_AWS_SECRET_ACCESS_KEY')),
                "region_present": bool(os.environ.get('AWS_DEFAULT_REGION_AWS_DEFAULT_REGION'))
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"AWS Connection Error: {str(e)}"
        )

@app.get("/api/cloudfront/comprehensive-checks", response_model=List[CheckResult])
async def get_cloudfront_comprehensive_checks():
    try:
        print("Starting comprehensive checks...")
        # Initialize AWS clients
        session = boto3.Session(
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID_AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY_AWS_SECRET_ACCESS_KEY'),
            region_name=os.environ.get('AWS_DEFAULT_REGION_AWS_DEFAULT_REGION')
        )
        
        cloudfront = session.client('cloudfront')
        s3 = session.client('s3')
        sts = session.client('sts')
        
        print("Getting AWS account ID...")
        # Get AWS account ID
        account_id = sts.get_caller_identity()['Account']
        
        print("Listing CloudFront distributions...")
        # Get all distributions with pagination
        distributions = []
        paginator = cloudfront.get_paginator('list_distributions')
        for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions.extend(page['DistributionList']['Items'])
        
        print(f"Found {len(distributions)} distributions")
        if not distributions:
            return []
            
        # Process all distributions
        results = []
        print("Processing all distributions...")
        for dist in distributions:
            dist_id = dist['Id']
            dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"
            
            # Get detailed distribution config
            print(f"Getting config for distribution {dist_id}...")
            config = cloudfront.get_distribution_config(Id=dist_id)
            dist_config = config['DistributionConfig']
            
            # Run all security checks for this distribution
            print(f"Running security checks for distribution {dist_id}...")
            results.extend([
                check_s3_origin_existence(dist, dist_config, s3, account_id),
                check_encryption_in_transit(dist, dist_config, account_id),
                check_ssl_protocol(dist, dist_config, account_id),
                check_secure_cipher(dist, dist_config, account_id),
                check_custom_origins_encryption(dist, dist_config, account_id),
                check_non_s3_origins_encryption(dist, dist_config, account_id),
                check_logging(dist, dist_config, account_id),
                check_geo_restrictions(dist, dist_config, account_id)
            ])
        
        total_checks = len(results)
        print(f"Completed {total_checks} checks across {len(distributions)} distributions")
        print(f"Expected checks: {len(distributions) * 8}, Actual checks: {total_checks}")
        return results
    except Exception as e:
        error_msg = f"Error: {str(e)}\n"
        error_msg += f"AWS Access Key present: {bool(os.environ.get('AWS_ACCESS_KEY_ID_AWS_ACCESS_KEY_ID'))}\n"
        error_msg += f"AWS Secret Key present: {bool(os.environ.get('AWS_SECRET_ACCESS_KEY_AWS_SECRET_ACCESS_KEY'))}\n"
        error_msg += f"AWS Region present: {bool(os.environ.get('AWS_DEFAULT_REGION_AWS_DEFAULT_REGION'))}"
        print(error_msg)  # For server logs
        raise HTTPException(status_code=500, detail=error_msg)

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
