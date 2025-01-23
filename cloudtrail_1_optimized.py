import boto3
from flask import Flask, jsonify
import configparser
from datetime import datetime, timezone
import json
import os
import logging
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from dataclasses import dataclass
from db_utils import batch_insert_results

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cloudtrail_checks.log')
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AWSClients:
    """Class to hold AWS client instances"""
    session: boto3.Session
    cloudtrail: Any
    s3: Any
    sts: Any
    account_id: str

def log_error(error: Exception, context: str, extra_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Centralized error logging function"""
    error_msg = f"Error in {context}: {str(error)}"
    if extra_info:
        error_msg += f" | Additional info: {extra_info}"
    logger.error(error_msg)
    return {
        "error": str(error),
        "context": context,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "extra_info": extra_info
    }

@lru_cache(maxsize=1)
def get_all_trails(cloudtrail_client) -> List[Dict]:
    """Cache and return all CloudTrail trails"""
    try:
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        logger.info(f"Cached {len(trails)} CloudTrail trails")
        return trails
    except Exception as e:
        logger.error(f"Error describing trails: {e}")
        return []

@lru_cache(maxsize=1)
def get_all_s3_buckets(s3_client) -> set[str]:
    """Cache and return all S3 bucket names"""
    try:
        response = s3_client.list_buckets()
        buckets = {bucket['Name'] for bucket in response['Buckets']}
        logger.info(f"Cached {len(buckets)} S3 buckets")
        return buckets
    except Exception as e:
        logger.error(f"Error listing S3 buckets: {e}")
        return set()

@lru_cache(maxsize=256)
def get_trail_status_cached(cloudtrail_client, trail_arn: str) -> Optional[Dict]:
    """Get and cache trail status"""
    try:
        status = cloudtrail_client.get_trail_status(Name=trail_arn)
        logger.debug(f"Cached status for trail {trail_arn}")
        return status
    except Exception as e:
        logger.error(f"Error getting status for trail {trail_arn}: {e}")
        return None

@lru_cache(maxsize=256)
def get_event_selectors_cached(cloudtrail_client, trail_arn: str) -> Optional[Dict]:
    """Get and cache event selectors for a trail"""
    try:
        selectors = cloudtrail_client.get_event_selectors(TrailName=trail_arn)
        logger.debug(f"Cached event selectors for trail {trail_arn}")
        return selectors
    except Exception as e:
        logger.error(f"Error getting event selectors for trail {trail_arn}: {e}")
        return None

def get_aws_clients() -> AWSClients:
    """Create and cache AWS client instances"""
    try:
        # Load configuration
        config = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini')
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found at {config_path}")
        
        config.read(config_path)
        logger.info(f"Reading AWS credentials from: {config_path}")
        
        try:
            aws_key = config['AWS']['AWS_ACCESS_KEY_ID']
            aws_secret = config['AWS']['AWS_SECRET_ACCESS_KEY']
            aws_region = config['AWS'].get('AWS_REGION', 'us-east-1')
        except KeyError as e:
            raise ValueError(f"Missing AWS credentials in config.ini: {e}")
            
        if not aws_key or not aws_secret:
            raise ValueError("Empty AWS credentials in config.ini")
            
        session = boto3.Session(
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
            region_name=aws_region
        )
        
        cloudtrail = session.client('cloudtrail')
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        
        logger.info("Successfully initialized AWS clients")
        return AWSClients(session, cloudtrail, s3, sts, account_id)
    except Exception as e:
        error = log_error(e, "initializing AWS clients")
        raise ValueError(error["error"])

def create_check_result(check_type: str, resource: str, status: str, reason: str, account_id: str, region: str = "global") -> Dict[str, Any]:
    """Create a standardized check result"""
    return {
        "type": check_type,
        "resource": resource,
        "status": status,
        "reason": reason,
        "region": region,
        "account": account_id
    }

def check_cloudtrail_bucket_public_access(cloudtrail_client, s3_client, account_id: str, trails: List[Dict], buckets: set[str]) -> List[Dict[str, Any]]:
    """Check if CloudTrail buckets have public access"""
    check_name = "cloudtrail_bucket_public_access"
    logger.info(f"Starting {check_name} check")
    start_time = datetime.now()
    
    try:
        results = []
        for trail in trails:
            try:
                bucket_name = trail.get('S3BucketName')
                if not bucket_name or bucket_name not in buckets:
                    logger.debug(f"Skipping bucket {bucket_name} - not found in available buckets")
                    continue

                try:
                    bucket_region = s3_client.get_bucket_location(Bucket=bucket_name)
                    region = bucket_region.get('LocationConstraint', 'us-east-1') or 'us-east-1'
                except Exception as e:
                    log_error(e, f"getting location for bucket {bucket_name}", {
                        "bucket": bucket_name,
                        "check": check_name
                    })
                    region = "us-east-1"

                try:
                    public_access = s3_client.get_public_access_block(Bucket=bucket_name)
                    block_config = public_access['PublicAccessBlockConfiguration']
                    
                    is_public = not all([
                        block_config.get('BlockPublicAcls', False),
                        block_config.get('BlockPublicPolicy', False),
                        block_config.get('IgnorePublicAcls', False),
                        block_config.get('RestrictPublicBuckets', False)
                    ])
                    logger.debug(f"Public access check for {bucket_name}: {block_config}")
                except Exception as e:
                    log_error(e, f"checking public access for bucket {bucket_name}", {
                        "bucket": bucket_name,
                        "check": check_name,
                        "action": "assuming public access"
                    })
                    is_public = True  # Assume public if we can't verify

                status = "alarm" if is_public else "ok"
                reason = f"CloudTrail bucket {bucket_name} {'has' if is_public else 'does not have'} public access."

                results.append(create_check_result(
                    check_name,
                    f"arn:aws:s3:::{bucket_name}",
                    status,
                    reason,
                    account_id,
                    region
                ))
                logger.debug(f"Completed check for bucket {bucket_name} with status {status}")

            except Exception as e:
                log_error(e, f"processing trail {trail.get('Name')}", {
                    "trail": trail.get('Name'),
                    "check": check_name,
                    "account": account_id
                })
                continue

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Completed {check_name} check in {duration:.2f} seconds - processed {len(results)} buckets")
        return results

    except Exception as e:
        error_info = log_error(e, f"running {check_name} check", {
            "total_trails": len(trails),
            "total_buckets": len(buckets),
            "account": account_id
        })
        return []

def check_cloudtrail_multi_region_read_write(cloudtrail_client, account_id: str, trails: List[Dict]) -> Dict[str, Any]:
    """Check if CloudTrail has multi-region read/write events enabled"""
    check_name = "cloudtrail_multi_region_read_write"
    logger.info(f"Starting {check_name} check")
    start_time = datetime.now()
    
    try:
        multi_region_trail_found = False
        read_write_enabled = False
        trail_name = "No multi-region trail found"
        trails_checked = 0

        for trail in trails:
            if not trail.get('IsMultiRegionTrail'):
                logger.debug(f"Skipping non-multi-region trail: {trail.get('Name')}")
                continue

            multi_region_trail_found = True
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', '')
            trails_checked += 1

            try:
                event_selectors = get_event_selectors_cached(cloudtrail_client, trail_arn)
                if not event_selectors:
                    logger.warning(f"No event selectors found for trail {trail_name}")
                    continue

                for selector in event_selectors.get('EventSelectors', []):
                    read_write_type = selector.get('ReadWriteType')
                    logger.debug(f"Checking selector ReadWriteType: {read_write_type} for trail {trail_name}")
                    if read_write_type in ['All', 'WriteOnly']:
                        read_write_enabled = True
                        logger.info(f"Found enabled read/write events in trail {trail_name}")
                        break

                if read_write_enabled:
                    break

            except Exception as e:
                log_error(e, f"getting event selectors for trail {trail_name}", {
                    "trail": trail_name,
                    "trail_arn": trail_arn,
                    "check": check_name,
                    "account": account_id
                })
                continue

        status = "ok" if multi_region_trail_found and read_write_enabled else "alarm"
        reason = (f"{trail_name} has multi-region read/write events enabled." if status == "ok"
                else "No multi-region trail with read/write events found.")

        result = create_check_result(
            check_name,
            f"arn:aws:cloudtrail:{account_id}:trail/{trail_name}",
            status,
            reason,
            account_id
        )

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Completed {check_name} check in {duration:.2f} seconds - checked {trails_checked} trails")
        return result

    except Exception as e:
        error_info = log_error(e, f"running {check_name} check", {
            "total_trails": len(trails),
            "account": account_id,
            "multi_region_found": multi_region_trail_found
        })
        return create_check_result(
            check_name,
            f"arn:aws:cloudtrail:{account_id}:trail/error",
            "error",
            str(e),
            account_id
        )

def check_cloudtrail_multi_region_trail(cloudtrail_client, account_id: str, trails: List[Dict]) -> Dict[str, Any]:
    """Check if CloudTrail has at least one multi-region trail"""
    try:
        multi_region_trail = None
        for trail in trails:
            if trail.get('IsMultiRegionTrail'):
                trail_status = get_trail_status_cached(cloudtrail_client, trail['TrailARN'])
                if trail_status and trail_status.get('IsLogging'):
                    multi_region_trail = trail
                    break

        if multi_region_trail:
            status = "ok"
            trail_name = multi_region_trail.get('Name', 'Unknown')
            reason = f"Multi-region trail {trail_name} is enabled and logging."
        else:
            status = "alarm"
            reason = "No enabled multi-region trail found."
            trail_name = "no-multi-region-trail"

        return create_check_result(
            "cloudtrail_multi_region_trail",
            f"arn:aws:cloudtrail:{account_id}:trail/{trail_name}",
            status,
            reason,
            account_id
        )

    except Exception as e:
        logger.error(f"Error checking CloudTrail multi-region trail: {e}")
        return create_check_result(
            "cloudtrail_multi_region_trail",
            f"arn:aws:cloudtrail:{account_id}:trail/error",
            "error",
            str(e),
            account_id
        )

def check_cloudtrail_s3_logging(cloudtrail_client, s3_client, account_id: str, trails: List[Dict], buckets: set[str]) -> List[Dict[str, Any]]:
    """Check if CloudTrail S3 buckets have logging enabled"""
    try:
        results = []
        for trail in trails:
            try:
                bucket_name = trail.get('S3BucketName')
                if not bucket_name or bucket_name not in buckets:
                    continue

                try:
                    bucket_region = s3_client.get_bucket_location(Bucket=bucket_name)
                    region = bucket_region.get('LocationConstraint', 'us-east-1') or 'us-east-1'
                except Exception as e:
                    logger.error(f"Error getting location for bucket {bucket_name}: {e}")
                    region = "us-east-1"

                try:
                    logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
                    logging_enabled = bool(logging_config.get('LoggingEnabled'))
                except Exception as e:
                    logger.warning(f"Could not get logging config for {bucket_name}: {e}")
                    logging_enabled = False

                status = "ok" if logging_enabled else "alarm"
                reason = f"CloudTrail bucket {bucket_name} {'has' if logging_enabled else 'does not have'} logging enabled."

                results.append(create_check_result(
                    "cloudtrail_s3_logging",
                    f"arn:aws:s3:::{bucket_name}",
                    status,
                    reason,
                    account_id,
                    region
                ))

            except Exception as e:
                logger.error(f"Error processing trail {trail.get('Name')}: {e}")
                continue

        return results

    except Exception as e:
        logger.error(f"Error checking CloudTrail S3 logging: {e}")
        return []

def check_cloudtrail_s3_data_events(cloudtrail_client, s3_client, account_id: str, trails: List[Dict], buckets: set[str]) -> List[Dict[str, Any]]:
    """Check if CloudTrail has S3 data events enabled"""
    try:
        results = []
        buckets_with_data_events = set()

        # Check each trail for S3 data events
        for trail in trails:
            if not trail.get('IsMultiRegionTrail'):
                continue

            try:
                event_selectors = get_event_selectors_cached(cloudtrail_client, trail['TrailARN'])
                if not event_selectors:
                    continue

                for selector in event_selectors.get('EventSelectors', []):
                    for data_resource in selector.get('DataResources', []):
                        if data_resource.get('Type') == 'AWS::S3::Object':
                            for value in data_resource.get('Values', []):
                                if value == 'arn:aws:s3':
                                    # All buckets are covered
                                    buckets_with_data_events.update(buckets)
                                else:
                                    # Extract bucket name from ARN
                                    bucket_arn = value.split('/', 1)[0]
                                    bucket_name = bucket_arn.split(':')[-1]
                                    buckets_with_data_events.add(bucket_name)

            except Exception as e:
                logger.error(f"Error getting event selectors for trail {trail['Name']}: {e}")
                continue

        # Generate results for each bucket
        for bucket_name in buckets:
            try:
                bucket_region = s3_client.get_bucket_location(Bucket=bucket_name)
                region = bucket_region.get('LocationConstraint', 'us-east-1') or 'us-east-1'
            except Exception as e:
                logger.error(f"Error getting location for bucket {bucket_name}: {e}")
                region = "us-east-1"

            status = "ok" if bucket_name in buckets_with_data_events else "alarm"
            reason = f"{bucket_name} data events logging {'enabled' if status == 'ok' else 'disabled'}."

            results.append(create_check_result(
                "cloudtrail_s3_data_events",
                f"arn:aws:s3:::{bucket_name}",
                status,
                reason,
                account_id,
                region
            ))

        return results

    except Exception as e:
        logger.error(f"Error checking CloudTrail S3 data events: {e}")
        return []

def check_cloudtrail_s3_object_read_events(cloudtrail_client, s3_client, account_id: str, trails: List[Dict], buckets: set[str]) -> List[Dict[str, Any]]:
    """Check if CloudTrail has S3 object-level read events enabled"""
    check_name = "cloudtrail_s3_object_read_events"
    logger.info(f"Starting {check_name} check")
    start_time = datetime.now()
    
    try:
        buckets_with_read_events = set()
        trails_checked = 0
        buckets_checked = 0

        # Check each trail for S3 read events
        for trail in trails:
            trail_name = trail.get('Name', 'Unknown')
            if not trail.get('IsMultiRegionTrail'):
                logger.debug(f"Skipping non-multi-region trail: {trail_name}")
                continue

            trails_checked += 1
            try:
                event_selectors = get_event_selectors_cached(cloudtrail_client, trail['TrailARN'])
                if not event_selectors:
                    logger.warning(f"No event selectors found for trail {trail_name}")
                    continue

                for selector in event_selectors.get('EventSelectors', []):
                    read_write_type = selector.get('ReadWriteType')
                    logger.debug(f"Checking selector ReadWriteType: {read_write_type} for trail {trail_name}")
                    if read_write_type not in ['ReadOnly', 'All']:
                        continue

                    for data_resource in selector.get('DataResources', []):
                        if data_resource.get('Type') == 'AWS::S3::Object':
                            for value in data_resource.get('Values', []):
                                if value == 'arn:aws:s3':
                                    logger.info(f"Found wildcard S3 read events in trail {trail_name}")
                                    buckets_with_read_events.update(buckets)
                                else:
                                    bucket_arn = value.split('/', 1)[0]
                                    bucket_name = bucket_arn.split(':')[-1]
                                    buckets_with_read_events.add(bucket_name)
                                    logger.debug(f"Found read events for bucket {bucket_name} in trail {trail_name}")

            except Exception as e:
                log_error(e, f"getting event selectors for trail {trail_name}", {
                    "trail": trail_name,
                    "trail_arn": trail.get('TrailARN'),
                    "check": check_name,
                    "account": account_id
                })
                continue

        results = []
        for bucket_name in buckets:
            buckets_checked += 1
            try:
                bucket_region = s3_client.get_bucket_location(Bucket=bucket_name)
                region = bucket_region.get('LocationConstraint', 'us-east-1') or 'us-east-1'
            except Exception as e:
                log_error(e, f"getting location for bucket {bucket_name}", {
                    "bucket": bucket_name,
                    "check": check_name,
                    "account": account_id
                })
                region = "us-east-1"

            status = "ok" if bucket_name in buckets_with_read_events else "alarm"
            reason = f"{bucket_name} object-level read events logging {'enabled' if status == 'ok' else 'disabled'}."
            logger.debug(f"Bucket {bucket_name} read events status: {status}")

            results.append(create_check_result(
                check_name,
                f"arn:aws:s3:::{bucket_name}",
                status,
                reason,
                account_id,
                region
            ))

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"Completed {check_name} check in {duration:.2f} seconds - "
            f"checked {trails_checked} trails and {buckets_checked} buckets"
        )
        return results

    except Exception as e:
        error_info = log_error(e, f"running {check_name} check", {
            "total_trails": len(trails),
            "total_buckets": len(buckets),
            "trails_checked": trails_checked,
            "buckets_checked": buckets_checked,
            "account": account_id
        })
        return []

def check_cloudtrail_s3_object_write_events(cloudtrail_client, s3_client, account_id: str, trails: List[Dict], buckets: set[str]) -> List[Dict[str, Any]]:
    """Check if CloudTrail has S3 object-level write events enabled"""
    check_name = "cloudtrail_s3_object_write_events"
    logger.info(f"Starting {check_name} check")
    start_time = datetime.now()
    
    try:
        buckets_with_write_events = set()
        trails_checked = 0
        buckets_checked = 0

        # Check each trail for S3 write events
        for trail in trails:
            trail_name = trail.get('Name', 'Unknown')
            if not trail.get('IsMultiRegionTrail'):
                logger.debug(f"Skipping non-multi-region trail: {trail_name}")
                continue

            trails_checked += 1
            try:
                event_selectors = get_event_selectors_cached(cloudtrail_client, trail['TrailARN'])
                if not event_selectors:
                    logger.warning(f"No event selectors found for trail {trail_name}")
                    continue

                # Check standard event selectors
                for selector in event_selectors.get('EventSelectors', []):
                    read_write_type = selector.get('ReadWriteType')
                    logger.debug(f"Checking selector ReadWriteType: {read_write_type} for trail {trail_name}")
                    if read_write_type not in ['WriteOnly', 'All']:
                        continue

                    for data_resource in selector.get('DataResources', []):
                        if data_resource.get('Type') == 'AWS::S3::Object':
                            for value in data_resource.get('Values', []):
                                if value == 'arn:aws:s3':
                                    logger.info(f"Found wildcard S3 write events in trail {trail_name}")
                                    buckets_with_write_events.update(buckets)
                                else:
                                    bucket_arn = value.split('/', 1)[0]
                                    bucket_name = bucket_arn.split(':')[-1]
                                    buckets_with_write_events.add(bucket_name)
                                    logger.debug(f"Found write events for bucket {bucket_name} in trail {trail_name}")

                # Check advanced event selectors
                for selector in event_selectors.get('AdvancedEventSelectors', []):
                    has_s3_object = False
                    has_write = False
                    
                    for field_selector in selector.get('FieldSelectors', []):
                        if (field_selector.get('Field') == 'resources.type' and 
                            'AWS::S3::Object' in field_selector.get('Equals', [])):
                            has_s3_object = True
                            logger.debug(f"Found S3 object type in advanced selector for trail {trail_name}")
                        if (field_selector.get('Field') == 'readOnly' and 
                            'false' in field_selector.get('Equals', [])):
                            has_write = True
                            logger.debug(f"Found write events in advanced selector for trail {trail_name}")
                    
                    if has_s3_object and has_write:
                        logger.info(f"Found advanced S3 write events in trail {trail_name}")
                        buckets_with_write_events.update(buckets)

            except Exception as e:
                log_error(e, f"getting event selectors for trail {trail_name}", {
                    "trail": trail_name,
                    "trail_arn": trail.get('TrailARN'),
                    "check": check_name,
                    "account": account_id
                })
                continue

        results = []
        for bucket_name in buckets:
            buckets_checked += 1
            try:
                bucket_region = s3_client.get_bucket_location(Bucket=bucket_name)
                region = bucket_region.get('LocationConstraint', 'us-east-1') or 'us-east-1'
            except Exception as e:
                log_error(e, f"getting location for bucket {bucket_name}", {
                    "bucket": bucket_name,
                    "check": check_name,
                    "account": account_id
                })
                region = "us-east-1"

            status = "ok" if bucket_name in buckets_with_write_events else "alarm"
            reason = f"{bucket_name} object-level write events logging {'enabled' if status == 'ok' else 'disabled'}."
            logger.debug(f"Bucket {bucket_name} write events status: {status}")

            results.append(create_check_result(
                check_name,
                f"arn:aws:s3:::{bucket_name}",
                status,
                reason,
                account_id,
                region
            ))

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"Completed {check_name} check in {duration:.2f} seconds - "
            f"checked {trails_checked} trails and {buckets_checked} buckets"
        )
        return results

    except Exception as e:
        error_info = log_error(e, f"running {check_name} check", {
            "total_trails": len(trails),
            "total_buckets": len(buckets),
            "trails_checked": trails_checked,
            "buckets_checked": buckets_checked,
            "account": account_id
        })
        return []

def check_cloudtrail_logs_integration(cloudtrail_client, account_id: str, trails: List[Dict]) -> List[Dict[str, Any]]:
    """Check CloudTrail logs integration with CloudWatch Logs"""
    check_name = "cloudtrail_logs_integration"
    logger.info(f"Starting {check_name} check")
    start_time = datetime.now()
    
    try:
        results = []
        trails_checked = 0
        trails_with_logs = 0
        
        for trail in trails:
            try:
                trail_name = trail.get('Name', 'Unknown')
                trail_arn = trail.get('TrailARN', '')
                trails_checked += 1
                
                logger.debug(f"Checking CloudWatch Logs integration for trail: {trail_name}")
                
                # Check if CloudWatch Logs integration is configured
                cloudwatch_logs_enabled = bool(
                    trail.get('CloudWatchLogsLogGroupArn') and
                    trail.get('CloudWatchLogsRoleArn')
                )
                
                if cloudwatch_logs_enabled:
                    logger.debug(f"Trail {trail_name} has CloudWatch Logs configuration")
                    log_group = trail.get('CloudWatchLogsLogGroupArn', '').split(':')[-1]
                    logger.debug(f"Using log group: {log_group}")
                else:
                    logger.debug(f"Trail {trail_name} missing CloudWatch Logs configuration")

                # Get trail status to check if it's actively logging
                trail_status = get_trail_status_cached(cloudtrail_client, trail_arn)
                is_logging = trail_status.get('IsLogging', False) if trail_status else False
                
                if not trail_status:
                    logger.warning(f"Could not get status for trail {trail_name}")
                elif not is_logging:
                    logger.warning(f"Trail {trail_name} is not actively logging")

                if cloudwatch_logs_enabled and is_logging:
                    status = "ok"
                    reason = f"{trail_name} has CloudWatch Logs integration enabled and is logging."
                    trails_with_logs += 1
                    logger.debug(f"Trail {trail_name} passed CloudWatch Logs check")
                else:
                    status = "alarm"
                    reason = f"{trail_name} {'is not logging' if not is_logging else 'has no CloudWatch Logs integration'}."
                    logger.warning(f"Trail {trail_name} failed CloudWatch Logs check: {reason}")

                results.append(create_check_result(
                    check_name,
                    trail_arn,
                    status,
                    reason,
                    account_id
                ))

            except Exception as e:
                log_error(e, f"processing trail {trail_name}", {
                    "trail": trail_name,
                    "trail_arn": trail_arn,
                    "check": check_name,
                    "account": account_id
                })
                continue

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"Completed {check_name} check in {duration:.2f} seconds - "
            f"checked {trails_checked} trails, {trails_with_logs} with CloudWatch Logs enabled"
        )
        return results

    except Exception as e:
        error_info = log_error(e, f"running {check_name} check", {
            "total_trails": len(trails),
            "trails_checked": trails_checked,
            "account": account_id
        })
        return []

app = Flask(__name__)

@app.route('/check-cloudtrail-1')
def check_cloudtrail():
    """Main route to check CloudTrail security"""
    start_time = datetime.now()
    logger.info("Starting CloudTrail security checks")
    
    try:
        # Initialize AWS clients
        aws = get_aws_clients()
        logger.info("AWS clients initialized")
        
        # Get cached data
        trails = get_all_trails(aws.cloudtrail)
        buckets = get_all_s3_buckets(aws.s3)
        logger.info(f"Found {len(trails)} trails and {len(buckets)} buckets")
        
        if not trails:
            return jsonify({"error": "No CloudTrail trails found"}), 404
        
        # Define check functions and their parameters
        check_functions = [
            (check_cloudtrail_bucket_public_access, [aws.cloudtrail, aws.s3, aws.account_id, trails, buckets]),
            (check_cloudtrail_multi_region_read_write, [aws.cloudtrail, aws.account_id, trails]),
            (check_cloudtrail_multi_region_trail, [aws.cloudtrail, aws.account_id, trails]),
            (check_cloudtrail_logs_integration, [aws.cloudtrail, aws.account_id, trails]),
            (check_cloudtrail_s3_logging, [aws.cloudtrail, aws.s3, aws.account_id, trails, buckets]),
            (check_cloudtrail_s3_data_events, [aws.cloudtrail, aws.s3, aws.account_id, trails, buckets]),
            (check_cloudtrail_s3_object_read_events, [aws.cloudtrail, aws.s3, aws.account_id, trails, buckets]),
            (check_cloudtrail_s3_object_write_events, [aws.cloudtrail, aws.s3, aws.account_id, trails, buckets])
        ]
        
        # Calculate optimal number of workers based on CPU cores and workload
        total_checks = len(check_functions)
        cpu_count = os.cpu_count() or 2  # Default to 2 if CPU count cannot be determined
        max_workers = min(total_checks, cpu_count * 2)  # Double the CPU count for I/O-bound tasks
        logger.info(f"Using {max_workers} workers for {total_checks} total checks (CPU cores: {cpu_count})")
        
        # Run checks in parallel
        all_results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_check = {
                executor.submit(func, *args): (func.__name__, args)
                for func, args in check_functions
            }
            
            logger.info(f"Submitted {len(future_to_check)} checks for processing")
            
            # Track progress
            completed = 0
            total = len(future_to_check)
            
            # Collect results as they complete
            for future in as_completed(future_to_check):
                check_name, args = future_to_check[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result:
                        if isinstance(result, list):
                            all_results.extend(result)
                        else:
                            all_results.append(result)
                    
                    # Log progress every 10% or when all checks are complete
                    if completed == total or completed % max(1, total // 10) == 0:
                        logger.info(f"Progress: {completed}/{total} checks completed ({(completed/total)*100:.1f}%)")
                        
                except Exception as e:
                    logger.error(f"Error in {check_name}: {e}", extra={
                        "check_name": check_name,
                        "args": str(args),
                        "error": str(e)
                    })
        
        logger.info(f"Collected {len(all_results)} check results")
        
        # Calculate summary
        summary = {
            "total_checks": len(all_results),
            "ok": len([r for r in all_results if r['status'] == 'ok']),
            "alarm": len([r for r in all_results if r['status'] == 'alarm']),
            "error": len([r for r in all_results if r['status'] == 'error'])
        }
        
        # Batch insert results
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini')
        if all_results:
            logger.info("Starting batch insert of results")
            if not batch_insert_results(all_results, config_path):
                logger.error("Failed to insert results into database")
                return jsonify({
                    "error": "Database operation failed",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }), 500
            logger.info("Successfully completed batch insert")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        logger.info(f"Completed all checks in {duration} seconds")
        
        return jsonify({
            "results": all_results,
            "summary": summary,
            "duration_seconds": duration
        })
    
    except Exception as e:
        error_info = log_error(e, "check_cloudtrail")
        return jsonify(error_info), 500

if __name__ == '__main__':
    logger.info("Starting server on port 5001...")
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.run(debug=True, port=5001, use_reloader=False)
