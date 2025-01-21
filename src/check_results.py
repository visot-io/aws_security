import sys
import json
import requests

try:
    response = requests.get('http://localhost:8000/api/cloudfront/comprehensive-checks')
    data = response.json()
    total_checks = len(data)
    distributions = total_checks // 8
    expected_checks = distributions * 8
    
    print(f'Total checks: {total_checks}')
    print(f'Distributions: {distributions}')
    print(f'Expected checks: {expected_checks}')
    
    if total_checks == expected_checks:
        print('✓ Check count matches expectations')
    else:
        print('✗ Check count does not match expectations')
        
except Exception as e:
    print(f'Error: {str(e)}')
