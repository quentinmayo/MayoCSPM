#!/usr/bin/env python3
"""Operator-only local metadata export. Credentials use the normal AWS SDK chain."""
import argparse
import json
import os
from dataclasses import asdict

import boto3

from app.collectors import SDK, AWSCollector

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--region', action='append', required=True)
parser.add_argument('--services', default='ec2,s3,rds,iam,cloudtrail,eks')
parser.add_argument('--profile')
parser.add_argument('--max-resources', type=int, default=1000)
parser.add_argument('--max-api-calls', type=int, default=300)
parser.add_argument('--output', required=True, help='New private JSON file; never commit real cloud inventory')
args = parser.parse_args()
session = boto3.Session(profile_name=args.profile, region_name=args.region[0])
account = session.client('sts', config=SDK).get_caller_identity()['Account']
snapshot = AWSCollector(session, account, {'regions': args.region, 'services': args.services.split(','),
                                         'max_resources': args.max_resources, 'max_api_calls': args.max_api_calls}).collect()
fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as file:
    json.dump(asdict(snapshot), file)
print(json.dumps({'resources': len(snapshot.resources), 'logical_api_calls': snapshot.api_calls,
                  'complete_scopes': sum(c['status'] == 'complete' for c in snapshot.coverage),
                  'incomplete_scopes': sum(c['status'] != 'complete' for c in snapshot.coverage)}))
