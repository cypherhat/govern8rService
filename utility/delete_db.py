from __future__ import print_function # Python 2/3 compatibility
import boto3
import botocore
import configuration

config = configuration.NotaryConfiguration()

dynamodb = boto3.resource('dynamodb', region_name='us-east-1', endpoint_url=config.get_db_url())
try:
    account_table = dynamodb.Table('Account')
    account_table.delete()
    print(account_table.table_status)
except botocore.exceptions.ClientError as e:
    print(e.response['Error']['Code'])


try:
    notarization_table = dynamodb.Table('Notarization')
    notarization_table.delete()
    print("Notarization Table status:", notarization_table.table_status)
except botocore.exceptions.ClientError as e:
    print(e.response['Error']['Code'])