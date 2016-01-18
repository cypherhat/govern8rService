from __future__ import print_function # Python 2/3 compatibility
import boto3
import botocore
import configuration

config = configuration.NotaryConfiguration('../notaryconfig.ini')

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
try:
    account_table = dynamodb.Table('Account')
    account_table.delete()
    print(account_table.table_status)
    print("Account Table status: %s " % account_table.table_status)
except botocore.exceptions.ClientError as e:
    print(e.response['Error']['Code'])


try:
    notarization_table = dynamodb.Table('Notarization')
    notarization_table.delete()
    print("Notarization Table status: %s " % notarization_table.table_status)
except botocore.exceptions.ClientError as e:
    print(e.response['Error']['Code'])