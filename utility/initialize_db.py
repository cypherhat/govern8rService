from __future__ import print_function # Python 2/3 compatibility
import boto3
import botocore
from boto3.dynamodb.conditions import Key
import configuration

config = configuration.NotaryConfiguration('../notaryconfig.ini')

dynamodb = boto3.resource('dynamodb', region_name='us-east-1', endpoint_url=config.get_db_url())
try:
    account_table = dynamodb.Table('Account')
    print(account_table.table_status)
except botocore.exceptions.ClientError as e:
    print(e.response['Error']['Code'])

try:
    account_table = dynamodb.create_table(
        TableName='Account',
        KeySchema=[
            {
                'AttributeName': 'address',
                'KeyType': 'HASH'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'address',
                'AttributeType': 'S'
            },
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 10,
            'WriteCapacityUnits': 10
        }

    )

    print("Account Table status:", account_table.table_status)
except botocore.exceptions.ClientError as e:
    print(e.response['Error']['Code'])


try:
    notarization_table = dynamodb.create_table(
        TableName='Notarization',
        KeySchema=[
            {
                'AttributeName': 'digest',
                'KeyType': 'HASH'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'digest',
                'AttributeType': 'S'
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 10,
            'WriteCapacityUnits': 10
        }


    )
    print("Notarization Table status:", notarization_table.table_status)
except botocore.exceptions.ClientError as e:
    print(e.response['Error']['Code'])
    # account_table = dynamodb.Table('Notarization')
    # account_table.delete()
