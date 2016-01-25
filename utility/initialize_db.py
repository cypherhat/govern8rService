from __future__ import print_function # Python 2/3 compatibility
import botocore
import configuration
import resource_factory

config = configuration.NotaryConfiguration('../notaryconfig.ini')

dynamodb = resource_factory.get_dynamodb(config)
try:
    account_table = dynamodb.Table('Account')
    print("Account Table status: %s " % account_table.table_status)
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
    print("Notarization Table status: %s " % notarization_table.table_status)
except botocore.exceptions.ClientError as e:
    print(e.response['Error']['Code'])

