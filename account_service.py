from __future__ import print_function # Python 2/3 compatibility
import boto3
import botocore
from boto3.dynamodb.conditions import Key
from bitcoinlib.wallet import P2PKHBitcoinAddress
from datetime import datetime
import hashlib
import os
import random
import time
from bitcoinlib.core.key import CPubKey
import configuration

config = configuration.NotaryConfiguration('./notaryconfig.ini')


def to_bytes(x): return x if bytes == str else x.encode()

i2b = chr if bytes == str else lambda x: bytes([x])
b2i = ord if bytes == str else lambda x: x
NONCE_LEN = 16
# Expiration delay (in seconds)
EXPIRATION_DELAY = 600


def has_expired(created):
    delta = datetime.now() - created
    return delta.total_seconds() > EXPIRATION_DELAY


def generate_nonce():
    entropy = str(os.urandom(32)) + str(random.randrange(2**256)) + str(int(time.time())**7)
    return hashlib.sha256(to_bytes(entropy)).hexdigest()[:NONCE_LEN]


def check_account(account):
    if (account is None) or (not account['public_key']) or (not account['email']):
        return False
    else:
        return True


class AccountService(object):

    def __init__(self, wallet):
        # Initializes some dictionaries to store accounts
        self.wallet = wallet
        self.dynamodb = boto3.resource('dynamodb', region_name='us-east-1', endpoint_url=config.get_db_url())
        try:
            self.account_table = self.dynamodb.Table('Account')
            print("Account Table is %s" % self.account_table.table_status)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                self.create_account_table()

    def create_account_table(self):
        try:
            self.account_table = self.dynamodb.create_table(
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
            print("Account Table is %s" % self.account_table.table_status)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ResourceInUseException':
                print("Houston, we have a problem: the Account Table exists.")

    def create_account(self, address, account):
        if not check_account(account):
            return False

        if self.get_account_by_address(address) is None:
            client_public_key = account['public_key']
            decoded = client_public_key.decode("hex")
            pubkey = CPubKey(decoded)
            raw_address = P2PKHBitcoinAddress.from_pubkey(pubkey)
            derived_address = str(raw_address)
            if derived_address == address:
                account['nonce'] = generate_nonce()
                account['date_created'] = datetime.now().isoformat(' ')
                account['account_status'] = 'PENDING'
                account['address'] = str(address)
                self.account_table.put_item(Item=account)
                return self.send_confirmation_email(account)
            else:
                return None
        else:
            return None

    def send_confirmation_email(self, account):
        server_url = config.get_server_url()
        confirmation_url = server_url+'/api/v1/account/'+account['address']+'/'+account['nonce']
        client = boto3.client('ses', region_name='us-east-1')

        response = client.send_email(
            Source='thegovern8r@gmail.com',
            Destination={
                'ToAddresses': [account['email']
                ]
            },
            Message={
                'Subject': {
                    'Data': 'Please confirm your govern8r account',
                    'Charset': 'iso-8859-1'
                },
                'Body': {
                    'Text': {
                        'Data': 'To complete your registration with govern8r please click the link',
                        'Charset': 'iso-8859-1'
                    },
                    'Html': {
                        'Data': confirmation_url,
                        'Charset': 'iso-8859-1'
                    }
                }
            }
        )
        print(confirmation_url)
        return response

    def update_account_status(self, account, new_status):
        self.account_table.update_item(
            Key={
                'address': account['address']
            },
            UpdateExpression="set account_status = :_status",
            ExpressionAttributeValues={
                ':_status': new_status
            },
            ReturnValues="UPDATED_NEW"
        )

    def update_account_nonce(self, account, new_nonce):
        self.account_table.update_item(
            Key={
                'address': account['address']
            },
            UpdateExpression="set nonce = :_nonce",
            ExpressionAttributeValues={
                ':_nonce': new_nonce
            },
            ReturnValues="UPDATED_NEW"
        )

    def get_challenge(self, address):
        account = self.get_account_by_address(address)
        if account is None or account['account_status'] != 'CONFIRMED':
            return None
        else:
            new_nonce = generate_nonce()
            account['nonce'] = new_nonce
            self.update_account_nonce(account, new_nonce)
            return account

    def confirm_account(self, address, nonce):
        account = self.get_account_by_address(address)
        if account is not None and account['nonce'] == nonce and account['account_status'] != 'CONFIRMED':
            self.update_account_status(account, 'CONFIRMED')
            return True
        else:
            return False        
    
    def delete_account(self, account):
        if account is None:
            return False

        if not self.get_account_by_public_key(account.public_key) is None:
            return True
        else:
            return False        
    
    def get_account_by_address(self, address):
        response = self.account_table.query(KeyConditionExpression=Key('address').eq(address))

        if len(response['Items']) == 0:
            return None
        else:
            return response['Items'][0]
