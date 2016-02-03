import requests
import boto3
import botocore
from blockcypher import embed_data, get_transaction_details, subscribe_to_address_webhook
from boto3.dynamodb.conditions import Key
import hashlib
from datetime import datetime
import configuration
import resource_factory

config = configuration.NotaryConfiguration('./notaryconfig.ini')
blockcypher_token = config.get_block_cypher_token()



class NotarizationService(object):
    def __init__(self, wallet, logger):
        self.wallet = wallet
        self.logger = logger
        self.dynamodb = resource_factory.get_dynamodb(config)
        try:
            self.notarization_table = self.dynamodb.Table('Notarization')
            self.logger.debug("Notarization Table is %s" % self.notarization_table.table_status)
        except botocore.exceptions.ClientError as e:
            self.logger.exception("Problem accessing notarization table %s " % e.response)
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                self.logger.debug("Attempting to create Notarization table since it did not exist.")
                self.create_notarization_table()

    def add_to_blockchain(self, data_value):
        try:
            response = embed_data(to_embed=data_value, api_key=blockcypher_token, data_is_hex=True,
                                  coin_symbol=config.get_coin_network())
            transaction_hash = response['hash']
            return transaction_hash
        except requests.ConnectionError as e:
            self.logger.exception("Failed to update account nonce %s" % e.message)
            return None

    def check_notarization(self, notarization):
        if (notarization is None) or \
                (not notarization['document_hash']) or \
                (not notarization['notary_hash']) or \
                (not notarization['address']) or \
                (not notarization['date_created']) or \
                (not notarization['transaction_hash']):
            return False
        else:
            return True

    def create_notarization_table(self):
        try:
            self.notarization_table = self.dynamodb.create_table(
                    TableName='Notarization',
                    KeySchema=[
                        {
                            'AttributeName': 'address',
                            'KeyType': 'HASH'  #Partition key
                        },
                        {
                            'AttributeName': 'document_hash',
                            'KeyType': 'RANGE'  #Sort key
                        }
                    ],
                    AttributeDefinitions=[
                        {
                            'AttributeName': 'address',
                            'AttributeType': 'S'
                        },
                        {
                            'AttributeName': 'document_hash',
                            'AttributeType': 'S'
                        }
                    ],
                    ProvisionedThroughput={
                        'ReadCapacityUnits': 10,
                        'WriteCapacityUnits': 10
                    }
            )
            self.logger.debug("Notarization Table is %s" % self.notarization_table.table_status)
        except botocore.exceptions.ClientError as e:
            self.logger.exception("Problem accessing notarization table %s " % e.response)

    def sign_and_hash(self, document_hash):
        signature = self.wallet.sign(document_hash)
        hashed_signature = hashlib.sha256(signature).digest()
        hashed_document_hash = hashlib.sha256(document_hash).digest()
        notary_hash = hashlib.sha256(hashed_signature + hashed_document_hash).digest()
        return notary_hash

    def notarize(self, notarization):
        notary_hash = self.sign_and_hash(notarization['document_hash'])
        hex_hash = str(notary_hash).encode("hex")
        notarization['notary_hash'] = hex_hash
        transaction_hash = self.add_to_blockchain(hex_hash)
        if transaction_hash is not None:
            notarization['transaction_hash'] = transaction_hash
            notarization['date_created'] = datetime.now().isoformat(' ')
            notarization['document_status'] = 'NOT_ON_FILE'
            if self.create_notarization(notarization):
                return notarization

        return None

    def create_notarization(self, notarization):
        if not self.check_notarization(notarization):
            return None
        try:
            self.logger.debug("Notarization is %s " % notarization)
            self.notarization_table.put_item(Item=notarization)
        except botocore.exceptions.ClientError as e:
            self.logger.exception("Problem accessing notarization table %s " % e.response)
            return False

        return True

    def update_document_status(self, notarization, new_status):
        try:
            self.notarization_table.update_item(
                Key={
                    'document_hash': notarization['document_hash']
                },
                UpdateExpression="set document_status = :_status",
                ExpressionAttributeValues={
                    ':_status': new_status
                },
                ReturnValues="UPDATED_NEW"
            )
        except botocore.exceptions.ClientError as e:
            self.logger.exception("Problem accessing notarization table %s " % e.response)

    def get_notarization_by_document_hash(self, address, document_hash):
        try:
            response = self.notarization_table.query(KeyConditionExpression=Key('address').eq(address) & Key('document_hash').eq(document_hash))
        except botocore.exceptions.ClientError as e:
            self.logger.exception("Problem accessing notarization table %s " % e.response)

        if len(response['Items']) == 0:
            return None
        else:
            return response['Items'][0]

    def get_notarization_status(self, document_hash):
        notarization_data = self.get_notarization_by_document_hash(document_hash)
        status_data = get_transaction_details(notarization_data['transaction_hash'], config.get_coin_network())
        if status_data is None:
            return None
        else:
            return status_data

    def store_file(self, notarization, file_to_store):
        try:
            s3 = boto3.resource('s3', region_name='us-east-1')
            key = notarization['address']+'/'+notarization['document_hash']
            s3.Bucket('govern8r-notarized-documents').put_object(Key=key, Body=file_to_store, ACL='public-read')
            self.update_document_status(notarization, 'ON_FILE')
            self.logger.debug ('https://bucket.s3.amazonaws.com'+'/'+key)
        except botocore.exceptions.ClientError as e:
            self.logger.exception("Problem accessing S3 %s " % e.response)
        return None
