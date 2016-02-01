import hashlib
import log_handlers
from functools import wraps
import base58
import configuration
from flask import request, Response, json, g, redirect
from flask_api import FlaskAPI
from message import SecureMessage
import wallet
import getpass
import socket
from account_service import AccountService
from notarization_service import NotarizationService

config = configuration.NotaryConfiguration('./notaryconfig.ini')
logger = log_handlers.get_logger(config)
logger.debug("-------------------------ENVIRONMENT--------------------------")
logger.debug("Who Am I: %s " % getpass.getuser())
logger.debug("Where Am I: %s " % socket.gethostname())
logger.debug("Am I Local: %s " % config.is_local_host())
logger.debug("CONFIGURATION SETTING[server_url]: %s " % config.get_server_url())
logger.debug("CONFIGURATION SETTING[aws_region]: %s " % config.get_aws_region())
logger.debug("CONFIGURATION SETTING[block_cypher_token]: %s " % config.get_block_cypher_token())
logger.debug("CONFIGURATION SETTING[block_cypher_url]: %s " % config.get_block_cypher_url())
logger.debug("CONFIGURATION SETTING[coin_network]: %s " % config.get_coin_network())
logger.debug("CONFIGURATION SETTING[db_url]: %s " % config.get_db_url())
logger.debug("CONFIGURATION SETTING[debug_log]: %s " % config.get_debug_log())
logger.debug("CONFIGURATION SETTING[key_id]: %s " % config.get_key_id())
logger.debug("CONFIGURATION SETTING[local_db_url]: %s " % config.get_local_db_url())
logger.debug("CONFIGURATION SETTING[local_server_url]: %s " % config.get_local_server_url())
logger.debug("CONFIGURATION SETTING[remote_db_url]: %s " % config.get_remote_db_url())
logger.debug("CONFIGURATION SETTING[remote_server_url]: %s " % config.get_remote_server_url())
logger.debug("CONFIGURATION SETTING[wallet_type]: %s " % config.get_wallet_type())
logger.debug("-------------------------ENVIRONMENT--------------------------")

keyId = config.get_key_id()
application = FlaskAPI(__name__)
wallet = wallet.create_wallet(config.get_wallet_type(), config, logger)
account_service = AccountService(wallet, logger)
notarization_service = NotarizationService(wallet, logger)
secure_message = SecureMessage(wallet)


def convert_account():
    file_encryption_key = wallet.decrypt_from_hex(g.account_data['file_encryption_key'])
    converted_account = dict(g.account_data)
    converted_account['file_encryption_key'] = file_encryption_key
    del converted_account['nonce']
    del converted_account['account_status']
    del converted_account['public_key']
    del converted_account['address']
    return converted_account


def get_bad_response(status_code):
    bad_response = Response(json.dumps({}), status=status_code, mimetype='application/json')
    if 'govern8r_token' in request.cookies:
        govern8r_token = request.cookies.get('govern8r_token')
    else:
        govern8r_token = 'UNAUTHENTICATED'
    bad_response.set_cookie('govern8r_token', govern8r_token)
    return bad_response


def build_fingerprint():
    fingerprint = str(request.user_agent)+str(request.remote_addr)
    return fingerprint


def build_token(nonce):
    nonce_hash = hashlib.sha256(nonce).digest()
    fingerprint_hash = hashlib.sha256(build_fingerprint()).digest()
    token = hashlib.sha256(nonce_hash + fingerprint_hash).digest()
    encoded = base58.base58_check_encode(0x80, token.encode("hex"))
    return encoded


def previously_notarized(document_hash):
    notarization_data = notarization_service.get_notarization_by_document_hash(document_hash)
    if notarization_data is not None:
        return True
    else:
        return False


def validate_token(nonce, token):
    check_token = build_token(nonce)
    return check_token == token


def authenticated(address):
    if not hasattr(g, 'account_data'):
        account_data = account_service.get_account_by_address(address)
        if account_data is None:
            return get_bad_response(404)
        g.account_data = account_data

    if g.account_data is None or g.account_data['nonce'] is None:
        return False

    if 'govern8r_token' in request.cookies:
        govern8r_token = request.cookies.get('govern8r_token')
    else:
        govern8r_token = 'UNAUTHENTICATED'
    if g.account_data is None or g.account_data['nonce'] is None \
            or g.account_data['account_status'] == 'PENDING' or govern8r_token == 'UNAUTHENTICATED':
        return False
    return validate_token(g.account_data['nonce'], govern8r_token)


def rotate_authentication_token():
    govern8r_token = build_token(g.account_data['nonce'])
    authenticated_response = Response(json.dumps({}), status=200, mimetype='application/json')
    authenticated_response.set_cookie('govern8r_token', govern8r_token)
    return authenticated_response


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        address = kwargs['address']
        if address is None:
            return get_bad_response(500)
        if not authenticated(address):
            return get_bad_response(401)
        return f(*args, **kwargs)
    return decorated_function


def address_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        address = kwargs['address']
        if address is None:
            return get_bad_response(500)
        else:
            if not hasattr(g, 'account_data'):
                account_data = account_service.get_account_by_address(address)
                if account_data is None:
                    return get_bad_response(404)
                g.account_data = account_data
        return f(*args, **kwargs)
    return decorated_function


def notarization_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        document_hash = kwargs['document_hash']
        if document_hash is None:
            return get_bad_response(500)
        else:
            notarization_data = notarization_service.get_notarization_by_document_hash(document_hash)
            if notarization_data is None:
                return get_bad_response(404)
            g.notarization_data = notarization_data
        return f(*args, **kwargs)
    return decorated_function


def security_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        address = kwargs['address']
        payload = request.data
        if secure_message.verify_secure_payload(address, payload):
            raw_message = secure_message.get_message_from_secure_payload(payload)
            g.message = json.loads(raw_message)
        else:
            return get_bad_response(403)
        return f(*args, **kwargs)
    return decorated_function


@application.route("/", methods=['GET'])
def hello_server():
    return {}


@application.route("/govern8r/api/v1/pubkey", methods=['GET'])
def pubkey():
    """
    Return server public key. The key is encoded in hex and needs to be decoded
    from hex to be used by the encryption utility.
    """
    # request.method == 'GET'
    public_key = wallet.get_public_key()
    data = {
        'public_key': public_key.encode("hex")
    }
    js = json.dumps(data)

    resp = Response(js, status=200, mimetype='application/json')
    return resp


@application.route("/govern8r/api/v1/challenge/<address>", methods=['PUT'])
@address_required
@security_required
def put_challenge(address):
    """
    Authentication
    Parameters
    ----------
    address : string
       The Bitcoin address of the client.
    """

    if g.account_data['account_status'] == 'PENDING':
        return get_bad_response(403)
    if g.message['nonce'] != g.account_data['nonce']:
        return get_bad_response(401)
    govern8r_token = build_token(g.account_data['nonce'])
    good_response = Response(json.dumps({}), status=200, mimetype='application/json')
    good_response.set_cookie('govern8r_token', value=govern8r_token)
    return good_response


@application.route("/govern8r/api/v1/challenge/<address>", methods=['GET'])
@address_required
def get_challenge(address):
    """
    Authentication
    Parameters
    ----------
    address : string
       The Bitcoin address of the client.
    """
    if g.account_data['account_status'] == 'PENDING':
        return get_bad_response(403)
    str_nonce = json.dumps({'nonce': g.account_data['nonce']})
    payload = secure_message.create_secure_payload(g.account_data['public_key'], str_nonce)
    good_response = Response(json.dumps(payload), status=200, mimetype='application/json')
    return good_response


@application.route("/govern8r/api/v1/account/<address>", methods=['GET'])
@login_required
@address_required
def get_account(address):
    """
    Account registration
    Parameters
    ----------
    address : string
       The Bitcoin address of the client.
    """
    authenticated_response = rotate_authentication_token()
    account = convert_account()
    outbound_payload = secure_message.create_secure_payload(g.account_data['public_key'], json.dumps(account))
    authenticated_response.data = json.dumps(outbound_payload)
    return authenticated_response


@application.route("/govern8r/api/v1/account/<address>", methods=['PUT'])
@security_required
def put_account(address):
    """
    Account registration
    Parameters
    ----------
    address : string
       The Bitcoin address of the client.
    """

    good_response = Response(json.dumps({}), status=200, mimetype='application/json')
    response = account_service.create_account(address, g.message)
    if response is None:
        return get_bad_response(409)
    else:
        return good_response


@application.route("/govern8r/api/v1/account/<address>/<nonce>", methods=['GET'])
@address_required
def confirm_account(address, nonce):
    """
    Account registration confirmation
    Parameters
    ----------
    address : string
       The Bitcoin address of the client.
    nonce : string
       The nonce sent to the email address
    """
    good_response = Response("Confirmed: "+address, status=200, mimetype='application/json')
    account_service.confirm_account(address, nonce)
    return good_response


@application.route("/govern8r/api/v1/account/<address>/notarization/<document_hash>", methods=['PUT'])
@login_required
@address_required
@security_required
def notarization(address, document_hash):
    """
    Notarize document
    Parameters
    ----------
    address : string
       The Bitcoin address of the client.
    document_hash : string
       The hash of the document.
    """

    authenticated_response = rotate_authentication_token()

    if previously_notarized(document_hash):
        authenticated_response.status_code = 500
        return authenticated_response

    if g.message['document_hash'] == document_hash:
        g.message['address'] = address
        outbound_message = notarization_service.notarize(g.message)
        if outbound_message is not None:
            outbound_payload = secure_message.create_secure_payload(g.account_data['public_key'], json.dumps(outbound_message))
            authenticated_response.data = json.dumps(outbound_payload)
        else:
            authenticated_response.status_code = 500
        return authenticated_response
    else:
        return get_bad_response(403)


@application.route("/govern8r/api/v1/account/<address>/notarization/<document_hash>/status", methods=['GET'])
@login_required
@notarization_required
@address_required
def notarization_status(address, document_hash):
    """
    Notarization status
    Parameters
    ----------
    address : string
       The Bitcoin address of the client.
    document_hash : string
       The hash of the document.
    """
    authenticated_response = rotate_authentication_token()

    if g.notarization_data is None:
        authenticated_response.status_code = 404
        return authenticated_response

    status_data = notarization_service.get_notarization_status(document_hash)
    if status_data is not None:
        outbound_payload = secure_message.create_secure_payload(g.account_data['public_key'], json.dumps(status_data))
        authenticated_response.data = json.dumps(outbound_payload)
    else:
        authenticated_response.data = status_data
    return authenticated_response


@application.route('/govern8r/api/v1/account/<address>/document/<document_hash>', methods=['PUT'])
@login_required
@notarization_required
@address_required
def upload_document(address, document_hash):
    """
    Upload document
    Parameters
    ----------
    address : string
       The Bitcoin address of the client.
    document_hash : string
       The hash of the document.
    """
    authenticated_response = rotate_authentication_token()

    f = request.files['document_content']
    notarization_service.store_file(g.notarization_data, f)
    return authenticated_response


@application.route('/govern8r/api/v1/account/<address>/document/<document_hash>', methods=['GET'])
@login_required
@notarization_required
@address_required
def download_document(address, document_hash):
    """
    Upload document
    Parameters
    ----------
    address : string
       The Bitcoin address of the client.
    document_hash : string
       The hash of the document.
    """

    if g.notarization_data['address'] != g.account_data['address']:
        return get_bad_response(403)

    bucket_url = 'https://s3.amazonaws.com/govern8r-notarized-documents/'+address+'/'+document_hash
    print(bucket_url)

    return redirect(bucket_url)


@application.route('/govern8r/api/v1/account/<address>/document/<document_hash>/status', methods=['GET'])
@login_required
@notarization_required
@address_required
def check_document_status(address, document_hash):
    """
    Upload document
    Parameters
    ----------
    address : string
       The Bitcoin address of the client.
    document_hash : string
       The hash of the document.
    """
    authenticated_response = rotate_authentication_token()
    status_data = {'owner_address': g.notarization_data['address'],
                   'document_status': g.notarization_data['document_status'],
                   'document_hash': g.notarization_data['document_hash']}
    outbound_payload = secure_message.create_secure_payload(g.account_data['public_key'], json.dumps(status_data))
    authenticated_response.data = json.dumps(outbound_payload)

    return authenticated_response


@application.route("/govern8r/api/v1/account/<address>/test", methods=['GET'])
@login_required
@address_required
def test_authentication(address):
    """
    Test authentication
    Parameters
    ----------
    address : string
       The Bitcoin address of the client.
    """

    authenticated_response = rotate_authentication_token()
    return authenticated_response


if __name__ == "__main__":
    # try:
    #     1/0 #Love me a divide by zero.
    # except ZeroDivisionError as e:
    #     logger.exception("FFFFFFFFFFFFFFFFFFFFFFFUUUUUUUUUUUUUUUUUUUUUU")

    application.run(debug=True, use_reloader=False, ssl_context='adhoc')