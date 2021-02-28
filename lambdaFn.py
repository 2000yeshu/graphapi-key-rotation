
import base64
import json
import logging
import os

import boto3
from botocore.vendored import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Secrets Manager Twitter Bearer Token Handler

    This handler uses the master-user rotation scheme to rotate a bearer token of a Twitter app.

    The Secret PlaintextString is expected to be a JSON string with the following format:
    {
        'FB_LONG_ACCESS_TOKEN': ,
        'token_type': ,
        'masterarn': 
    }

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the secret json does not contain the expected keys

    """
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client and environment variables
    service_client = boto3.client(
        'secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])
    oauth2_token_url = os.environ['FACEBOOK_OAUTH2_TOKEN_URL']
    #oauth2_invalid_token_url = os.environ['TWITTER_OAUTH2_INVALID_TOKEN_URL']
    #tweet_search_url = os.environ['TWITTER_SEARCH_URL']

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error(
            "Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError(
            "Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info(
            "Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error(
            "Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError(
            "Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    # Call the appropriate step
    if step == "createSecret":
        create_secret(service_client, arn, token,
                      oauth2_token_url,
                      # oauth2_invalid_token_url
                      )

    elif step == "setSecret":
        set_secret(service_client, arn, token, oauth2_token_url)

    elif step == "testSecret":
        test_secret(service_client, arn, token, tweet_search_url)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        logger.error(
            "lambda_handler: Invalid step parameter %s for secret %s" % (step, arn))
        raise ValueError(
            "Invalid step parameter %s for secret %s" % (step, arn))


def create_secret(service_client, arn, token, oauth2_token_url, oauth2_invalid_token_url):
    """Get a new bearer token from Twitter 

    This method invalidates existing bearer token for the Twitter app and retrieves a new one from Twitter.
    If a secret version with AWSPENDING stage exists, updates it with the newly retrieved bearer token and if 
    the AWSPENDING stage does not exist, creates a new version of the secret with that stage label. 

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

        oauth2_token_url (string): The Twitter API endpoint to request a bearer token

        oauth2_invalid_token_url (string): The Twitter API endpoint to invalidate a bearer token

    Raises:
        ValueError: If the current secret is not valid JSON

        KeyError: If the secret json does not contain the expected keys

        ResourceNotFoundException: If the current secret is not found

    """
    # Make sure the current secret exists and try to get the master arn from the secret
    try:
        current_secret_dict = get_secret_dict(
            service_client, arn, "AWSCURRENT")
        master_arn = current_secret_dict['masterarn']
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        return
    # create bearer token credentials to be passed as authorization string to Twitter
    bearer_token_credentials = encode_credentials(
        service_client, master_arn, "AWSCURRENT")
    # get the bearer token from Twitter

    #bearer_token_from_twitter = get_access_token(bearer_token_credentials, oauth2_token_url)

    # invalidate the current bearer token

    #invalidate_bearer_token(oauth2_invalid_token_url, bearer_token_credentials, bearer_token_from_twitter)

    # get a new bearer token from Twitter
    new_bearer_token = get_access_token(
        bearer_token_credentials, oauth2_token_url)
    # if a secret version with AWSPENDING stage exists, update it with the lastest bearer token
    # if the AWSPENDING stage does not exist, then create the version with AWSPENDING stage
    try:
        pending_secret_dict = get_secret_dict(
            service_client, arn, "AWSPENDING", token)
        pending_secret_dict['FB_LONG_ACCESS_TOKEN'] = new_bearer_token
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(
            pending_secret_dict), VersionStages=['AWSPENDING'])
        logger.info(
            "createSecret: Successfully invalidated the bearer token of the secret %s and updated the pending version" % arn)
    except service_client.exceptions.ResourceNotFoundException:
        current_secret_dict['FB_LONG_ACCESS_TOKEN'] = new_bearer_token
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(
            current_secret_dict), VersionStages=['AWSPENDING'])
        logger.info(
            "createSecret: Successfully invalidated the bearer token of the secret %s and and created the pending version." % arn)


def set_secret(service_client, arn, token, oauth2_token_url):
    """Validate the pending secret with that in Twitter

    This method checks wether the bearer token in Twitter is the same as the one in the version with AWSPENDING stage.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

        oauth2_token_url (string): The Twitter API endopoint to get a bearer token

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON or master credentials could not be used to login to DB

        KeyError: If the secret json does not contain the expected keys

    """
    # First get the pending version of the bearer token and compare it with that in Twitter
    pending_secret_dict = get_secret_dict(service_client, arn, "AWSPENDING")
    master_arn = pending_secret_dict['masterarn']
    # create bearer token credentials to be passed as authorization string to Twitter
    bearer_token_credentials = encode_credentials(
        service_client, master_arn, "AWSCURRENT")
    # get the bearer token from Twitter
    bearer_token_from_twitter = get_access_token(
        bearer_token_credentials, oauth2_token_url)
    # if the bearer tokens are same, invalidate the bearer token in Twitter
    # if not, raise an exception that bearer token in Twitter was changed outside Secrets Manager
    if pending_secret_dict['FB_LONG_ACCESS_TOKEN'] == bearer_token_from_twitter:
        logger.info(
            "createSecret: Successfully verified the bearer token of arn %s" % arn)
    else:
        raise ValueError(
            "The bearer token of the Twitter app was changed outside Secrets Manager. Please check.")


def test_secret(service_client, arn, token, tweet_search_url):
    """Test the pending secret by calling a Twitter API

    This method tries to use the bearer token in the secret version with AWSPENDING stage and search for tweets
    with 'aws secrets manager' string. 

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON or pending credentials could not be used to login to the database

        KeyError: If the secret json does not contain the expected keys

    """
    # First get the pending version of the bearer token and compare it with that in Twitter
    pending_secret_dict = get_secret_dict(
        service_client, arn, "AWSPENDING", token)
    # Now verify you can search for tweets using the bearer token
    if verify_bearer_token(pending_secret_dict['FB_LONG_ACCESS_TOKEN'], tweet_search_url):
        logger.info(
            "testSecret: Successfully authorized with the pending secret in %s." % arn)
        return
    else:
        logger.error(
            "testSecret: Unable to authorize with the pending secret of secret ARN %s" % arn)
        raise ValueError(
            "Unable to connect to Twitter with pending secret of secret ARN %s" % arn)


def finish_secret(service_client, arn, token):
    """Finish the rotation by marking the pending secret as current

    This method moves the secret from the AWSPENDING stage to the AWSCURRENT stage.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info(
                    "finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(
        SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info(
        "finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (version, arn))


def encode_credentials(service_client, arn, stage):
    """Encodes the Twitter credentials
    This helper function encodes the Twitter credentials (consumer_key and consumer_secret) 

    Args:
      service_client (client):The secrets manager service client

      arn (string): The secret ARN or other identifier

      stage (stage): The stage identifying the secret version

    Returns:
      encoded_credentials (string): base64 encoded authorization string for Twitter

    Raises:
      KeyError: If the secret json does not contain the expected keys
    """
    required_fields = ['FB_APP_ID', 'FB_APP_SECRET']
    master_secret_dict = get_secret_dict(service_client, arn, stage)
    for field in required_fields:
        if field not in master_secret_dict:
            raise KeyError("%s key is missing from the secret JSON" % field)
    encoded_credentials = base64.urlsafe_b64encode(
        '{}:{}'.format(master_secret_dict['FB_APP_ID'], master_secret_dict['FB_APP_SECRET']).encode('ascii')).decode('ascii')
    return encoded_credentials


def get_access_token(encoded_credentials, oauth2_token_url):
    """Gets a bearer token from Twitter

    This helper function retrieves the current bearer token from Twitter, given a set of credentials.

    Args:
      encoded_credentials (string): Twitter credentials for authentication

      oauth2_token_url (string): REST API endpoint to request a bearer token from Twitter

    Raises:
      KeyError: If the secret json does not contain the expected keys
    """
    headers = {
        'Authorization': 'Basic {}'.format(encoded_credentials),
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
    }
    data = 'grant_type=client_credentials'
    response = requests.post(oauth2_token_url, headers=headers, data=data)
    response_data = response.json()
    if response_data['token_type'] == 'bearer':
        bearer_token = response_data['FB_LONG_ACCESS_TOKEN']
        return bearer_token
    else:
        raise RuntimeError('unexpected token type: {}'.format(
            response_data['token_type']))


def invalidate_bearer_token(oauth2_invalid_token_url, bearer_token_credentials, bearer_token):
    """Invalidates a Bearer Token of a Twitter App

    This helper function invalidates a bearer token of a Twitter app. 
    If successful, it returns the invalidated bearer token, else None

    Args:
        oauth2_invalid_token_url (string): The Twitter API endpoint to invalidate a bearer token

        bearer_token_credentials (string): encoded consumer key and consumer secret to authenticate with Twitter

        bearer_token (string): The bearer token to be invalidated

    Returns:
        invalidated_bearer_token: The invalidated bearer token

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON

        KeyError: If the secret json does not contain the expected keys

    """
    headers = {
        'Authorization': 'Basic {}'.format(bearer_token_credentials),
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
    }
    data = 'FB_LONG_ACCESS_TOKEN=' + bearer_token
    invalidate_response = requests.post(
        oauth2_invalid_token_url, headers=headers, data=data)
    invalidate_response_data = invalidate_response.json()
    if invalidate_response_data:
        return
    else:
        raise RuntimeError('Invalidate bearer token request failed')


def verify_bearer_token(bearer_token, tweet_search_url):
    """Verifies access to Twitter APIs using a bearer token

    This helper function verifies that the bearer token is valid by calling Twitter's search/tweets API endpoint

    Args:
        bearer_token (string): The current bearer token for the application

    Returns:
        True or False

    Raises:
        KeyError: If the response of search tweets API call fails
    """
    headers = {
        'Authorization': 'Bearer {}'.format(bearer_token),
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
    }
    search_results = requests.get(tweet_search_url, headers=headers)
    try:
        search_results.json()['statuses']
        return True
    except:
        return False


def get_secret_dict(service_client, arn, stage, token=None):
    """Gets the secret dictionary corresponding for the secret arn, stage, and token

    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired

        stage (string): The stage identifying the secret version

    Returns:
        SecretDictionary: Secret dictionary

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON

    """
    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = service_client.get_secret_value(
            SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = service_client.get_secret_value(
            SecretId=arn, VersionStage=stage)
    plaintext = secret['SecretString']

    # Parse and return the secret JSON string
    return json.loads(plaintext)
