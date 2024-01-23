# pylint: disable=R0914
# pylint: disable=C0301
# pylint: disable=W0612
"""User management Lambda to manage cognito users."""

import os
import json
import logging
import boto3
import botocore
from datetime import datetime

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

# boto3 service call
COGNITO_CLIENT = boto3.client("cognito-idp")

# Environment variaable
USERPOOL_ID = os.getenv("USERPOOL_ID")

#Available Filters for ListUsers API
AVAILABLE_FILTERS = ['username', 'email', 'phone_number', 'name', 'given_name', 
    'family_name', 'preferred_username', 'cognito:user_status', 'status', 'sub']

# The fuction to get Cognito users using ListUsers API. Takes optional filter
def get_cognito_user(USERPOOL_ID, event):
    get_user_response = ''
    user_details = ''
    paginated_user_list = ''
    query_filter = ''
    
    if event['queryStringParameters']:
        try:
            query_filter = event['queryStringParameters']['filters']
        except:
            query_filter = False
            
    LOGGER.info("Passing filter %s", query_filter)
    
    if query_filter:
        # Check if filter is supported
        if query_filter.split()[0].lower() in AVAILABLE_FILTERS:
            
            query_filter = query_filter.split()
            
            LOGGER.info("Looking for users using the %s filter in Cognito user pool %s", 
                query_filter, USERPOOL_ID)    # noqa: E501
            paginator = COGNITO_CLIENT.get_paginator('list_users')
            paginated_user_list = paginator.paginate(
                UserPoolId = USERPOOL_ID,
                Filter = query_filter[0].lower() + " = " + query_filter[2],
                PaginationConfig={
                }
            )
        # Throw error if filter is unsupported
        elif query_filter.split()[0].lower() not in AVAILABLE_FILTERS:
            LOGGER.info("Found unsupported filter")    # noqa: E501
            bad_filter= { 
                "status": "400", 
                "response":{"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "scimType":"invalidFilter",
                "detail":"Request contained an unsupported filter",
                "status":"400"
                    }
                }
            return bad_filter
        
    # If no filter provided, list all users
    elif not query_filter:
        LOGGER.info("Listing all users in Cognito user pool %s...", USERPOOL_ID)    # noqa: E501
        paginator = COGNITO_CLIENT.get_paginator('list_users')
        paginated_user_list = paginator.paginate(
            UserPoolId = USERPOOL_ID,
            PaginationConfig={
                }
            )
    try:
        for page in paginated_user_list:
                for user in page['Users']:
                    if user['Username']:
                        user_details += '{"userName": "' + user['Username'] + '",' + '"Id": "' + user['Attributes'][0]['Value'] + '"},'
                        LOGGER.info("Found user %s (user id ['%s']) in Cognito user pool %s.", 
                            user['Username'], user['Attributes'][0]['Value'], USERPOOL_ID)    # noqa: E501
    except botocore.exceptions.ClientError as error:
        LOGGER.error("Boto3 client error in user_management_lambda.py while getting Cognito user due to %s",
            error.response['Error']['Code'])     # noqa: E501
        raise error
    
    user_details = user_details[:-1]

    number_of_results = (len(list(user_details.split('}'))) - 1)

    get_user_response_payload = json.loads('{"totalResults": ' + str(number_of_results) + 
        ', "itemsPerPage": ' + str(number_of_results) + 
        ', "startIndex": 1, "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "Resources": [' 
        + user_details + ']}')
    
    return get_user_response_payload



# Return username of PATCH target
def find_target_user(USERPOOL_ID, event, body):
    """To update cognito user."""
    user_to_update = ''

    if event['pathParameters']['userid']:
        try:
            user_to_update = COGNITO_CLIENT.list_users(
                UserPoolId = USERPOOL_ID, 
                Filter = 'sub = "' + event['pathParameters']['userid'] + '"'
            )
            LOGGER.info('ListUser response is %s', user_to_update)
            try:
                target_user = user_to_update['Users'][0]['Username']
                
                return target_user
            except IndexError as error:
                LOGGER.error("Was unable to find userid %s in Cognito userpool %s", event['pathParameters']['userid'], USERPOOL_ID)
                raise error
                
        except botocore.exceptions.ClientError as error:
            LOGGER.error("Unable to find user associated with UserId %s", 
                event['pathParameters']['userid'])
            LOGGER.error("Error: %s", error.response)
            raise error
            
    
# Helper function to make AdminUpdateUserAttributes/AdminDeleteUserAttrbites calls

def update_cognito_user(USERPOOL_ID, body, target_user):
    
    attributes_to_update = []
    attributes_to_remove = []
    
    for i in range(0, len(body['Operations'])):
        operation = body['Operations'][i]
        
        #Build dictionary to add/replace attributes
        if (operation['op'] == 'replace') or (operation['op'] == 'add'):
            attribute = '{"Name": "' + operation['path'] + '", "Value": "' + operation['value'] + '"}'
            attributes_to_update.append(json.loads(attribute))
        
        #Build list to remove attributes
        elif (operation['op'] == 'remove'):
            attributes_to_remove.append(operation['path'].lower())

    if attributes_to_update:
        COGNITO_CLIENT.admin_update_user_attributes(
                UserPoolId = USERPOOL_ID,
                Username = target_user,
                UserAttributes = attributes_to_update
                )
    
    if attributes_to_remove:
        COGNITO_CLIENT.admin_delete_user_attributes(
            UserPoolId = USERPOOL_ID,
            Username = target_user,
            UserAttributeNames = attributes_to_remove)

#Helper function to create JSON response update_cognito_user
def patch_response_body(USERPOOL_ID,target_user):
    
    
    user_info = COGNITO_CLIENT.list_users(
        UserPoolId= USERPOOL_ID,
        Filter = '"username" = "' + target_user + '"'
        )
    
    attributes = user_info['Users'][0]['Attributes']
    
    name_dict={}
    meta_dict={}
    
    def attribute_unpack(attr, attributes=attributes):
        for i in range(0, len(attributes)):
            if attr in attributes[i].values():
                return attributes[i]['Value']
    
   
    
    response = '{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],'
    
    if attribute_unpack('sub'):
        response += '"id": "' + attribute_unpack('sub') + '",'
        
    response += '"userName": "' + user_info['Users'][0]['Username'] + '",'
    
    if attribute_unpack('name'):
        name_dict['formatted'] = attribute_unpack('name')
    if attribute_unpack('family_name'):
        name_dict['familyName'] = attribute_unpack('family_name')
    if attribute_unpack('given_name'):
        name_dict['givenName'] = attribute_unpack('given_name')
    if attribute_unpack('middle_name'):
        name_dict['middleName'] = attribute_unpack('middle_name')
    if name_dict:
        response += '"name" : ' + json.dumps(name_dict) + ','
    
    if attribute_unpack('nickname'):
        response += '"nickName": "' + attribute_unpack('nickname') + '",'
    
    if attribute_unpack('email'):
        response += '"emails": [{"value": "' + attribute_unpack('email') + '"}],'
    
    if attribute_unpack('address'):
        response += '"addresses": [{"streetAddress": "' + attribute_unpack('address') + '"}],'
    
    if attribute_unpack('phone_number'):
        response += '"phoneNumbers": [{"value": "' + attribute_unpack('phone_number') + '"}],'
    
    if attribute_unpack('picture'):
        response += '"photos": [{ "value": "' + attribute_unpack('picture') + '","type": "photo"}],'
    
    if attribute_unpack('locale'):
        response += '"locale": "' + attribute_unpack('locale') + '",'
    
    if attribute_unpack('zoneinfo'):
        response += '"timezone": "' + attribute_unpack('zoneinfo') + "',"
    
    response += '"active": ' + str(user_info['Users'][0]['Enabled']).lower() + ','
    
    meta_dict['resourceType'] = "User"
    meta_dict['created'] = datetime.strftime(user_info['Users'][0]['UserCreateDate'], '%Y-%m-%dT%H:%M:%SZ')
    meta_dict['lastModified'] =  datetime.strftime(user_info['Users'][0]['UserLastModifiedDate'], '%Y-%m-%dT%H:%M:%SZ')
    
    response += '"meta": ' + json.dumps(meta_dict) + '}'

    return response
    
    
# Main Lambda function
def lambda_handler(event, context):
    """The handler for the user management."""
    LOGGER.info("******************************************")
    LOGGER.info("Received event is %s", json.dumps(event))
    LOGGER.info("Received context is %s", context)
    body = ''
    method = event['httpMethod']
    
    #Check if request has body content
    if event['body']:
        body = json.loads(event['body'])
    
    # Get method user management action
    if method == 'GET':
        response_body = get_cognito_user(USERPOOL_ID, event)
        return {
            'statusCode': 200,
            'body': json.dumps(response_body),
            'headers': {
                'Content-Type': 'application/json',
            }
        }
            
    if method == 'PATCH':
        target_user = find_target_user(USERPOOL_ID, event, body)
        
        update_cognito_user(USERPOOL_ID, body, target_user)
        
        patch_response = patch_response_body(USERPOOL_ID,target_user)
        
        return {
            'statusCode' : 200,
            'body': patch_response,
            'headers': {
                'Content-Type': 'application/json'
            }
        }
        
    if method == 'DELETE':
        target_user = find_target_user(USERPOOL_ID, event, body)
        
        COGNITO_CLIENT.admin_delete_user(
            UserPoolId = USERPOOL_ID,
            Username = target_user
            )
            
        return {
            'statusCode': 204,
            'body': '',
            'headers': {
                'Content-Type': 'application/json'
            }
        }