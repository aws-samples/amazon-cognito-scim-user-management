# pylint: disable=R0914
# pylint: disable=C0301
# pylint: disable=W0612
"""User management Lambda to manage cognito users."""

import os
import json
import logging
import boto3
import botocore
import re
from datetime import datetime

LOGGER = logging.getLogger()
'''
If you need to debug code, change logging.INFO to logging.DEBUG. !!NOTE!! This may print sensitive information.
It is not recommended to use logging.DEBUG in production environments.
'''
LOGGER.setLevel('INFO')
COGNITO_CLIENT = boto3.client("cognito-idp")

# Environment variaables
USERPOOL_ID = os.getenv("USERPOOL_ID")

# Identity Provider name from Cognito, if using federated users. This allows IdPs like Okta to query the right user
IDENTITY_PROVIDER = ''
if os.getenv("IDENTITY_PROVIDER"):
    IDENTITY_PROVIDER = os.getenv("IDENTITY_PROVIDER") + '_'
    LOGGER.debug('IdP is' + IDENTITY_PROVIDER)

#Available Filters for ListUsers API
AVAILABLE_FILTERS = ['username', 'email', 'phone_number', 'name', 'given_name', 
    'family_name', 'preferred_username', 'cognito:user_status', 'status', "sub"]

# The fuction to get Cognito users using ListUsers API. Takes optional filter
def get_cognito_user(USERPOOL_ID, event, AVAILABLE_FILTERS):
    get_user_response = ''
    user_details = ''
    paginated_user_list = ''
    query_filter = ''
    number_of_results = ''
    
    if event['resource'] == '/scim/v2/Users':
        if event['queryStringParameters']:
            try:
                query_filter = event['queryStringParameters']['filter']
            except:
                query_filter = False
        if query_filter:
            regex_pattern = re.compile('\"\w{8}-\w{4}-\w{4}-\w{4}-\w{12}\"')
            query_filter = query_filter.split()
            
            LOGGER.debug("'" + query_filter[0].lower() + "'")
            #Entra ID may send '?filter=userName eq <UUID>'. This points Cognito to call ListUsers using sub, not username.
            if regex_pattern.match(query_filter[2]):
                query_filter[0] = 'sub'

            if query_filter[0].lower() in AVAILABLE_FILTERS:
            # If filter is a supported filter, call ListUsers with the filter
                if IDENTITY_PROVIDER:
                    query_filter = query_filter[0].lower() + ' = "' + IDENTITY_PROVIDER + query_filter[2].strip('"') + '"'
                else:
                    query_filter = query_filter[0].lower() + ' = ' + query_filter[2]
                    
                LOGGER.info("Looking for users using the %s filter in Cognito user pool %s", 
                    query_filter, USERPOOL_ID)    # noqa: E501
                

                paginator = COGNITO_CLIENT.get_paginator('list_users')
                paginated_user_list = paginator.paginate(
                    UserPoolId = USERPOOL_ID,
                    Filter = query_filter
                )
        # Throw error if filter is unsupported
            elif query_filter[0].lower() not in AVAILABLE_FILTERS:
                LOGGER.debug(query_filter[0].lower())
                LOGGER.info("Found unsupported filter")    # noqa: E501
                bad_filter= { 
                    "status": "400", 
                    "response": {
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                        "scimType":"invalidFilter",
                        "detail":"Request contained an unsupported filter",
                        "status": "400"
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
    elif event['resource'] == '/scim/v2/Users/{userid+}':
        user_sub = event['pathParameters']['userid']

        paginator = COGNITO_CLIENT.get_paginator('list_users')
        paginated_user_list = paginator.paginate(
            UserPoolId = USERPOOL_ID,
            Filter = 'sub = "' + user_sub + '"'
        )

    try:
        for page in paginated_user_list:
            for user in page['Users']:
                if user['Username']:
                    if query_filter:
                        if IDENTITY_PROVIDER:
                            username = user['Username'].lstrip(IDENTITY_PROVIDER)
                            user_details += '{"userName": "' + username + '", "id": "' + user['Attributes'][0]['Value'] + '", "externalId": "' + user['Attributes'][0]['Value'] + '", "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"], "active": ' + str(user['Enabled']).lower() + '},'
                        else:
                            user_details += '{"userName": "' + user['Username'] + '", "id": "' + user['Attributes'][0]['Value'] + '", "externalId": "' + user['Attributes'][0]['Value'] + '", "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"], "active": ' + str(user['Enabled']).lower() + '},'
                    else:
                        user_details += '{"userName": "' + user['Username'] + '", "id": "' + user['Attributes'][0]['Value'] + '", "externalId": "' + user['Attributes'][0]['Value'] + '", "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"], "active": ' + str(user['Enabled']).lower() + '},'

                    LOGGER.info("Found user that matched query filter in Cognito user pool %s", USERPOOL_ID)
                    LOGGER.debug("Found user %s (user id ['%s']) in Cognito user pool %s.", 
                        user['Username'], user['Attributes'][0]['Value'], USERPOOL_ID)    # noqa: E501


    except botocore.exceptions.ClientError as error:
        LOGGER.error("Boto3 client error in user management Lambda while getting Cognito user due to %s",
            error.response['Error']['Code'])     # noqa: E501

    if (len(list(user_details.split('}')))) == 1:
        number_of_results == '1'  
    else:
        number_of_results = (len(list(user_details.split('}'))) - 1)

    if not number_of_results:
        user_not_found = { 
                        "status": "200", 
                        "response":{
                            "totalResults": 0,
                            "itemsPerPage": 0,
                            "startIndex": 1,
                            "schemas": [
                                "urn:ietf:params:scim:api:messages:2.0:ListResponse"
                            ],
                            "Resources": []
                            }
                        }

        return user_not_found
    elif number_of_results == 1:
        user_details = user_details.lstrip('{').rstrip('},')
        get_user_response_payload = json.loads('{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],' + user_details + '}')

        return get_user_response_payload
    else:
        get_user_response_payload = json.loads('{"totalResults": ' + str(number_of_results) + ', "itemsPerPage": ' + str(number_of_results) + ', "startIndex": 1, "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "Resources": [' + user_details.rstrip(',') + ']}')

        return get_user_response_payload

#Helper function for PUT and PATCH requests. Takes UserID and returns to Cognito username.
def find_target_user(USERPOOL_ID, event):
    user_to_update = ''
        
    if event['pathParameters']['userid']:
        try:
            user_to_update = COGNITO_CLIENT.list_users(
                UserPoolId = USERPOOL_ID, 
                Filter = 'sub = "' + event['pathParameters']['userid'] + '"'
            )
            LOGGER.debug('ListUser response is %s', user_to_update)

            user_to_update = user_to_update['Users'][0]['Username']

            return user_to_update
        except botocore.exceptions.ClientError as error:
            LOGGER.error("Unable to find user associated with UserId %s", 
                event['pathParameters']['userid'])
            LOGGER.error("Error: %s", error.response)
            raise error
        
    
# Update a user that already exists in Cognito
def put_existing_cognito_user(USERPOOL_ID, body, user_to_update):
    attributes_to_update = []
    attributes_to_remove = []
    cognito_attributes = {}
    scim_attributes = {}

    #Attributes from Cognito
    cognito_list_users_attributes = user_to_update["Users"][0]["Attributes"]

    if len(cognito_list_users_attributes) == 1:
        attribute_dict = cognito_list_users_attributes[0]

        cognito_attributes[attribute_dict['Name']] = attribute_dict['Value']
        
    else:
        for i in range(0, (len(cognito_list_users_attributes) -1)):
            attribute_dict = cognito_list_users_attributes[i]

            cognito_attributes[attribute_dict['Name']] = attribute_dict['Value']
        

    
    #Attributes from IdP. userName not a valid attribute.
    if body['name']:
        if 'givenName' in body['name'].keys():
            scim_attributes['given_name'] = body['name']['givenName']
        if 'familyName' in body['name'].keys():
            scim_attributes['family_name'] = body['name']['familyName']
        if 'middleName' in body['name'].keys():
            scim_attributes['middle_name'] = body['name']['middleName']
        if 'formatted' in body['name'].keys():
            scim_attributes['name'] = body['name']['formatted']
    if 'emails' in body.keys():
        scim_attributes['email'] = body['emails'][0]['value']
    if 'displayName' in body.keys():
        scim_attributes['preferred_username'] = body['displayName']
    if 'locale' in body.keys():
        scim_attributes['locale'] = body['locale']
    if 'nickName' in body.keys():
        scim_attributes['nickname'] = body['nickName']
    if 'addresses' in body.keys():
        scim_attributes['address'] = body['addresses'][0]['formatted']
    if 'phoneNumbers' in body.keys():
        scim_attributes['phone_number'] = body['phoneNumbers'][0]['value']
    if 'photos' in body.keys():
        scim_attributes['picture'] = body['photos'][0]['value']
    if 'profileUrl' in body.keys():
        scim_attributes['profile'] = body['profileUrl']
    if 'timezone' in body.keys():
        scim_attributes['zoneinfo'] = body['timezone']

    for key in scim_attributes.keys():
        try:
            if scim_attributes[key] == cognito_attributes[key]:
                pass
            elif scim_attributes[key] != cognito_attributes[key]:
                attributes_to_update.append(json.loads('{"Name": "' + key + '", "Value": "' + scim_attributes[key] + '"}'))
        except KeyError:
                attributes_to_update.append(json.loads('{"Name": "' + key + '", "Value": "' + scim_attributes[key] + '"}'))

    COGNITO_CLIENT.admin_update_user_attributes(
        UserPoolId = USERPOOL_ID,
        Username = user_to_update["Users"][0]["Username"],
        UserAttributes = attributes_to_update
    )

# Function to make AdminUpdateUserAttributes and AdminDeleteUserAttributes calls
def patch_cognito_user(USERPOOL_ID, body, target_user):
    attributes_to_update = []
    look_up = {'name.givenName': 'given_name', 'name.familyName': 'family_name', 'name.middleName': 'middle_name', 'name.formatted': 'name',
                   'test': 'email', 'displayName': 'preferred_username', 'nickName': 'nickname', 'addresses[type eq "work"].streetAddress': 'address', 
                   'phoneNumbers[type eq "work"].value': 'phone_number', 'photos': 'picture', 'profileUrl': 'profile', 'zoneinfo': 'timezone'}
    
    LOGGER.info('Patching users')
    LOGGER.debug('Body is ' + str(body))
    
    for i in range(0, (len(body['Operations']) -1)):
        temp_dict = {}

        operation = body['Operations'][i]

        #Make a lookup table to map SCIM attributes to OIDC attributes
        if operation['op'].lower() == 'add':
            LOGGER.debug('***Add opperations***')
            LOGGER.debug(operation['path'])
            LOGGER.debug(operation['value'])

            if operation['path'] in look_up.keys():
                LOGGER.debug('***Opration path***')
                LOGGER.debug(operation['path'])

                temp_dict['Name'] = look_up[operation['path']]
                temp_dict['Value'] = operation['value']
                LOGGER.info(temp_dict)

                attributes_to_update.append(temp_dict)
            
            elif operation['path'] not in look_up.keys():
                pass

        LOGGER.info(attributes_to_update)

    # Call AdminUpdateUserAttributes if attributes were listed with add or replace operations
    COGNITO_CLIENT.admin_update_user_attributes(
            UserPoolId = USERPOOL_ID,
            Username = target_user,
            UserAttributes = attributes_to_update
            )
         
# Helper function to create JSON response to patch_cognito_user
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
    LOGGER.debug("******************************************")
    LOGGER.debug("Received event is %s", json.dumps(event))
    LOGGER.debug("Received context is %s", context)
    body = ''
    method = event['httpMethod']
    
    #Check if request has body content
    if event['body']:
        body = json.loads(event['body'])
    
    # Get method user management action
    if method == 'GET':
        response_body = get_cognito_user(USERPOOL_ID, event, AVAILABLE_FILTERS)
        LOGGER.debug(response_body)
        
        if 'response' in response_body.keys():
            if 'scimType' in response_body['response'].keys():
                if response_body['response']['scimType'] == 'invalidFilter':
                    return {
                        'statusCode': response_body['status'],
                        'body': json.dumps(response_body),
                        'headers': {
                            'Content-Type': 'application/json'
                        }
                    }
        
            elif response_body['response']['totalResults'] == 0:
                return {
                    'statusCode': response_body['status'],
                    'body': json.dumps(response_body),
                    'headers': {
                        'Content-Type': 'application/json'
                    }
                }
        
        else:
            return{
                'statusCode': "200",
                'body': json.dumps(response_body),
                'headers': {
                    'Content-Type': 'application/json'
                }
            }
    if method == 'PUT' or method == 'POST':

        if event['resource'] == '/scim/v2/Users/{userid+}':
            user_to_update = find_target_user(USERPOOL_ID, event, body)

            put_existing_cognito_user(USERPOOL_ID, body, user_to_update)


            return {
                "statusCode": "201",
                "body": "test",
                "headers": {
                    "Content-Type": "application/json"
                }
            }

    if method == 'PATCH':
        body = json.loads(event['body'])

        target_user = find_target_user(USERPOOL_ID, event)
        
        patch_cognito_user(USERPOOL_ID, body, target_user)
        
        patch_response = patch_response_body(USERPOOL_ID,target_user)
        
        return {
            'statusCode' : "200",
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
            'statusCode': "204",
            'body': '',
            'headers': {
                'Content-Type': 'application/json'
            }
        }