## Amazon Cognito SCIM user management

This sample solution is a lightweight SCIM interface for Cognito that leverages Amazon API Gateway and Lambda functions to facilitate the following actions: 
- List Cognito User IDs
- Update Cognito users
- Delete Cognito users

>[!IMPORTANT]
> This solution currently does not **create** Cognito users. This is because Cognito supports just-in-time (JIT) user creation by default.

## Deployment

1. Download the repo
1. Create an S3 bucket and add the .zip files `user_management_lambda.zip` and `lambda authorizer.zip` into the bucket
1. Import `user_management_cloudformation.yaml` into CloudFormation. Enter the parameters requested by the template.
1. Retrieve the API key from AWS Secrets Manager
1. Provide the API key and SCIM endpoint URL to your IdP's SCIM service (or you can make your own API calls using cURL or similar)
## Supported operations

### GET requests

The `/Users` endpoint allows `GET` requests to display users' usernames and associated Cognito User ID (Sub) values. There are two ways to make a `GET` request: List all users, or use filters to narrow down your list of users.

**Listing all users**

The following is an example request and response for listing all users:

**Example request**
```
GET https://{API Gateway stage invoke URL}/scim/v2/Users
User-Agent: Mozilla/5.0
Authorization: <Secrets Manager api-token>
```
**Example response**
```
HTTP/1.1 200 
Date: Tue, 23 Jan 2024 20:14:41 GMT
Content-Type: application/json
x-amzn-RequestId: a1b2c3d4-5678-90ab-cdef-EXAMPLEaaaaa

{
    "totalResults": 2,
    "itemsPerPage": 2,
    "startIndex": 1,
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    ],
    "Resources": [
        {
            "userName": "alejandro_rosalez",
            "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
        },
        {
            "userName": "jane_doe",
            "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE22222"
        }
    ]
}
```

**Filters**

The following filters are supported:
- `username`
- `email`
- `phone_number` 
- `name`
- `given_name`
- `family_name`
- `preferred_username` 
- `cognito:user_status` 
- `status` 
- `sub`

**Filter example**

`filter=<filterAttribute> eq "<filterValue>"`

The following is an example request and response for filtering users:

**Example request**
```
https://{API Gateway stage invoke URL}/scim/v2/Users?filters=userName eq "alejandro_rosalez"
User-Agent: Mozilla/5.0
Authorization: <Secrets Manager api-token>
```
**Example response**
```
HTTP/1.1 200 
Date: Tue, 23 Jan 2024 20:20:20 GMT
Content-Type: application/json
x-amzn-RequestId: a1b2c3d4-5678-90ab-cdef-EXAMPLEbbbbb

{
    "totalResults": 1,
    "itemsPerPage": 1,
    "startIndex": 1,
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    ],
    "Resources": [
        {
            "userName": "alejandro_rosalez",
            "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
        }
    ]
}
```

### PATCH requests

The `/Users` endpoint allows `PATCH` requests to update user attrbutes. Supported attributes are the writable attributes within your Cognito User Pool. This includes standard attributes supported by Cognito (based on the [OpenID Connect standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)) and any custom attributes you have created within your user pool.

- Supported actions are `add`, `replace`, and `remove`
- A value is required for `add` and `remove` operations
- A path is required for `remove` operations
- Any writable value configured in the user pool can be modified 

>[!TIP]
> To verify an attribute which must be verified in the same API request, you must include the `email_verified` or `phone_number_verified` attribute with a value of `"true"`. This will not send a verification message to the updated user.

>[!NOTE]
>`PATCH` operations currently respond only with populated user attributes that are included in the [User Resource Schma](https://datatracker.ietf.org/doc/html/rfc7643#section-4.1) from the SCIM Core Schema RFC (RFC-7643). This means that all user attributes may not be returned, especially any custom attributes defined in the user pool.

**Example request**
```
PATCH https://{API Gateway stage invoke URL}/scim/v2/Users/{Cognito user ID}
User-Agent: Mozilla/5.0
Authorization: <Secrets Manager api-token>

{
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    ],
    "Operations": [
        {
            "op": "replace",
            "path": "email",
            "value": "alejandro_rosalez@example.org"
        }
    ]
}
```
>[!TIP]
> Retrieve the user's Cognito user ID by using the `GET` method. You can also get this information in the Cognito console, or using the [ListUsers](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsers.html) Cognito API.

**Example response**
```
HTTP/1.1 200 
Date: Fri, 26 Jan 2024 17:43:19 GMT
Content-Type: application/json
x-amzn-RequestId: a1b2c3d4-5678-90ab-cdef-EXAMPLEbbbbb

{
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:User"
    ],
    "id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
    "userName": "alejandro_rosalez",
    "name": {
        "familyName": "Rosalez",
        "givenName": "Alejandro"
    },
    "emails": [
        {
            "value": "alejandro_rosalez@example.com"
        }
    ],
    "addresses": [
        {
            "streetAddress": "123 Any Street, Any Town, USA"
        }
    ],
    "phoneNumbers": [
        {
            "value": "+15125550100"
        }
    ],
    "active": true,
    "meta": {
        "resourceType": "User",
        "created": "2024-01-23T20:39:24Z",
        "lastModified": "2024-01-26T17:43:19Z"
    }
}
```

### DELETE requests

The `/Users` endpoint can delete a user with `DELETE` request.

**Example request**
```
DELETE https://{API Gateway stage invoke URL}/scim/v2/Users/{Cognito user ID}
User-Agent: Mozilla/5.0
Authorization: <Secrets Manager api-token>
```

**Example response**
```
HTTP/1.1 204 
Date: Mon, 29 Jan 2024 19:06:15 GMT
Content-Type: application/json
x-amzn-RequestId: a1b2c3d4-5678-90ab-cdef-EXAMPLEbbbbb
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

## Legal Disclaimer

You should consider doing your own independent assessment before using the content in this library for production purposes. This may include (amongst other things) testing, securing, and optimizing services and other content, provided in this solution, based on your specific quality control practices and standards.
