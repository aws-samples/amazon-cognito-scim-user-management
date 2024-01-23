## Amazon Cognito SCIM user management

This solution is a lightweight SCIM interface for Cogntio that leverages Amazon API Gateway and Lamda functions to facilitate the following actions: 
- List Cognito User IDs
- Update Cognito users
- Delete Cognito users

>[!IMPORTANT]
> This solution currently does not **create** Cognito users. This is because Cognito supports just-in-time (JIT) user creation by default.

## Supported operations

### GET requests

`GET` requests will display users' usernames and associated Cognito User ID (Sub) value. There are two ways to make a `GET` request: List all users, or use filters to narrow down your list of users.

**Examples**

The following is an example request and response for listing all users:

**Example request**
```
GET https://{API Gateway stage invoke URL}/scim/v2/Users
User-Agent: Mozilla/5.0
Authorization: <Systems Manager api-token>
```
**Example Response**
```
HTTP/1.1 200 
Date: Tue, 23 Jan 2024 20:14:41 GMT
Content-Type: application/json
x-amzn-RequestId: 97d490ef-207d-4a3e-958b-f8a188a668be

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


**Example request**
```
https://{API Gateway stage invoke URL}/scim/v2/Users?filters=userName eq "alejandro_rosalez"
User-Agent: Mozilla/5.0
Authorization: <Systems Manager api-token>
```
**Example response**
```
HTTP/1.1 200 
Date: Tue, 23 Jan 2024 20:14:41 GMT
Content-Type: application/json
x-amzn-RequestId: 991caeb0-667c-4c6a-bd42-a673727da84c

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

TODO: 
- Project description
- Architectural diagram
- Limitations

Be sure to:

* Change the title in this README
* Edit your repository description on GitHub

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

