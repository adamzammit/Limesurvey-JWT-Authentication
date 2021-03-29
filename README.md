# LimeSurvey JWT Authentication
LimeSurvey authentication plugin for authenticating users based on a JWT (Json Web Token)

## Requirements
- LimeSurvey 3.XX

## Installation instructions
- Download the zip from the [releases](https://github.com/adamzammit/Limesurvey-JWT-Authentication/releases) page and extract to your plugins folder.
- Rename the downloaded folder to AuthJWT
- You will also need to download the zip of  https://github.com/firebase/php-jwt and extract as the php-jwt folder within the plugin folder.

- You can also clone directly from git: go to your plugins directory and type: (this will include the php-jwt code in one hit)
```
git clone --recurse-submodules https://github.com/adamzammit/Limesurvey-JWT-Authentication AuthJWT
```

## Configuration options

### Required
- **Method for JWT authentication**: choose which hashing/key method for JWT authentication
- **Shared secret key (for ES256,HS256,HS384 or HS512 methods) or Public Key (for RS256,RS384,RS512 methods) for JWT authentication ?**: Shared password or public key used
- **Name of attribute containing the username (required and unique)**: The JWT attribute that will contain the LimeSurvey username to be authenticated against/created

### Optional
- **Name of attribute containing the email address (leave blank to auto generate)**: the attribute in the JWT that contains the email address
- **Name of attribute containing the display name (leave blank to auto generate based on users name)**: the attribute returned in the JWT that will be the users human friendly name
- **Auto create users**: check if the user exists in the local database and if not the plugin creates the user from the JWT metadata
- **Auto update users**: check if the JWT attributes have different attribute values for email and name and update them on LimeSurvey
- **Storage base**: LimeSurvey internal configuration options, use it only if you know what you are doing. Configures where the plugin settings are stored.
- **Logout Redirect URL**: configures where should the user be redirected after the logout path
- **Allow initial user to login via JWT**: Check this if you want the admin user to be able to use JWT also
- **Permissions**: Choose the default permissions given to newly created users

## Usage
- Pass a "Authorization Bearer" header containing the JWT token to the login page to pre-fill the login with the JWT token
- Pass the JWT token as a GET request ( eg: http://localhost/index.php/admin/authentication/sa/login/jwt/jwttokengoeshere )
- The JWT token must contain at least one attribute that is the username field in LimeSurvey - this must be set as the attribute in the plugin configuration
- The system will respect the expiry times set on tokens

## Resources

- Generate test JWT tokens here: https://jwt.io/#debugger


## Acknowledgements

- LimeSurvey: https://github.com/LimeSurvey/LimeSurvey
- PHP JWT library: https://github.com/firebase/php-jwt
- LimeSurvey SAML authentication plugin (this is based on that plugin): https://github.com/e-ucm/Limesurvey-SAML-Authentication
 
## Licence

GPLv3
