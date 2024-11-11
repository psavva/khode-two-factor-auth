# khode-two-factor-auth

khode-two-factor-auth is a Keycloak extension that provides a REST API for managing Time-based One-Time Password (TOTP)
authentication. This extension allows you to set up, verify, enable, disable, and validate TOTP for users in a Keycloak
realm.

## Features

- Setup TOTP for a user
- Verify and enable TOTP
- Get TOTP status for a user
- Validate TOTP code
- Disable TOTP for a user

This extension is designed to integrate seamlessly with existing Keycloak deployments, offering developers and
administrators greater flexibility in implementing and managing 2FA.

## Installation

1. Build the project using Maven:
   ```
   mvn clean package
   ```

2. Copy the resulting JAR file to the Keycloak deployments directory:
   ```
   cp target/khode-two-factor-auth.jar /path/to/keycloak/standalone/deployments/
   ```

3. Restart Keycloak to load the new extension.

## Usage

This extension provides the following REST endpoints:

### Setup TOTP

```http
GET /realms/{realm}/khode-two-factor-auth/totp/setup/{user_id}
```

Returns:

```json
{
  "secret": "BASE32_ENCODED_SECRET",
  "qrCode": "otpauth://totp/...",
  "policy": {
    "algorithm": "HmacSHA1",
    "digits": 6,
    "period": 30,
    "type": "totp"
  },
  "supportedApplications": [
    "FreeOTP",
    "Google Authenticator"
  ]
}
```

Generates a TOTP secret for the user and returns the secret and QR code.

### Verify and Enable TOTP

```http
POST /realms/{realm}/khode-two-factor-auth/totp/verify/{user_id}
Content-Type: application/json

{
    "code": "123456"
}
```

Returns:

```json
{
  "message": "TOTP enabled successfully",
  "enabled": true
}
```

Verifies the TOTP code and enables TOTP for the user.

### Get TOTP Status

```http
GET /realms/{realm}/khode-two-factor-auth/totp/status/{user_id}
```

Returns:

```json
{
  "enabled": true,
  "credentials": [
    {
      "id": "credential-id",
      "type": "otp",
      "createdDate": 1234567890
    }
  ]
}
```

Returns the TOTP status and credentials for the user.

### Validate TOTP Code

```http
POST /realms/{realm}/khode-two-factor-auth/totp/validate/{user_id}
Content-Type: application/json

{
    "code": "123456"
}
```

Returns:

```json
{
  "message": "TOTP code validated successfully",
  "valid": true
}
```

Validates the TOTP code for an existing TOTP setup.

### Disable TOTP

```http
DELETE /realms/{realm}/khode-two-factor-auth/totp/{user_id}
```

Returns:

```json
{
  "message": "TOTP disabled successfully",
  "enabled": false
}
```

## Authentication

All endpoints require authentication using a bearer token with appropriate permissions.

## Error Handling

The extension provides appropriate error responses for various scenarios, such as invalid codes, missing TOTP setup,
etc.

## Dependencies

- Keycloak
- Jakarta RESTful Web Services (JAX-RS)
- Microprofile OpenAPI
- Lombok

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
