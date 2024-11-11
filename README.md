# khode-two-factor-auth
A comprehensive Keycloak extension that enhances the platform's Two-Factor Authentication (2FA) capabilities by providing advanced management and control over Time-based One-Time Password (TOTP) functionality. This extension offers a set of RESTful APIs that allow for programmatic setup, verification, management, and disabling of TOTP for users, making it ideal for custom implementations and integrations.

Key highlights of this extension include:

1. **Streamlined TOTP Setup**: Easily generate and provide TOTP secrets and QR codes for users, facilitating a smooth onboarding process for 2FA.

2. **Flexible Verification**: Verify TOTP codes and enable 2FA for users through a simple API call, allowing for custom verification flows.

3. **Status Monitoring**: Quickly retrieve the current TOTP status for any user, including details about their TOTP credentials.

4. **Code Validation**: Validate TOTP codes on-demand, useful for implementing custom authentication flows or periodic security checks.

5. **Easy Disabling**: Programmatically disable TOTP for users when needed, providing full control over the 2FA lifecycle.

6. **Security-First Approach**: All endpoints require proper authentication and authorization, ensuring that sensitive 2FA operations are protected.

7. **Compliance Ready**: Helps organizations meet security compliance requirements by providing robust 2FA management capabilities.

This extension is designed to integrate seamlessly with existing Keycloak deployments, offering developers and administrators greater flexibility in implementing and managing 2FA. Whether you're building a custom user portal, integrating with a mobile app, or automating security processes, khode-two-factor-auth provides the tools you need to handle TOTP-based 2FA effectively and securely.

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

```markdown
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
    "supportedApplications": ["FreeOTP", "Google Authenticator"]
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

The extension provides appropriate error responses for various scenarios, such as invalid codes, missing TOTP setup, etc.

## Dependencies

- Keycloak
- Jakarta RESTful Web Services (JAX-RS)
- Microprofile OpenAPI
- Lombok

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
