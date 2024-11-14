# Changelog

## [1.2.0] - 2024-11-15

### Added
- New endpoint `/realms/{realm}/khode-two-factor-auth/totp/disable-with-validation/{user_id}` for secure TOTP disabling
- Standardized response codes across all endpoints (0-8) for better error handling
- New field "code" in all API responses for programmatic handling
- Enhanced response messages with consistent format

### Changed
- Updated all API responses to include standardized response codes:
  - 0: Success
  - 1: Invalid user ID
  - 2: Invalid code format
  - 3: TOTP not enabled
  - 4: TOTP already enabled
  - 5: Server error
  - 6: TOTP setup required
  - 7: Invalid TOTP code
  - 8: Operation failed
- Enhanced error messages with more descriptive information
- Improved response structure for better consistency

### Security
- Added validation step before TOTP disabling with new disable-with-validation endpoint
- Enhanced input validation across all endpoints

### Documentation
- Added API Response Codes reference table
- Updated all API examples with new standardized response format
- Added error handling section with example responses
- Enhanced endpoint descriptions with more detailed information

## [1.1.1] - 2024-11-14

### Changed
- Improved error handling across all endpoints
- Added comprehensive validation checks for user IDs and TOTP codes
- Introduced helper methods for better code organization and reusability
- Enhanced logging for error scenarios

### Fixed
- Improved error messages for better clarity
- Better handling of edge cases in TOTP operations

## [1.1.0] - 2024-11-13

### Added
- New endpoint `/realms/{realm}/khode-two-factor-auth/totp/is-configured/{user_id}` to check if TOTP is already configured for a user
- Added documentation for the new TOTP configuration check endpoint

### Changed
- Changed TOTP setup endpoint from `GET` to `POST` method for `/realms/{realm}/khode-two-factor-auth/totp/setup/{user_id}` to follow better security practices
- Updated documentation to reflect the HTTP method change for TOTP setup endpoint

### Security
- Improved security by changing TOTP setup to use POST instead of GET to prevent secret exposure in URL/logs

## [1.0.0] - Initial Release

### Added
- Initial implementation of TOTP management REST API
- TOTP setup endpoint
- TOTP verification and enabling
- TOTP status checking
- TOTP code validation
- TOTP disabling
- Basic documentation and installation instructions