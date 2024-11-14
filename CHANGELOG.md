# Changelog

## [1.1.1] - 2024-11-15

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