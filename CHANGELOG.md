# Changelog

## [1.1.0] - 2024-11-13

### Changed
- Changed TOTP setup endpoint from `GET` to `POST` method for `/realms/{realm}/khode-two-factor-auth/totp/setup/{user_id}` to follow better security practices
- Updated documentation to reflect the HTTP method change for TOTP setup endpoint

### Added
- New endpoint `/realms/{realm}/khode-two-factor-auth/totp/is-configured/{user_id}` to check if TOTP is already configured for a user
- Added documentation for the new TOTP configuration check endpoint

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