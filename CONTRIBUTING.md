# Contributing to khode-two-factor-auth

Thank you for your interest in contributing to Khode Two-Factor Auth! This extension aims to enhance Keycloak's
Two-Factor Authentication capabilities, and we welcome contributions from the community.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork:

```bash
git clone https://github.com/your-username/khode-two-factor-auth.git
cd khode-two-factor-auth
```

## Development Setup

1. Ensure you have the following prerequisites:
    - Java Development Kit (JDK)
    - Maven
    - Keycloak server (for testing)

2. Build the project:

```bash
mvn clean package
```

3. Deploy to Keycloak for testing:

```bash
cp target/khode-two-factor-auth.jar /path/to/keycloak/standalone/deployments/
```

## Making Changes

1. Create a new branch for your feature/fix:

```bash
git checkout -b feature/your-feature-name
```

2. Make your changes
3. Test thoroughly:
    - Ensure all endpoints work as expected
    - Test error scenarios
    - Verify authentication and authorization

4. Commit your changes:

```bash
git add .
git commit -m "Add a descriptive commit message"
```

5. Push to your fork:

```bash
git push origin feature/your-feature-name
```

6. Open a Pull Request from your fork to our main branch

## Pull Request Guidelines

* Focus on a single feature or fix per PR
* Update documentation for any changed functionality
* Follow existing code style and patterns
* Include tests for new features
* Ensure all tests pass before submitting
* Update the README.md if necessary

## Areas for Contribution

We welcome contributions in these areas:

* Additional TOTP management features
* Enhanced security measures
* Performance improvements
* Documentation improvements
* Bug fixes
* Test coverage improvements

## Bug Reports

When filing an issue, please include:

* Clear description of the problem
* Steps to reproduce
* Expected vs actual behavior
* Your environment:
    - Keycloak version
    - Java version
    - Operating system
* Relevant logs or error messages

## Feature Requests

We welcome feature requests! Please provide:

* Clear description of the proposed feature
* Use cases and benefits
* Any implementation ideas
* Potential impact on existing functionality

## Questions?

Feel free to open an issue for any questions about:

* Setting up the development environment
* Implementation details
* Best practices
* Feature discussions

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.

## Contact

For any questions or concerns, please:

* Open an issue on GitHub
* Visit the repository: https://github.com/chornthorn/khode-two-factor-auth

Thank you for contributing to khode-two-factor-auth!