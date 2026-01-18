# Contributing to TinyVault

Thank you for your interest in contributing to TinyVault!

## Development Guidelines

For detailed development standards, code organization, and security requirements, please refer to [AGENTS.md](AGENTS.md).

## Getting Started

1. Fork the repository
2. Clone your fork
3. Set up the development environment:
   ```bash
   task setup
   ```
4. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Before Submitting

Run the full check suite:
```bash
task check
```

This ensures:
- Code passes linting (`task lint`)
- All tests pass (`task test`)
- Project builds successfully (`task build:all`)

## Pull Request Process

1. Update documentation if you're changing behavior
2. Add tests for new functionality
3. Ensure all checks pass
4. Submit a PR with a clear description of changes

## Reporting Issues

When reporting bugs, please include:
- Steps to reproduce
- Expected vs actual behavior
- Go version and OS
- Relevant logs (with sensitive data redacted)

## Security Vulnerabilities

For security issues, please email the maintainer directly instead of opening a public issue.

## Code of Conduct

Be respectful and constructive in all interactions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
