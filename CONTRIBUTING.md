# 🤝 Contributing to SSHCracker

We love your input! We want to make contributing to SSHCracker as easy and transparent as possible.

## 📱 Community

Join our communities for discussions and support:
- **English Community**: [@MatrixORG](https://t.me/MatrixORG)
- **Persian Community**: [@MatrixFa](https://t.me/MatrixFa)
- **Chat Group**: [@DD0SChat](https://t.me/DD0SChat)

## 🚀 Development Process

We use GitHub to host code, track issues and feature requests, and accept pull requests.

### Pull Requests
1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. Ensure your code follows Go best practices
4. Make sure your code builds successfully
5. Update documentation if needed
6. Issue that pull request!

### Any contributions you make will be under the MIT License
When you submit code changes, your submissions are understood to be under the same [MIT License](LICENSE) that covers the project.

## 🐛 Report bugs using GitHub Issues
We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/Matrix-Community-ORG/SSHCracker/issues).

**Great Bug Reports** tend to have:
- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening)

## 🎯 Feature Requests
We welcome feature requests! Please:
1. Check if the feature already exists
2. Open an issue with the `enhancement` label
3. Describe the feature and why it would be useful
4. Be patient - we review all requests

## 💻 Coding Style

### Go Code Style
- Follow standard Go formatting (`go fmt`)
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small
- Handle errors appropriately
- For NLA Checker, follow similar structure to SSHCracker for consistency

### Commit Messages
- Use descriptive commit messages
- Start with an emoji if appropriate
- Keep the first line under 50 characters
- Use the body to explain what and why
- Use 🛡️ for NLA-related changes

Example:
```
🐛 Fix honeypot detection false positives

The banner analysis was too aggressive and flagged legitimate
servers. This commit adjusts the threshold and adds more
sophisticated pattern matching.
```

## 🧪 Testing

### Running Tests
```bash
go test ./...
```

### Building
```bash
go build ssh.go
```

### Code Quality
```bash
go vet ./...
go fmt ./...
```

## 📋 Issue Labels

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Improvements or additions to documentation
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention is needed
- `question` - Further information is requested

## 🔒 Security

Please do not open issues for security vulnerabilities. Instead:
1. Contact us privately through Telegram
2. Email the maintainers
3. We'll work with you to address the issue

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be recognized in our README and release notes!

---

Thank you for contributing! 🎉
