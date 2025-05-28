# GitHub Workflows

This directory contains GitHub Actions workflows for CI/CD and release management.

## Active Workflows

### 1. CI (`ci.yml`)
- **Trigger**: Push to any branch, pull requests
- **Purpose**: Run tests and build checks on Node.js 18.x and 20.x
- **Actions**: Install dependencies, build, run tests

### 2. Auto Release (`auto-release.yml`)
- **Trigger**: Push to main branch with changes to src/, contracts/, or config files
- **Purpose**: Automatically version bump, create release, and publish to npm
- **Version Bump Logic**:
  - `fix:`, `bugfix:`, `hotfix:` → patch version (1.0.0 → 1.0.1)
  - `feat:`, `feature:` → minor version (1.0.0 → 1.1.0)
  - `breaking:`, `BREAKING CHANGE` → major version (1.0.0 → 2.0.0)
  - Other commits → patch version by default
- **Requirements**: `NPM_TOKEN` secret for npm publishing

### 3. Manual Release and Publish (`release-and-publish.yml`)
- **Trigger**: Manual workflow dispatch
- **Purpose**: Manually trigger version bump, release, and npm publish
- **Options**: Choose between patch, minor, or major version bump
- **Use Case**: When you want explicit control over versioning

## Legacy Workflows (Deprecated)

### 1. Release (`release.yml`)
- **Status**: Deprecated, use `auto-release.yml` or `release-and-publish.yml`
- **Trigger**: Manual tag push (v*)
- **Purpose**: Create GitHub release with artifacts

### 2. Publish to npm (`publish.yml`)
- **Status**: Deprecated, use `auto-release.yml` or `release-and-publish.yml`
- **Trigger**: When a release is published
- **Purpose**: Publish package to npm

## Commit Message Convention

To leverage automatic versioning, use these commit message prefixes:

- `fix:` - Bug fixes (patch release)
- `feat:` - New features (minor release)
- `breaking:` or include `BREAKING CHANGE` - Breaking changes (major release)
- `chore:` - Maintenance tasks (no release)
- `docs:` - Documentation changes (no release)
- `test:` - Test changes (no release)

## Required Secrets

- `NPM_TOKEN`: npm authentication token for publishing packages
  - Get from: https://www.npmjs.com/settings/YOUR_USERNAME/tokens
  - Set in: Repository Settings → Secrets and variables → Actions

## Usage Examples

### Automatic Release (Recommended)
```bash
# This will trigger a patch release
git commit -m "fix: resolve authentication issue"
git push origin main

# This will trigger a minor release
git commit -m "feat: add support for blockchain storage"
git push origin main

# This will trigger a major release
git commit -m "breaking: change API interface for DID creation"
git push origin main
```

### Manual Release
1. Go to Actions tab in GitHub
2. Select "Release and Publish" workflow
3. Click "Run workflow"
4. Choose version type (patch/minor/major)
5. Click "Run workflow" button

## Notes

- The `[skip ci]` tag in commit messages prevents infinite loops
- Version bumps are automatically committed back to main
- All releases are created with auto-generated release notes
- npm packages are published with provenance for security