#!/usr/bin/env bash

set -eo pipefail

# This script should be called from the root of the repository
version=$1

# Update package.json version
npm version $version --no-git-tag-version

# Install dependencies
npm install

# Run linting first
npm run lint

# Build the package
npm run build

# Run tests to ensure everything passes
npm test

# Publish to npm with 'latest' tag
npm publish --access public
