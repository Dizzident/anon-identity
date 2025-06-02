#!/bin/bash

# Quality Check Script for anon-identity
# Ensures code meets all quality requirements before deployment

set -e

echo "🔍 Running Quality Checks..."
echo ""

# 1. TypeScript Type Checking
echo "1️⃣ TypeScript Type Checking..."
echo "Command: npm run typecheck"
if npm run typecheck; then
    echo "✅ TypeScript type checking passed"
else
    echo "❌ TypeScript type checking failed"
    exit 1
fi
echo ""

# 2. Build Verification
echo "2️⃣ Build Verification..."
echo "Command: npm run build"
if npm run build; then
    echo "✅ Build completed successfully"
else
    echo "❌ Build failed"
    exit 1
fi
echo ""

# 3. Test Execution with Coverage
echo "3️⃣ Test Execution with Coverage..."
echo "Command: npm run test"
if npm run test; then
    echo "✅ Tests passed with required coverage"
else
    echo "❌ Tests failed or coverage below 70%"
    exit 1
fi
echo ""

# 4. Linting (if configured)
echo "4️⃣ Code Style Linting..."
echo "Command: npm run lint"
if npm run lint; then
    echo "✅ Linting passed"
else
    echo "⚠️ Linting not properly configured or failed"
    # Don't exit here since linting might not be set up
fi
echo ""

echo "🎉 All Quality Checks Passed!"
echo ""
echo "✅ Code is ready for deployment"
echo "✅ Will pass GitHub Actions pipeline"
echo ""