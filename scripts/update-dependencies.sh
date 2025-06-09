#!/bin/bash
# Secure dependency update script for rusty-socks
# This script helps maintain pinned dependencies while ensuring security

set -euo pipefail

echo "🔐 Rusty Socks - Secure Dependency Update Script"
echo "================================================="

# Check if cargo-audit is installed
if ! command -v cargo-audit &> /dev/null; then
    echo "❌ cargo-audit not found. Installing..."
    cargo install cargo-audit
fi

# Check if cargo-outdated is installed
if ! command -v cargo-outdated &> /dev/null; then
    echo "❌ cargo-outdated not found. Installing..."
    cargo install cargo-outdated
fi

echo ""
echo "🔍 Step 1: Security audit of current dependencies"
echo "------------------------------------------------"
if ! cargo audit; then
    echo "⚠️  Security vulnerabilities found! Please review and update vulnerable dependencies."
    echo "   Consider updating vulnerable crates before proceeding."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "✅ No known security vulnerabilities found."
fi

echo ""
echo "📦 Step 2: Check for outdated dependencies"
echo "----------------------------------------"
cargo outdated

echo ""
echo "🛡️  Step 3: Update recommendations"
echo "---------------------------------"
echo "For security updates:"
echo "1. Review each outdated dependency for security advisories"
echo "2. Test updates in a separate branch"
echo "3. Update Cargo.toml with exact versions (=x.y.z)"
echo "4. Run full test suite"
echo "5. Update this script with new versions"

echo ""
echo "📋 Step 4: Manual update process"
echo "-------------------------------"
echo "To update a specific dependency (example with tokio):"
echo '1. cargo update -p tokio'
echo '2. cargo tree --depth 1 | grep tokio'
echo '3. Update Cargo.toml: tokio = "=NEW_VERSION"'
echo '4. cargo test'
echo '5. cargo audit'

echo ""
echo "🔄 Step 5: Bulk update process (use with caution)"
echo "-----------------------------------------------"
read -p "Do you want to check for bulk updates? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Generating dependency tree before update..."
    cargo tree --depth 1 > dependencies-before.txt
    
    echo "Creating backup of Cargo.toml..."
    cp Cargo.toml Cargo.toml.backup
    
    echo "⚠️  This will update Cargo.lock. Review changes carefully!"
    echo "You will need to manually update Cargo.toml with exact versions."
    read -p "Continue with cargo update? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cargo update
        echo "Generating dependency tree after update..."
        cargo tree --depth 1 > dependencies-after.txt
        
        echo ""
        echo "📊 Dependency changes:"
        echo "--------------------"
        diff dependencies-before.txt dependencies-after.txt || true
        
        echo ""
        echo "⚠️  IMPORTANT: Update Cargo.toml with new exact versions!"
        echo "Use the output above to update version numbers in Cargo.toml"
        echo "Then run: cargo audit && cargo test"
    fi
fi

echo ""
echo "✅ Dependency security check complete!"
echo "Remember to:"
echo "- Update Cargo.toml with exact versions (=x.y.z)"
echo "- Run cargo test to ensure everything works"
echo "- Run cargo audit to check for vulnerabilities"
echo "- Commit changes with security update notes"