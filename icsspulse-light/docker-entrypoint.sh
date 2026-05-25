#!/bin/bash
set -e

echo "=========================================="
echo "ICSSPulse Light - Protocol Controllers"
echo "=========================================="

# Create necessary directories
mkdir -p /app/opcua_certs
echo "✓ Directories created"

echo ""
echo "=========================================="
echo "Starting ICSSPulse Light application..."
echo "=========================================="
echo ""

# Execute the main command
exec "$@"