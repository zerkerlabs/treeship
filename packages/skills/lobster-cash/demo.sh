#!/bin/bash
set -e

echo "=== Lobster Cash Skill Demo ==="
echo ""

# -----------------------------------------------
# Check dependencies
# -----------------------------------------------
echo "[preflight] Checking dependencies..."

if ! command -v treeship &> /dev/null; then
  echo "ERROR: treeship is not installed or not on PATH."
  exit 1
fi
echo "  treeship: $(treeship --version)"

if ! command -v lobstercash &> /dev/null; then
  echo "ERROR: lobstercash is not installed or not on PATH."
  exit 1
fi
echo "  lobstercash: $(lobstercash --version 2>/dev/null || echo 'available')"

echo "[preflight] All dependencies found."
echo ""

# -----------------------------------------------
# Start session
# -----------------------------------------------
echo "[session] Starting Treeship session..."
SESSION_ID=$(treeship session start --skill lobster-cash --json | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "  Session ID: ${SESSION_ID:-demo-session}"
echo ""

# -----------------------------------------------
# Check balance (attested)
# -----------------------------------------------
echo "[balance] Wrapping lobstercash balance check..."
treeship wrap lobstercash balance || echo "  (balance check placeholder, wallet may not be configured)"
echo ""

# -----------------------------------------------
# Show payment intent
# -----------------------------------------------
echo "[intent] Demo payment intent:"
echo "  Type:      send"
echo "  Recipient: demo@lobster.cash"
echo "  Amount:    0.01"
echo "  Currency:  USDC"
echo ""

# -----------------------------------------------
# Attest approval
# -----------------------------------------------
echo "[approval] Attesting human approval for demo payment..."
treeship wrap echo "APPROVED: send 0.01 USDC to demo@lobster.cash" || echo "  (approval attestation placeholder)"
echo ""

# -----------------------------------------------
# Execute payment (placeholder if wallet not funded)
# -----------------------------------------------
echo "[execute] Wrapping demo payment..."
treeship wrap lobstercash send demo@lobster.cash 0.01 USDC 2>/dev/null || echo "  (send placeholder, wallet not funded for demo)"
echo ""

# -----------------------------------------------
# Close session
# -----------------------------------------------
echo "[session] Closing session..."
treeship session close 2>/dev/null || echo "  (session close placeholder)"
echo ""

# -----------------------------------------------
# Push to hub
# -----------------------------------------------
echo "[hub] Pushing attestation bundle to hub..."
treeship hub push 2>/dev/null || echo "  (hub push placeholder)"
echo ""

# -----------------------------------------------
# Verification URL
# -----------------------------------------------
echo "[verify] Attestation verification URL:"
echo "  https://hub.treeship.dev/verify/${SESSION_ID:-demo-session}"
echo ""
echo "=== Demo complete ==="
