# Sourced by every shell in the agent container: exports the client certificate paths that
# git, curl, Node and Python need to pass the mTLS gateway. Written by agent-init.
if [ -r "${CERT_DIR:-/certs}/env.sh" ]; then
  . "${CERT_DIR:-/certs}/env.sh"
fi
mkdir -p "$HOME" 2>/dev/null || true
