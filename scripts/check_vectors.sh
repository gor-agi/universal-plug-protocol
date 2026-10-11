#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Cross-implementation checks with Node as the independent implementation.
set -e
cd "$(dirname "$0")/.."
py=python3; [ -x .venv/bin/python ] && py=.venv/bin/python
node spec/vectors/generate_jcs.mjs | "$py" -c "import json,sys; a=json.load(sys.stdin); b=json.load(open('spec/vectors/jcs.json')); a.pop('generator'); b.pop('generator'); sys.exit('jcs.json differs from the Node generator' if a != b else 0)"
echo "vectors: jcs.json reproduces"
node spec/vectors/verify_protocol.mjs
