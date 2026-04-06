#!/usr/bin/env bash
set -euo pipefail

APP_NAME="${1:-sectalon}"

python3 -m pip install -r requirements.txt -r requirements-build.txt

# Ensure packaged Playwright browser cache is not embedded into binary.
PW_LOCAL_BROWSERS_PATH="$(python3 - <<'PY'
from pathlib import Path
import playwright
print(Path(playwright.__file__).parent / "driver" / "package" / ".local-browsers")
PY
)"
rm -rf "${PW_LOCAL_BROWSERS_PATH}"

pyinstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name "${APP_NAME}" \
  --collect-submodules playwright \
  --collect-all openai \
  talon_v1.py

echo
echo "Build complete:"
echo "  dist/${APP_NAME}"
echo
echo "Run example:"
echo "  ./dist/${APP_NAME} \"https://example.com\" --llm-provider ollama --llm-model gemma4"
