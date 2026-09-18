#!/bin/bash
# IPAL Development Environment Activation Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="$SCRIPT_DIR/ipal-dev"

if [ ! -d "$VENV_PATH" ]; then
    echo "Error: Virtual environment not found at $VENV_PATH"
    echo "Please run setup_development_venv.sh first"
    exit 1
fi

echo "Activating IPAL development environment..."
source "$VENV_PATH/bin/activate"

echo "IPAL development environment activated!"
echo "Virtual environment: $VIRTUAL_ENV"
echo "Python: $(which python)"
echo ""
echo "Available IPAL commands:"
echo "  ipal-transcriber, ipal-state-extractor, ipal-minimize, ipal-join"
echo "  ipal-iids, ipal-visualize-model, ipal-extend-alarms"
echo "  ipal-evaluate, ipal-plot-alerts, ipal-plot-metrics, ipal-tune, ipal-add-attacks"
echo ""
echo "To deactivate: deactivate"
