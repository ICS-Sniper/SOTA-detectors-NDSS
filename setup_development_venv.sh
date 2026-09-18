#!/bin/bash
set -e  # Exit on any error

# === IPAL Development Environment Setup (venv version) ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_NAME="ipal-dev"
VENV_PATH="$SCRIPT_DIR/$VENV_NAME"

echo "=== IPAL Development Environment Setup (venv) ==="
echo "Script directory: $SCRIPT_DIR"
echo "Virtual environment: $VENV_PATH"
echo ""

# ----------------------------
# Function: check_python_version
# ----------------------------
check_python_version() {
    echo "Checking Python version..."
    PYTHON_CMD=""
    for cmd in python3.12 python3.11 python3.10 python3.9 python3 python; do
        if command -v $cmd &> /dev/null; then
            VERSION=$($cmd -V 2>&1 | grep -oE '[0-9]+\.[0-9]+')
            if [[ "$VERSION" =~ ^3\.(9|10|11|12)$ ]]; then
                PYTHON_CMD=$cmd
                echo "Found compatible Python: $cmd (version $VERSION)"
                break
            fi
        fi
    done

    if [ -z "$PYTHON_CMD" ]; then
        echo "❌ Error: Compatible Python version not found."
        echo "Please install Python 3.9–3.12, e.g.:"
        echo "  sudo apt install python3.10 python3.10-venv python3.10-dev"
        exit 1
    fi

    export PYTHON_CMD

    # Check if venv module is available
    if ! $PYTHON_CMD -m venv --help &>/dev/null; then
        echo "⚠️  python3-venv not available. Installing..."
        PY_MAJOR=$(echo "$VERSION" | cut -d. -f1)
        PY_MINOR=$(echo "$VERSION" | cut -d. -f2)
        sudo apt-get update -y
        sudo apt-get install -y "python${PY_MAJOR}.${PY_MINOR}-venv"
    else
        echo "✓ python-venv module available"
    fi
}

# ----------------------------
# Function: create_venv
# ----------------------------
create_venv() {
    echo "Creating virtual environment..."
    if [ -d "$VENV_PATH" ]; then
        echo "Virtual environment already exists, removing old one..."
        rm -rf "$VENV_PATH"
    fi
    $PYTHON_CMD -m venv "$VENV_PATH"
    echo "✓ Virtual environment created successfully"
}

# ----------------------------
# Function: activate_venv
# ----------------------------
activate_venv() {
    echo "Activating virtual environment..."
    source "$VENV_PATH/bin/activate"
    echo "✓ Virtual environment activated: $VIRTUAL_ENV"
}

# ----------------------------
# Function: setup_pip
# ----------------------------
setup_pip() {
    echo "Upgrading pip and installing base tools..."
    python -m pip install --upgrade pip setuptools wheel
}

# ----------------------------
# Function: check_system_deps
# ----------------------------
check_system_deps() {
    echo "Checking system dependencies..."
    if ! command -v tshark &> /dev/null; then
        echo "⚠️  tshark not found. Installing..."
        sudo apt-get update -y
        sudo apt-get install -y tshark
    else
        echo "✓ tshark found"
    fi

    echo "Note: Some IDS algorithms require libgsl (GNU Scientific Library)"
    echo "If you encounter compilation errors, install it:"
    echo "  sudo apt-get install libgsl-dev"
}

# ----------------------------
# Function: install_dependencies
# ----------------------------
install_dependencies() {
    echo "Installing Python dependencies from all modules..."
    TEMP_REQ="$SCRIPT_DIR/temp_combined_requirements.txt"
    echo "# Combined requirements" > "$TEMP_REQ"

    # Root + submodules
    for module in "" ipal_transcriber ipal_ids_framework ipal_evaluate; do
        REQ_FILE="$SCRIPT_DIR/$module/requirements.txt"
        if [ -f "$REQ_FILE" ]; then
            echo "# $REQ_FILE" >> "$TEMP_REQ"
            cat "$REQ_FILE" >> "$TEMP_REQ"
            echo "" >> "$TEMP_REQ"
        fi
    done

    # Remove duplicates & install
    sort -u "$TEMP_REQ" -o "$TEMP_REQ"
    if [ -f "$SCRIPT_DIR/constraints.txt" ]; then
        python -m pip install -r "$TEMP_REQ" -c "$SCRIPT_DIR/constraints.txt"
    else
        python -m pip install -r "$TEMP_REQ"
    fi

    rm -f "$TEMP_REQ"
}

# ----------------------------
# Function: install_ipal_modules
# ----------------------------
install_ipal_modules() {
    echo "Installing IPAL modules in development mode..."
    for module in ipal_transcriber ipal_ids_framework ipal_evaluate; do
        MODULE_PATH="$SCRIPT_DIR/$module"
        if [ -d "$MODULE_PATH" ]; then
            echo "Installing $module..."
            python -m pip install -e "$MODULE_PATH"
        fi
    done
}

# ----------------------------
# Main
# ----------------------------
main() {
    echo "Starting setup..."
    check_python_version
    check_system_deps
    create_venv
    activate_venv
    setup_pip
    install_dependencies
    install_ipal_modules

    echo
    echo "✅ Setup complete!"
    echo "To activate environment, run:"
    echo "  source $VENV_PATH/bin/activate"
}

main "$@"