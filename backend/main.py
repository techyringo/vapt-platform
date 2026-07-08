"""VAPT Multi-Agent System — Main Entry Point"""

import sys
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent))

if __name__ == "__main__":
    import typer
    from cli.main import app
    app()