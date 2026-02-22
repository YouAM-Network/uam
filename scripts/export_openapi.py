"""Export the relay's OpenAPI spec for documentation.

Extracts the OpenAPI JSON schema from the FastAPI ``create_app()`` factory
and writes it to ``docs/relay/openapi.json``.  This file is consumed by the
``mkdocs-render-swagger-plugin`` at docs build time.

Usage::

    python scripts/export_openapi.py
"""

import json
import sys
from pathlib import Path

# Ensure src/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from uam.relay.app import create_app


def main() -> None:
    """Export the OpenAPI JSON spec from the relay FastAPI app."""
    app = create_app()
    spec = app.openapi()

    out_path = Path(__file__).parent.parent / "docs" / "relay" / "openapi.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w") as f:
        json.dump(spec, f, indent=2)

    print(f"Exported OpenAPI spec v{spec.get('openapi', 'unknown')} to {out_path}")


if __name__ == "__main__":
    main()
