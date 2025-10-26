"""VulnSherif application entry point."""

from __future__ import annotations

import os
import sys

from vulnsherif.api_keys import ensure_api_key_interactive
from vulnsherif.app import create_app, logger

app = create_app()


def main() -> None:
    if not os.getenv("WERKZEUG_RUN_MAIN"):
        try:
            ensure_api_key_interactive(app, logger)
        except Exception as exc:  # pragma: no cover - startup failure path
            print(f"Failed to initialize API key: {exc}")
            sys.exit(1)
    port = int(os.getenv("PORT", "5000"))
    debug_flag = bool(os.getenv("FLASK_DEBUG")) or bool(os.getenv("VULNSHERIF_DEBUG"))
    app.run(host="127.0.0.1", port=port, debug=debug_flag)


if __name__ == "__main__":
    main()
