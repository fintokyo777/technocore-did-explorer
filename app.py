"""Hugging Face Spaces entry point.

Hugging Face Spaces sets the PORT (and sometimes HOST) environment variables and
expects `app.py` to define an ASGI/WSGI `app`. We reuse the same read-only Flask
app from the package -- no secrets, no writes, no signing.

Run locally the same way for testing:
    pip install -r requirements.txt
    python app.py
"""

import os

from technocore_did_explorer import web

app = web.app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8723))
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=False)
