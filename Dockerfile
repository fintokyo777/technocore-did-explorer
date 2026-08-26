# Technocore DID Explorer — read-only Flask app
# Builds a small image and serves the app on the port Hugging Face provides.

FROM python:3.11-slim

WORKDIR /app

# cryptography needs a build toolchain on slim images
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

# HF Spaces injects PORT; gunicorn binds 0.0.0.0:$PORT via the CMD below.
EXPOSE 7860

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-7860} --workers 1 --timeout 120 app:app"]
