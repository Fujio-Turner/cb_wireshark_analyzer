FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# tshark reads the pcap. dumpcap setuid is not required for offline files.
RUN apt-get update \
    && echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get install -y --no-install-recommends tshark ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analyze_capture.py config.json pyproject.toml ./
COPY tests ./tests
COPY images ./images
COPY web ./web

ENTRYPOINT ["python3", "analyze_capture.py"]
