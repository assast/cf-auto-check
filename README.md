# CF Auto Check (Python Version)

Cloudflare IP/Domain latency and speed testing service, rewritten in Python with [CloudflareSpeedTest (CFST)](https://github.com/XIU2/CloudflareSpeedTest) integration.

## Features

- **CFST Integration**: Uses CloudflareSpeedTest binary for accurate latency and speed testing.
- **Auto Download**: Automatically downloads the correct CFST binary for your platform.
- **Multi-Port Support**: Groups IPs by port and tests each group separately.
- **Check Interval**: Configurable interval for periodic IP checks.
- **Auto Update**: Updates remarks in the API with format: `IP Region|Latency|SpeedMB/S`.
- **Fallback Testing**: Falls back to manual ping testing if CFST fails.

## Prerequisites

- Python 3.9+
- `ping` command (for fallback testing)
- Internet access (for CFST auto-download)

## Installation

1.  Clone the repository.
2.  Create and activate a virtual environment:
    ```bash
    python -m venv venv
    
    # macOS/Linux
    source venv/bin/activate
    
    # Windows
    .\venv\Scripts\activate
    ```
3.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

Copy `.env.example` to `.env` and configure your settings:

```ini
# API Configuration
API_URL=https://your-worker.pages.dev
API_KEY=your-api-key-here

# API Client Configuration
API_MAX_RETRIES=3
API_RETRY_DELAY=2000
API_USE_SESSION_TOKEN=true  # Use session token for API authentication

# Test Configuration
CHECK_INTERVAL=3600         # Seconds between check cycles
CONCURRENT_TESTS=5          # Number of parallel CFST tests
TIMEOUT=5000                # Latency timeout (ms)
TEST_URL=https://www.cloudflare.com/cdn-cgi/trace

# Test Mode: cfip, proxyip, outbound, all
TEST_MODE=cfip

# Enable/Disable Features
ENABLE_LATENCY_TEST=true
ENABLE_SPEED_TEST=true
ENABLE_AUTO_UPDATE=true

# Speed Test Configuration
SPEED_TEST_SIZE=1048576     # 1MB
SPEED_TEST_DURATION=10000   # 10s limit

# Telegram Notification (optional)
TG_ENABLED=false            # Set to true to enable
TG_BOT_TOKEN=your-bot-token
TG_CHAT_ID=your-chat-id
TG_PROXY=                   # Proxy for TG only (doesn't affect speed test)
```

## Usage

### Run Locally

```bash
python -m src.main
```

### Run with Docker

#### Using Pre-built Image (Recommended)

```bash
docker run -d \
  --name cf-auto-check \
  --restart unless-stopped \
  --env-file .env \
  -v ./cfst_data:/app/cfst_data \
  ghcr.io/assast/cf-auto-check:latest
```

#### Build Locally

1.  Build the image:
    ```bash
    docker build -t cf-auto-check .
    ```

2.  Run the container:
    ```bash
    docker run -d \
      --name cf-auto-check \
      --restart unless-stopped \
      --env-file .env \
      cf-auto-check
    ```

Or use Docker Compose:

```bash
docker-compose up -d
```

## Project Structure

```
cf-auto-check/
├── src/
│   ├── main.py        # Main entry point, CFST integration, and scheduler
│   ├── tester.py      # Fallback latency (ping), speed, and geo tests
│   ├── api_client.py  # API interaction logic
│   ├── config.py      # Configuration loader
│   └── logger.py      # Logging setup
├── cfst_data/         # CFST binary and result files (auto-created)
├── .env.example       # Example configuration file
├── docker-compose.yml # Docker Compose configuration
├── Dockerfile         # Docker build configuration
└── requirements.txt   # Python dependencies
```
