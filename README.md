# CF Auto Check (Python Version)

Cloudflare IP/Domain latency and speed testing service, rewritten in Python with [CloudflareSpeedTest (CFST)](https://github.com/XIU2/CloudflareSpeedTest) integration.

## Features

- **CFST Integration**: Uses CloudflareSpeedTest binary for accurate latency and speed testing.
- **Two-Stage Testing**: First tests latency for all IPs, then tests speed for top N by latency.
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
API_USE_SESSION_TOKEN=true

# Schedule Configuration (cron expression)
CHECK_CRON=0 * * * *          # Every hour at minute 0

# CFST Configuration
CONCURRENT_TESTS=5

# Two-stage testing: first test latency for all IPs, then test speed for top N by latency
LATENCY_TEST_COUNT=100    # Test top N IPs by latency for speed testing
SPEED_ENABLE_COUNT=50     # Enable top N IPs by download speed

# Test Mode: cfip, proxyip, outbound, all
TEST_MODE=cfip

# Enable/Disable Auto Update
ENABLE_AUTO_UPDATE=true

# Telegram Notification (optional)
TG_ENABLED=false
TG_BOT_TOKEN=your-bot-token
TG_CHAT_ID=your-chat-id
TG_PROXY=                     # Proxy for TG only
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
│   ├── main.py              # Main entry point, CFST integration, and scheduler
│   ├── api_client.py        # API interaction logic
│   ├── telegram_notifier.py # Telegram notification service
│   ├── config.py            # Configuration loader
│   └── logger.py            # Logging setup
├── cfst_data/               # CFST binary and result files (auto-created)
├── .env.example             # Example configuration file
├── docker-compose.yml       # Docker Compose configuration
├── Dockerfile               # Docker build configuration
└── requirements.txt         # Python dependencies
```
