# CF Auto Check (Python Version)

Cloudflare IP/Domain latency and speed testing service, rewritten in Python with [CloudflareSpeedTest (CFST)](https://github.com/XIU2/CloudflareSpeedTest) integration.

## Features

- **CFST Integration**: Uses CloudflareSpeedTest binary for accurate latency and speed testing.
- **Smart Testing**: CFST tests latency for all IPs, then tests speed for: top N(443) by latency and top N(non-443 shared) by latency (configurable via SPEED_TEST_COUNT_443 and SPEED_TEST_COUNT).
- **Auto Download**: Automatically downloads the correct CFST binary for your platform.
- **Multi-Port Support**: Groups IPs by port and tests each group separately.
- **Check Interval**: Configurable interval for periodic IP checks.
- **Auto Update**: Updates remarks in the API with format: `IP Region|Latency|SpeedMB/S`.
- **Telegram Bot Commands**: Built-in Telegram bot long polling with `/cfst`, `/cfst_status`, `/cfst_health`, and manual `/cf_sync <IP>`.
- **Telegram Proxy Support**: Supports per-Telegram proxy via `TG_PROXY`.
- **Manual Cloudflare Sync**: Automatic CF DNS sync is disabled in command mode; sync target IP manually with bot command.
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

# Download speed test configuration
SPEED_TEST_COUNT=20       # Number of non-443 IP:port to speed test (shared across non-443 ports)
SPEED_TEST_COUNT_443=20   # Number of 443 IP:port to speed test
SPEED_ENABLE_COUNT=50     # Enable top N non-443 IP:port (shared across non-443 ports)
SPEED_ENABLE_COUNT_443=50 # Enable top N 443 IP:port

# Test Mode: cfip, proxyip, outbound, all
TEST_MODE=cfip

# Enable/Disable Auto Update
ENABLE_AUTO_UPDATE=true

# Telegram Notification (optional)
TG_ENABLED=true
TG_BOT_TOKEN=your-bot-token
TG_CHAT_ID=your-chat-id
TG_PROXY=                     # Proxy for TG only
TG_BOT_COMMANDS_ENABLED=true  # Enable built-in bot commands
```

## Usage

### Run Locally

```bash
python -m src.main
```

### Run with Docker

After configuring `.env`, the built-in Telegram bot will start automatically when `TG_ENABLED=true` and `TG_BOT_COMMANDS_ENABLED=true`.

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


https://github.com/XIU2/CloudflareSpeedTest