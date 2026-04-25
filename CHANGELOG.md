# Changelog

All notable changes to this project will be documented in this file.

## Unreleased - 2026-04-25

### Added
- Added enabled-CFIP maintenance scheduling via `SYNC_TO_CF_CRON` to re-test enabled records for latency and speed.
- Added Telegram command `/cfst_maint` to trigger enabled-CFIP maintenance manually.
- Added Telegram maintenance result notifications with sync summary, tested count, update count, and best sync candidate details.

### Changed
- Changed maintenance sync selection to honor `SYNC_TO_CF_FILTER_PORT`; keep `443` to preserve the previous behavior, or set `0` to allow all ports.
- Changed maintenance updates to preserve `DOMAIN-KEEP` semantics for domain-based records when resolution or testing fails.
- Changed service startup behavior so the process stays alive when only the enabled maintenance scheduler is configured.
- Updated configuration examples and README to describe the maintenance workflow and Telegram trigger.
