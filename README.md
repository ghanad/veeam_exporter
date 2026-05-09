# Veeam Prometheus Exporter

A Prometheus exporter for Veeam Backup & Replication that collects metrics about backup jobs, repositories, and server availability status.

## Features

- Monitors Veeam server and API availability
- Collects backup job metrics (status, last result, timing)
- Tracks repository usage and capacity
- Gracefully handles API downtime
- Provides detailed logging

## Metrics

### Server Status Metrics
- `veeam_server_up`: Indicates if the Veeam server is operational (1: up, 0: down)
- `veeam_api_up`: Shows if the Veeam API is accessible (1: up, 0: down)

### Job Metrics
- `veeam_job_last_result`: Last result of the job (0: None, 1: Success, 2: Warning, 3: Failed)
- `veeam_job_last_run`: Timestamp of the last job run
- `veeam_job_next_run`: Timestamp of the next scheduled job run
- `veeam_job_status`: Current status of the job (1: Running, 2: Inactive, 3: Disabled)

### Repository Metrics
- `veeam_repository_capacity_gb`: Total capacity of the repository in GB
- `veeam_repository_free_gb`: Free space in the repository in GB
- `veeam_repository_used_gb`: Used space in the repository in GB

## Prerequisites

- Python 3.6 or higher, or Docker
- Veeam Backup & Replication server with API access
- Access to Veeam server (credentials with appropriate permissions)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/veeam-exporter.git
cd veeam-exporter
```

2. Install required packages:
```bash
pip install -r exporter/requirements.txt
```

## Configuration

Configure the Veeam server connection with environment variables:

```bash
export VEEAM_BASE_URL="https://your-veeam-server:9419"
export VEEAM_USERNAME="your-username"
export VEEAM_PASSWORD="your-password"
export EXPORTER_PORT=8001
```

## Usage

1. Start the exporter:
```bash
python exporter/veeam_exporter.py
```

2. The exporter will start on port 8001 by default. Metrics are available at:
```
http://localhost:8001/metrics
```

3. Add the target to your Prometheus configuration:
```yaml
scrape_configs:
  - job_name: 'veeam'
    static_configs:
      - targets: ['localhost:8001']
```

## Docker

1. Create a local environment file:
```bash
cp .env.example .env
```

2. Edit `.env` and set the Veeam connection details:
```bash
VEEAM_BASE_URL=https://your-veeam-server:9419
VEEAM_USERNAME=your-username
VEEAM_PASSWORD=your-password
EXPORTER_PORT=8001
```

3. Build and start the container:
```bash
docker compose up -d --build
```

Metrics will be available at:
```
http://localhost:8001/metrics
```

Health check:
```
http://localhost:8001/health
```

## Health Check

The exporter provides a health check endpoint at:
```
http://localhost:8001/health
```

## Logging

Logs are written to `logs/veeam_exporter.log` with rotation enabled:
- Maximum file size: 10MB
- Keeps last 5 log files
- Logs both to file and console

## Error Handling

The exporter handles various error conditions:
- API unavailability: Sets metrics to 0 and continues running
- Authentication failures: Implements retry mechanism with exponential backoff
- Token expiration: Automatically refreshes authentication tokens
- Parse errors: Logs errors and continues with default values

## Development

To contribute:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues and feature requests, please create an issue on GitHub.
