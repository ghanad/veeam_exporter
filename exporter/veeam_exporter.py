import os
import time
import logging
from abc import ABC, abstractmethod
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from prometheus_client.core import REGISTRY
from prometheus_client import Gauge
import requests
import urllib3
from typing import List, Dict, Any
from dateutil import parser
import pytz
from flask import Flask, Response
from logging.handlers import RotatingFileHandler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logger = logging.getLogger('veeam_exporter')
logger.setLevel(logging.INFO)

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Create file handler
file_handler = RotatingFileHandler(
    'logs/veeam_exporter.log',
    maxBytes=10485760,  # 10MB
    backupCount=5
)
file_handler.setLevel(logging.INFO)

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

class VeeamAuth:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = 0
        logger.info("VeeamAuth initialized for URL: %s", base_url)

    def get_token(self) -> str:
        if self.access_token and time.time() < self.token_expiry:
            return self.access_token
        elif self.refresh_token:
            logger.info("Refreshing access token")
            return self.refresh_access_token()
        else:
            logger.info("Getting new token")
            return self.get_new_token()

    def get_new_token(self) -> str:
        url = f"{self.base_url}/api/oauth2/token"
        payload = {
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
            "use_short_term_refresh": "false"
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "x-api-version": "1.1-rev2"
        }
        try:
            response = requests.post(url, data=payload, headers=headers, verify=False)
            response.raise_for_status()
            data = response.json()
            self.access_token = data['access_token']
            self.refresh_token = data['refresh_token']
            self.token_expiry = time.time() + data['expires_in']
            logger.info("Successfully obtained new token")
            return self.access_token
        except Exception as e:
            logger.error("Failed to get token: %s", str(e))
            raise

    def refresh_access_token(self) -> str:
        url = f"{self.base_url}/api/oauth2/token"
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "x-api-version": "1.1-rev2"
        }
        try:
            response = requests.post(url, data=payload, headers=headers, verify=False)
            response.raise_for_status()
            data = response.json()
            self.access_token = data['access_token']
            self.refresh_token = data['refresh_token']
            self.token_expiry = time.time() + data['expires_in']
            logger.info("Successfully refreshed token")
            return self.access_token
        except Exception as e:
            logger.warning("Failed to refresh token: %s. Trying to get new token.", str(e))
            return self.get_new_token()

    def make_authenticated_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f"Bearer {self.get_token()}"
        headers['x-api-version'] = "1.1-rev2"
        kwargs['headers'] = headers
        try:
            response = requests.request(method, url, **kwargs, verify=False)
            response.raise_for_status()
            return response
        except Exception as e:
            logger.error("Request failed for endpoint %s: %s", endpoint, str(e))
            raise

class VeeamJobStatesManager:
    def __init__(self, auth: VeeamAuth):
        self.auth = auth

    def get_all_job_states(self, limit: int = 100, **filters) -> List[Dict[str, Any]]:
        endpoint = "/api/v1/jobs/states"
        params = {
            "skip": "0",
            "limit": str(limit),
            "orderColumn": "Name",
            "orderAsc": "true",
            **filters
        }
        response = self.auth.make_authenticated_request("GET", endpoint, params=params)
        if response.status_code == 200:
            return response.json().get('data', [])
        else:
            raise Exception(f"Failed to get job states: {response.status_code} - {response.text}")

class VeeamRepositoryStatesManager:
    def __init__(self, auth: VeeamAuth):
        self.auth = auth

    def get_all_repository_states(self, limit: int = 100, **filters) -> List[Dict[str, Any]]:
        endpoint = "/api/v1/backupInfrastructure/repositories/states"
        params = {
            "skip": "0",
            "limit": str(limit),
            "orderColumn": "Name",
            "orderAsc": "true",
            **filters
        }
        response = self.auth.make_authenticated_request("GET", endpoint, params=params)
        if response.status_code == 200:
            return response.json().get('data', [])
        else:
            raise Exception(f"Failed to get repository states: {response.status_code} - {response.text}")

class MetricsCollector(ABC):
    @abstractmethod
    def collect_metrics(self):
        pass

class RepositoryMetricsCollector(MetricsCollector):
    def __init__(self, auth: VeeamAuth):
        self.repository_states_manager = VeeamRepositoryStatesManager(auth)
        self.capacity_gb = Gauge('veeam_repository_capacity_gb', 'Capacity of the repository in GB', ['name', 'type'])
        self.free_gb = Gauge('veeam_repository_free_gb', 'Free space in the repository in GB', ['name', 'type'])
        self.used_gb = Gauge('veeam_repository_used_gb', 'Used space in the repository in GB', ['name', 'type'])

    def collect_metrics(self):
        try:
            repository_states = self.repository_states_manager.get_all_repository_states()
            for state in repository_states:
                name = state.get('name', 'N/A')
                repo_type = state.get('type', 'N/A')
                capacity = state.get('capacityGB', 0)
                free = state.get('freeGB', 0)
                used = state.get('usedSpaceGB', 0)

                self.capacity_gb.labels(name=name, type=repo_type).set(capacity)
                self.free_gb.labels(name=name, type=repo_type).set(free)
                self.used_gb.labels(name=name, type=repo_type).set(used)
            logger.info("Repository metrics collected successfully")
        except Exception as e:
            logger.error("Error collecting repository metrics: %s", str(e))
            raise

class JobMetricsCollector(MetricsCollector):
    def __init__(self, auth: VeeamAuth):
        self.job_states_manager = VeeamJobStatesManager(auth)
        self.job_last_result = Gauge('veeam_job_last_result', 'Last result of the job (0: None, 1: Success, 2: Warning, 3: Failed)', ['name', 'type'])
        self.job_last_run = Gauge('veeam_job_last_run', 'Timestamp of the last job run', ['name', 'type'])
        self.job_next_run = Gauge('veeam_job_next_run', 'Timestamp of the next scheduled job run', ['name', 'type'])
        self.job_status = Gauge('veeam_job_status', 'Current status of the job (1: Running, 2: Inactive, 3: Disabled)', ['name', 'type'])

    def collect_metrics(self):
        try:
            job_states = self.job_states_manager.get_all_job_states()
            for state in job_states:
                name = state.get('name', 'N/A')
                job_type = state.get('type', 'N/A')
                
                last_result_map = {'None': 0, 'Success': 1, 'Warning': 2, 'Failed': 3}
                last_result = last_result_map.get(state.get('lastResult', 'None'), 0)
                self.job_last_result.labels(name=name, type=job_type).set(last_result)

                last_run = state.get('lastRun', '')
                if last_run:
                    try:
                        parsed_time = parser.parse(last_run)
                        last_run_timestamp = parsed_time.astimezone(pytz.UTC).timestamp()
                        self.job_last_run.labels(name=name, type=job_type).set(last_run_timestamp)
                    except ValueError:
                        logger.error("Failed to parse lastRun timestamp for job %s: %s", name, last_run)

                # Add processing for nextRun
                next_run = state.get('nextRun', '')
                logger.info(f'[next run start ++] {state}')
                if next_run:
                    try:
                        parsed_time = parser.parse(next_run)
                        logger.info(f'[next_run] state: {state} - next run {parsed_time}')
                        next_run_timestamp = parsed_time.astimezone(pytz.UTC).timestamp()
                        self.job_next_run.labels(name=name, type=job_type).set(next_run_timestamp)
                    except ValueError:
                        logger.error("Failed to parse nextRun timestamp for job %s: %s", name, next_run)
                else:
                    # If nextRun is null, we set it to 0 to indicate no scheduled run
                    self.job_next_run.labels(name=name, type=job_type).set(0)

                status_map = {'Running': 1, 'Inactive': 2, 'Disabled': 3}
                status = status_map.get(state.get('status', 'Inactive'), 2)
                self.job_status.labels(name=name, type=job_type).set(status)
            logger.info("Job metrics collected successfully")
        except Exception as e:
            logger.error("Error collecting job metrics: %s", str(e))
            raise


class VeeamMetricsCollector:
    def __init__(self, auth: VeeamAuth):
        self.collectors = [
            RepositoryMetricsCollector(auth),
            JobMetricsCollector(auth)
        ]
        logger.info("VeeamMetricsCollector initialized with %d collectors", len(self.collectors))

    def collect_metrics(self):
        logger.info("Starting metrics collection")
        try:
            for collector in self.collectors:
                collector.collect_metrics()
            logger.info("Metrics collection completed successfully")
        except Exception as e:
            logger.error("Error collecting metrics: %s", str(e))
            raise

# Create Flask application
app = Flask(__name__)

# Initialize Veeam auth and metrics collector
base_url = "https://vbkmgmt.sfz.tsetmc.com:9419"
username = "prometheus"
password = "P@ssw0rd"

auth = VeeamAuth(base_url, username, password)
metrics_collector = VeeamMetricsCollector(auth)

@app.route('/metrics')
def metrics():
    try:
        metrics_collector.collect_metrics()
        return Response(generate_latest(REGISTRY), mimetype=CONTENT_TYPE_LATEST)
    except Exception as e:
        logger.error("Error generating metrics: %s", str(e))
        return Response(f"Error generating metrics: {str(e)}", status=500)

@app.route('/health')
def health():
    return Response('healthy', mimetype='text/plain')

# WSGI entry point
application = app

if __name__ == '__main__':
    # For development only
    app.run(host='0.0.0.0', port=8000)
