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
from typing import Tuple

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
    def __init__(self, base_url: str, username: str, password: str, max_retries: int = 3):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = 0
        self.max_retries = max_retries
        self.token_refresh_buffer = 300  # 5 minutes buffer before expiry
        logger.info("VeeamAuth initialized for URL: %s", base_url)

    def get_token(self) -> str:
        current_time = time.time()
        
        if self.access_token and current_time < (self.token_expiry - self.token_refresh_buffer):
            return self.access_token
        elif self.refresh_token:
            try:
                return self.refresh_access_token()
            except Exception as e:
                logger.warning("Failed to refresh token: %s. Getting new token.", str(e))
                return self.get_new_token_with_retry()
        else:
            return self.get_new_token_with_retry()

    def get_new_token_with_retry(self) -> str:
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                self._reset_tokens()  # Reset tokens before trying to get new ones
                return self._get_new_token()
            except Exception as e:
                last_exception = e
                wait_time = (attempt + 1) * 2  # Exponential backoff
                logger.warning(
                    "Attempt %d/%d to get new token failed: %s. Waiting %d seconds...",
                    attempt + 1, self.max_retries, str(e), wait_time
                )
                time.sleep(wait_time)
        
        logger.error("Failed to get new token after %d attempts", self.max_retries)
        raise last_exception

    def _reset_tokens(self):
        """Reset both access and refresh tokens"""
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = 0

    def _get_new_token(self) -> str:
        """Internal method to get new token"""
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
        except requests.exceptions.RequestException as e:
            logger.error("Failed to get new token: %s", str(e))
            raise

    def refresh_access_token(self) -> str:
        """Refresh the access token using the refresh token"""
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
        except requests.exceptions.RequestException as e:
            logger.warning("Failed to refresh token: %s. Will try to get new token.", str(e))
            return self.get_new_token_with_retry()

    def make_authenticated_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                url = f"{self.base_url}{endpoint}"
                headers = kwargs.get('headers', {})
                headers['Authorization'] = f"Bearer {self.get_token()}"
                headers['x-api-version'] = "1.1-rev2"
                kwargs['headers'] = headers
                
                response = requests.request(method, url, **kwargs, verify=False)
                
                if response.status_code == 401:
                    logger.warning("Received 401 error, clearing tokens and retrying...")
                    self._reset_tokens()
                    continue
                
                response.raise_for_status()
                return response
                
            except requests.exceptions.RequestException as e:
                last_exception = e
                wait_time = (attempt + 1) * 2
                logger.warning(
                    "Attempt %d/%d failed for endpoint %s: %s. Waiting %d seconds...",
                    attempt + 1, self.max_retries, endpoint, str(e), wait_time
                )
                time.sleep(wait_time)
        
        logger.error("Failed request after %d attempts", self.max_retries)
        raise last_exception

class VeeamAvailabilityManager:
    def __init__(self, auth: VeeamAuth):
        self.auth = auth
        self.veeam_up = Gauge('veeam_server_up', 'Indicates if Veeam server is up and accessible (1: up, 0: down)')
        self.api_up = Gauge('veeam_api_up', 'Indicates if Veeam API is up and accessible (1: up, 0: down)')
        self._last_api_state = False
        
    def check_port(self, host: str, port: int, timeout: int = 5) -> bool:
        """Check if a port is open"""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.error(f"Error checking port {port}: {str(e)}")
            return False
            
    def check_availability(self) -> Tuple[bool, bool]:
        """
        Check both Veeam server and API availability
        Returns: (server_up, api_up)
        """
        try:
            # First check if API port is open
            api_host = self.auth.base_url.split('://')[1].split(':')[0]
            api_up = self.check_port(api_host, 9419)
            
            # If API port is up, try to get a token to verify Veeam server is working
            if api_up:
                try:
                    self.auth.get_token()
                    server_up = True
                except Exception as e:
                    logger.error(f"Failed to get token: {str(e)}")
                    server_up = False
            else:
                server_up = False
                
            self._last_api_state = api_up
            return server_up, api_up
            
        except Exception as e:
            logger.error(f"Error checking Veeam availability: {str(e)}")
            self._last_api_state = False
            return False, False
            
    def collect_metrics(self):
        """Update the availability metrics"""
        server_up, api_up = self.check_availability()
        self.veeam_up.set(1 if server_up else 0)
        self.api_up.set(1 if api_up else 0)
        logger.info(f"Veeam availability - Server: {'up' if server_up else 'down'}, API: {'up' if api_up else 'down'}")

    def is_api_available(self) -> bool:
        """Return the current API availability state"""
        return self._last_api_state

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
    
    def safe_collect(self):
        """Template method for safe metric collection"""
        try:
            self.collect_metrics()
            return True
        except Exception as e:
            logger.error(f"Error collecting metrics in {self.__class__.__name__}: {str(e)}")
            self.reset_metrics()
            return False
            
    @abstractmethod
    def reset_metrics(self):
        """Reset metrics to default values when collection fails"""
        pass

class RepositoryMetricsCollector(MetricsCollector):
    def __init__(self, auth: VeeamAuth):
        self.repository_states_manager = VeeamRepositoryStatesManager(auth)
        self.capacity_gb = Gauge('veeam_repository_capacity_gb', 'Capacity of the repository in GB', ['name', 'type'])
        self.free_gb = Gauge('veeam_repository_free_gb', 'Free space in the repository in GB', ['name', 'type'])
        self.used_gb = Gauge('veeam_repository_used_gb', 'Used space in the repository in GB', ['name', 'type'])
        self._metric_labels = set()  # Track active metric labels

    def reset_metrics(self):
        """Reset all repository metrics to 0"""
        for labels in self._metric_labels:
            self.capacity_gb.labels(**labels).set(0)
            self.free_gb.labels(**labels).set(0)
            self.used_gb.labels(**labels).set(0)

    def collect_metrics(self):
        try:
            repository_states = self.repository_states_manager.get_all_repository_states()
            new_labels = set()
            
            for state in repository_states:
                labels = {
                    'name': state.get('name', 'N/A'),
                    'type': state.get('type', 'N/A')
                }
                new_labels.add(frozenset(labels.items()))
                
                self.capacity_gb.labels(**labels).set(state.get('capacityGB', 0))
                self.free_gb.labels(**labels).set(state.get('freeGB', 0))
                self.used_gb.labels(**labels).set(state.get('usedSpaceGB', 0))
            
            self._metric_labels = new_labels
            logger.info("Repository metrics collected successfully")
        except Exception as e:
            logger.error(f"Error collecting repository metrics: {str(e)}")
            self.reset_metrics()
            raise

class JobMetricsCollector(MetricsCollector):
    def __init__(self, auth: VeeamAuth):
        self.job_states_manager = VeeamJobStatesManager(auth)
        self.job_last_result = Gauge('veeam_job_last_result', 'Last result of the job (0: None, 1: Success, 2: Warning, 3: Failed)', ['name', 'type'])
        self.job_last_run = Gauge('veeam_job_last_run', 'Timestamp of the last job run', ['name', 'type'])
        self.job_next_run = Gauge('veeam_job_next_run', 'Timestamp of the next scheduled job run', ['name', 'type'])
        self.job_status = Gauge('veeam_job_status', 'Current status of the job (1: Running, 2: Inactive, 3: Disabled)', ['name', 'type'])
        self._metric_labels = set()  # Track active metric labels

    def reset_metrics(self):
        """Reset all job metrics to 0"""
        for labels in self._metric_labels:
            labels_dict = dict(labels)
            self.job_last_result.labels(**labels_dict).set(0)
            self.job_last_run.labels(**labels_dict).set(0)
            self.job_next_run.labels(**labels_dict).set(0)
            self.job_status.labels(**labels_dict).set(0)

    def clear_old_metrics(self, current_jobs: set):
        """Clear metrics for jobs that no longer exist"""
        jobs_to_remove = self._metric_labels - current_jobs
        for labels in jobs_to_remove:
            labels_dict = dict(labels)
            self.job_last_result.remove(*labels_dict.values())
            self.job_last_run.remove(*labels_dict.values())
            self.job_next_run.remove(*labels_dict.values())
            self.job_status.remove(*labels_dict.values())
        self._metric_labels = current_jobs

    def collect_metrics(self):
        try:
            job_states = self.job_states_manager.get_all_job_states()
            new_labels = set()
            
            for state in job_states:
                name = state.get('name', 'N/A')
                job_type = state.get('type', 'N/A')
                labels = frozenset({
                    'name': name,
                    'type': job_type
                }.items())
                new_labels.add(labels)
                labels_dict = dict(labels)
                
                # Set last result
                last_result_map = {'None': 0, 'Success': 1, 'Warning': 2, 'Failed': 3}
                last_result = last_result_map.get(state.get('lastResult', 'None'), 0)
                self.job_last_result.labels(**labels_dict).set(last_result)

                # Set last run time
                last_run = state.get('lastRun', '')
                if last_run:
                    try:
                        parsed_time = parser.parse(last_run)
                        last_run_timestamp = parsed_time.astimezone(pytz.UTC).timestamp()
                        self.job_last_run.labels(**labels_dict).set(last_run_timestamp)
                    except ValueError as e:
                        logger.error("Failed to parse lastRun timestamp for job %s: %s - %s", name, last_run, str(e))
                        self.job_last_run.labels(**labels_dict).set(0)
                else:
                    self.job_last_run.labels(**labels_dict).set(0)

                # Set next run time
                next_run = state.get('nextRun', '')
                if next_run:
                    try:
                        parsed_time = parser.parse(next_run)
                        next_run_timestamp = parsed_time.astimezone(pytz.UTC).timestamp()
                        self.job_next_run.labels(**labels_dict).set(next_run_timestamp)
                    except ValueError as e:
                        logger.error("Failed to parse nextRun timestamp for job %s: %s - %s", name, next_run, str(e))
                        self.job_next_run.labels(**labels_dict).set(0)
                else:
                    self.job_next_run.labels(**labels_dict).set(0)

                # Set job status
                status_map = {'Running': 1, 'Inactive': 2, 'Disabled': 3}
                status = status_map.get(state.get('status', 'Inactive'), 2)
                self.job_status.labels(**labels_dict).set(status)
            
            # Clear metrics for jobs that no longer exist
            self.clear_old_metrics(new_labels)
            logger.info("Job metrics collected successfully for %d jobs", len(job_states))
            
        except Exception as e:
            logger.error("Error collecting job metrics: %s", str(e))
            self.reset_metrics()
            raise

class VeeamMetricsCollector:
    def __init__(self, auth: VeeamAuth):
        self.availability_manager = VeeamAvailabilityManager(auth)
        self.collectors = [
            RepositoryMetricsCollector(auth),
            JobMetricsCollector(auth)
        ]
        logger.info("VeeamMetricsCollector initialized with %d collectors", len(self.collectors))

    def collect_metrics(self):
        logger.info("Starting metrics collection")
        
        # First check availability
        self.availability_manager.collect_metrics()
        
        # Collect other metrics only if API is available
        if self.availability_manager.is_api_available():
            for collector in self.collectors:
                collector.safe_collect()
        else:
            logger.warning("Skipping metric collection as API is down")
            # Reset all metrics when API is down
            for collector in self.collectors:
                collector.reset_metrics()

# Create Flask application
app = Flask(__name__)

# Initialize Veeam auth and metrics collector
base_url = "https://veeam.com:9419"
username = "admin"
password = "password"

auth = VeeamAuth(base_url, username, password)
metrics_collector = VeeamMetricsCollector(auth)

@app.route('/metrics')
def metrics():
    try:
        metrics_collector.collect_metrics()
        return Response(generate_latest(REGISTRY), mimetype=CONTENT_TYPE_LATEST)
    except Exception as e:
        logger.error(f"Error generating metrics: {str(e)}")
        # Even if collection fails, return available metrics
        return Response(generate_latest(REGISTRY), mimetype=CONTENT_TYPE_LATEST)

@app.route('/health')
def health():
    return Response('healthy', mimetype='text/plain')

# WSGI entry point
application = app

if __name__ == '__main__':
    # For development only
    app.run(host='0.0.0.0', port=8000)
