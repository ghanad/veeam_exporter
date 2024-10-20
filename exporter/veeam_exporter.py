import time
from abc import ABC, abstractmethod
from prometheus_client import start_http_server, Gauge
from typing import List
import requests
import urllib3
from typing import List, Dict, Any
from dateutil import parser
import pytz


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VeeamAuth:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = 0

    def get_token(self) -> str:
        if self.access_token and time.time() < self.token_expiry:
            return self.access_token
        elif self.refresh_token:
            return self.refresh_access_token()
        else:
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
        response = requests.post(url, data=payload, headers=headers, verify=False)
        if response.status_code == 200:
            data = response.json()
            self.access_token = data['access_token']
            self.refresh_token = data['refresh_token']
            self.token_expiry = time.time() + data['expires_in']
            return self.access_token
        else:
            raise Exception(f"Failed to get token: {response.status_code} - {response.text}")

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
        response = requests.post(url, data=payload, headers=headers, verify=False)
        if response.status_code == 200:
            data = response.json()
            self.access_token = data['access_token']
            self.refresh_token = data['refresh_token']
            self.token_expiry = time.time() + data['expires_in']
            return self.access_token
        else:
            # If refresh fails, try to get a new token
            return self.get_new_token()

    def make_authenticated_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f"Bearer {self.get_token()}"
        headers['x-api-version'] = "1.1-rev2"
        kwargs['headers'] = headers
        response = requests.request(method, url, **kwargs, verify=False)
        return response

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

    def display_job_states(self, **filters):
        job_states = self.get_all_job_states(**filters)
        print(f"{'id':<40} {'Name':<30} {'Type':<20} {'Status':<15} {'Last Result':<15} {'Last Run':<25}")
        print("-" * 170)
        for state in job_states:
            id = state.get('id', 'N/A')
            name = state.get('name', 'N/A')
            job_type = state.get('type', 'N/A')
            status = state.get('status', 'N/A')
            last_result = state.get('lastResult', 'N/A')
            last_run = state.get('lastRun', 'N/A')
            next_run = state.get('nextRun', 'N/A')
            print(f"{id:<40} {name:<30} {job_type:<20} {status:<15} {last_result:<15} {last_run:<25}")

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

    def display_repository_states(self, **filters):
        repository_states = self.get_all_repository_states(**filters)
        print(f"{'Name':<30} {'Type':<20} {'Capacity (GB)':<15} {'Free (GB)':<15} {'Used (GB)':<15}")
        print("-" * 95)
        for state in repository_states:
            name = state.get('name', 'N/A')
            repo_type = state.get('type', 'N/A')
            capacity = state.get('capacityGB', 'N/A')
            free = state.get('freeGB', 'N/A')
            used = state.get('usedSpaceGB', 'N/A')
            print(f"{name:<30} {repo_type:<20} {capacity:<15} {free:<15} {used:<15}")

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

class JobMetricsCollector(MetricsCollector):
    def __init__(self, auth: VeeamAuth):
        self.job_states_manager = VeeamJobStatesManager(auth)
        self.job_last_result = Gauge('veeam_job_last_result', 'Last result of the job (0: None, 1: Success, 2: Warning, 3: Failed)', ['name', 'type'])
        self.job_last_run = Gauge('veeam_job_last_run', 'Timestamp of the last job run', ['name', 'type'])
        self.job_status = Gauge('veeam_job_status', 'Current status of the job (1: Running, 2: Inactive, 3: Disabled)', ['name', 'type'])

    def collect_metrics(self):
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
                    print(f"Failed to parse lastRun timestamp for job {name}: {last_run}")

            status_map = {'Running': 1, 'Inactive': 2, 'Disabled': 3}
            status = status_map.get(state.get('status', 'Inactive'), 2)
            self.job_status.labels(name=name, type=job_type).set(status)

class VeeamPrometheusExporter:
    def __init__(self, auth: VeeamAuth, port: int = 8000, polling_interval_seconds: int = 60):
        self.port = port
        self.polling_interval_seconds = polling_interval_seconds
        self.collectors: List[MetricsCollector] = [
            RepositoryMetricsCollector(auth),
            JobMetricsCollector(auth)
        ]

    def run_metrics_loop(self):
        while True:
            self.fetch()
            time.sleep(self.polling_interval_seconds)

    def fetch(self):
        for collector in self.collectors:
            collector.collect_metrics()

    def run(self):
        start_http_server(self.port)
        self.run_metrics_loop()

if __name__ == '__main__':
    base_url = "https://veeam-api.com"
    username = "username"
    password = "password"

    auth = VeeamAuth(base_url, username, password)
    exporter = VeeamPrometheusExporter(auth)
    exporter.run()
