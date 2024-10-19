import requests
import time
from typing import List, Dict, Any
from datetime import datetime

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
        response = requests.post(url, data=payload, headers=headers)
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
        response = requests.post(url, data=payload, headers=headers)
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
        response = requests.request(method, url, **kwargs)
        return response

class VeeamJobManager:
    def __init__(self, auth: VeeamAuth):
        self.auth = auth

    def get_all_jobs(self, limit: int = 100) -> List[Dict[str, Any]]:
        endpoint = "/api/v1/jobs"
        params = {
            "skip": "0",
            "limit": str(limit),
            "orderColumn": "Name",
            "orderAsc": "true"
        }
        response = self.auth.make_authenticated_request("GET", endpoint, params=params)
        if response.status_code == 200:
            return response.json().get('data', [])
        else:
            raise Exception(f"Failed to get jobs: {response.status_code} - {response.text}")

    def display_job_statuses(self):
        jobs = self.get_all_jobs()
        print(f"{'Name':<30} {'Type':<20} {'Status':<15} {'Last Result':<15}")
        print("-" * 80)
        for job in jobs:
            name = job.get('name', 'N/A')
            job_type = job.get('type', 'N/A')
            status = job.get('status', 'N/A')
            last_result = job.get('lastResult', 'N/A')
            print(f"{name:<30} {job_type:<20} {status:<15} {last_result:<15}")

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
        print(f"{'Name':<30} {'Type':<20} {'Status':<15} {'Last Result':<15} {'Last Run':<25} {'Next Run':<25}")
        print("-" * 130)
        for state in job_states:
            name = state.get('name', 'N/A')
            job_type = state.get('type', 'N/A')
            status = state.get('status', 'N/A')
            last_result = state.get('lastResult', 'N/A')
            last_run = state.get('lastRun', 'N/A')
            next_run = state.get('nextRun', 'N/A')
            print(f"{name:<30} {job_type:<20} {status:<15} {last_result:<15} {last_run:<25} {next_run:<25}")


class VeeamTaskManager:
    def __init__(self, auth: VeeamAuth):
        self.auth = auth

    def get_all_tasks(self, limit: int = 100, **filters) -> List[Dict[str, Any]]:
        endpoint = "/api/v1/tasks"
        params = {
            "skip": "0",
            "limit": str(limit),
            "orderColumn": "CreationTime",
            "orderAsc": "false",
            **filters
        }
        response = self.auth.make_authenticated_request("GET", endpoint, params=params)
        if response.status_code == 200:
            return response.json().get('data', [])
        else:
            raise Exception(f"Failed to get tasks: {response.status_code} - {response.text}")

    def display_tasks(self, **filters):
        tasks = self.get_all_tasks(**filters)
        print(f"{'Name':<30} {'Type':<15} {'State':<10} {'Result':<10} {'Creation Time':<25} {'End Time':<25}")
        print("-" * 115)
        for task in tasks:
            name = task.get('name', 'N/A')
            task_type = task.get('type', 'N/A')
            state = task.get('state', 'N/A')
            result = task.get('result', 'N/A')
            creation_time = task.get('creationTime', 'N/A')
            end_time = task.get('endTime', 'N/A')
            print(f"{name:<30} {task_type:<15} {state:<10} {result:<10} {creation_time:<25} {end_time:<25}")

# Usage example:
if __name__ == "__main__":
    auth = VeeamAuth("https://cdn.veeam.com", "your_username", "your_password")
    job_manager = VeeamJobManager(auth)
    job_states_manager = VeeamJobStatesManager(auth)
    task_manager = VeeamTaskManager(auth)

    print("All Jobs:")
    job_manager.display_job_statuses()

    print("\nAll Job States:")
    job_states_manager.display_job_states()

    print("\nAll Tasks:")
    task_manager.display_tasks()

    print("\nFiltered Tasks (only Common tasks in Working state):")
    task_manager.display_tasks(typeFilter="Common", stateFilter="Working")
