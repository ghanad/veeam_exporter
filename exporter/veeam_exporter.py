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

def sanitize_label_value(value: str) -> str:
    """
    Clean label values to be prometheus compatible
    """
    if value is None:
        return "none"
    # Replace any non-alphanumeric character with underscore
    cleaned = ''.join(c if c.isalnum() else '_' for c in str(value))
    # Ensure it's not empty
    return cleaned if cleaned else "none"

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
            "x-api-version": "1.2-rev0"
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
            "x-api-version": "1.2-rev0"
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
                headers['x-api-version'] = "1.2-rev0"
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

    def get_last_session_by_job_id(self, job_id: str) -> Dict[str, Any]:
        """
        Get the last session for a specific job
        """
        endpoint = "/api/v1/sessions"
        params = {
            "jobIdFilter": job_id,
            "limit": "1",  # only get the last session
            "orderColumn": "CreationTime",
            "orderAsc": "false"  # descending order to get the most recent first
        }
        try:
            response = self.auth.make_authenticated_request("GET", endpoint, params=params)
            if response.status_code == 200:
                sessions = response.json().get('data', [])
                if sessions:
                    logger.debug(f"Found last session for job {job_id}: {sessions[0]}")
                    return sessions[0]
                logger.debug(f"No sessions found for job {job_id}")
                return {}
            else:
                logger.error(f"Failed to get sessions for job ID {job_id}: {response.status_code} - {response.text}")
                return {}
        except Exception as e:
            logger.error(f"Error getting last session for job {job_id}: {str(e)}")
            return {}

class JobMetricsCollector(MetricsCollector):
    def __init__(self, auth: VeeamAuth):
        self.job_states_manager = VeeamJobStatesManager(auth)
        # Existing metrics
        self.job_last_result = Gauge('veeam_job_last_result', 
                                   'Last result of the job (0: None, 1: Success, 2: Warning, 3: Failed)', 
                                   ['job_name', 'job_type', 'job_id'])
        self.job_last_run = Gauge('veeam_job_last_run', 
                                 'Timestamp of the last job run', 
                                 ['job_name', 'job_type', 'job_id'])
        self.job_next_run = Gauge('veeam_job_next_run', 
                                 'Timestamp of the next scheduled job run', 
                                 ['job_name', 'job_type', 'job_id'])
        self.job_status = Gauge('veeam_job_status', 
                               'Current status of the job (1: Running, 2: Inactive, 3: Disabled)', 
                               ['job_name', 'job_type', 'job_id'])
        
        # New timing metrics
        self.job_start_time = Gauge('veeam_job_start_time',
                                   'Start time of the last job run',
                                   ['job_name', 'job_type', 'job_id'])
        self.job_end_time = Gauge('veeam_job_end_time',
                                 'End time of the last job run',
                                 ['job_name', 'job_type', 'job_id'])
        self.job_duration_seconds = Gauge('veeam_job_duration_seconds',
                                        'Duration of the last job run in seconds',
                                        ['job_name', 'job_type', 'job_id'])
        
        # New data processing metrics
        self.job_processed_data_size = Gauge('veeam_job_processed_data_size',
                                           'Amount of processed data in bytes',
                                           ['job_name', 'job_type', 'job_id'])
        self.job_transferred_data_size = Gauge('veeam_job_transferred_data_size',
                                             'Amount of transferred data in bytes',
                                             ['job_name', 'job_type', 'job_id'])
        self.job_backup_size = Gauge('veeam_job_backup_size',
                                   'Size of the backup in bytes',
                                   ['job_name', 'job_type', 'job_id'])
        self.job_deduplication_ratio = Gauge('veeam_job_deduplication_ratio',
                                           'Deduplication ratio of the backup',
                                           ['job_name', 'job_type', 'job_id'])
        self.job_compression_ratio = Gauge('veeam_job_compression_ratio',
                                         'Compression ratio of the backup',
                                         ['job_name', 'job_type', 'job_id'])
        
        # New object metrics
        self.job_objects_total = Gauge('veeam_job_objects_total',
                                     'Total number of objects in the job',
                                     ['job_name', 'job_type', 'job_id'])
        self.job_objects_processed = Gauge('veeam_job_objects_processed',
                                         'Number of processed objects in the last job run',
                                         ['job_name', 'job_type', 'job_id'])
        self.job_objects_successful = Gauge('veeam_job_objects_successful',
                                          'Number of successfully processed objects',
                                          ['job_name', 'job_type', 'job_id'])
        self.job_objects_failed = Gauge('veeam_job_objects_failed',
                                      'Number of failed objects',
                                      ['job_name', 'job_type', 'job_id'])
        self.job_objects_warning = Gauge('veeam_job_objects_warning',
                                       'Number of objects processed with warning',
                                       ['job_name', 'job_type', 'job_id'])
        
        self._metric_labels = set()

    def reset_metrics(self):
        """Reset all job metrics to 0"""
        try:
            for labels in self._metric_labels:
                labels_dict = dict(labels)
                # Reset existing metrics
                self.job_last_result.labels(**labels_dict).set(0)
                self.job_last_run.labels(**labels_dict).set(0)
                self.job_next_run.labels(**labels_dict).set(0)
                self.job_status.labels(**labels_dict).set(0)
                
                # Reset new timing metrics
                self.job_start_time.labels(**labels_dict).set(0)
                self.job_end_time.labels(**labels_dict).set(0)
                self.job_duration_seconds.labels(**labels_dict).set(0)
                
                # Reset data processing metrics
                self.job_processed_data_size.labels(**labels_dict).set(0)
                self.job_transferred_data_size.labels(**labels_dict).set(0)
                self.job_backup_size.labels(**labels_dict).set(0)
                self.job_deduplication_ratio.labels(**labels_dict).set(0)
                self.job_compression_ratio.labels(**labels_dict).set(0)
                
                # Reset object metrics
                self.job_objects_total.labels(**labels_dict).set(0)
                self.job_objects_processed.labels(**labels_dict).set(0)
                self.job_objects_successful.labels(**labels_dict).set(0)
                self.job_objects_failed.labels(**labels_dict).set(0)
                self.job_objects_warning.labels(**labels_dict).set(0)
        except Exception as e:
            logger.error(f"Error in reset_metrics: {str(e)}")

	def set_basic_job_metrics(self, state: Dict[str, Any], labels_dict: Dict[str, str]):
        """Helper method to set the basic job metrics"""
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
                logger.error("Failed to parse lastRun timestamp for job %s: %s - %s", 
                           labels_dict['job_name'], last_run, str(e))
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
                logger.error("Failed to parse nextRun timestamp for job %s: %s - %s", 
                           labels_dict['job_name'], next_run, str(e))
                self.job_next_run.labels(**labels_dict).set(0)
        else:
            self.job_next_run.labels(**labels_dict).set(0)

        # Set job status
        status_map = {'Running': 1, 'Inactive': 2, 'Disabled': 3}
        status = status_map.get(state.get('status', 'Inactive'), 2)
        self.job_status.labels(**labels_dict).set(status)


    def get_backup_metrics(self, job_id: str) -> Dict[str, float]:
        """Get backup related metrics for a job"""
        try:
            response = self.job_states_manager.auth.make_authenticated_request(
                "GET", 
                "/api/v1/backups",
                params={"jobIdFilter": job_id}
            )
            if response.status_code != 200:
                return {}
            
            backup_data = response.json().get('data', [])
            if not backup_data:
                return {}
                
            backup_id = backup_data[0].get('id')
            if not backup_id:
                return {}
                
            # Get backup files details
            files_response = self.job_states_manager.auth.make_authenticated_request(
                "GET",
                f"/api/v1/backups/{backup_id}/backupFiles"
            )
            if files_response.status_code != 200:
                return {}
                
            files_data = files_response.json().get('data', [])
            if not files_data:
                return {}
                
            # Calculate metrics
            total_backup_size = sum(file.get('backupSize', 0) for file in files_data)
            dedup_ratio = sum(file.get('dedupRatio', 0) for file in files_data) / len(files_data)
            compress_ratio = sum(file.get('compressRatio', 0) for file in files_data) / len(files_data)
            
            return {
                'backup_size': total_backup_size,
                'dedup_ratio': dedup_ratio,
                'compress_ratio': compress_ratio
            }
        except Exception as e:
            logger.error(f"Error getting backup metrics for job {job_id}: {str(e)}")
            return {}

    def get_task_session_metrics(self, session_id: str) -> Dict[str, Any]:
        """Get metrics from task sessions"""
        try:
            response = self.job_states_manager.auth.make_authenticated_request(
                "GET",
                f"/api/v1/sessions/{session_id}/taskSessions"
            )
            if response.status_code != 200:
                return {}
                
            task_sessions = response.json().get('data', [])
            
            metrics = {
                'processed_size': 0,
                'transferred_size': 0,
                'objects_processed': 0,
                'objects_successful': 0,
                'objects_failed': 0,
                'objects_warning': 0
            }
            
            for task in task_sessions:
                if task.get('type') == 'Backup':
                    # Update data sizes
                    progress = task.get('progress', {})
                    metrics['processed_size'] += progress.get('processedSize', 0)
                    metrics['transferred_size'] += progress.get('transferredSize', 0)
                    
                    # Update object counts
                    metrics['objects_processed'] += 1
                    result = task.get('result', '')
                    if result == 'Success':
                        metrics['objects_successful'] += 1
                    elif result == 'Failed':
                        metrics['objects_failed'] += 1
                    elif result == 'Warning':
                        metrics['objects_warning'] += 1
                        
            return metrics
        except Exception as e:
            logger.error(f"Error getting task session metrics for session {session_id}: {str(e)}")
            return {}

    def collect_metrics(self):
        try:
            job_states = self.job_states_manager.get_all_job_states()
            new_labels = set()
            
            for state in job_states:
                job_id = sanitize_label_value(state.get('id'))
                name = sanitize_label_value(state.get('name', 'N/A'))
                job_type = sanitize_label_value(state.get('type', 'N/A'))
                
                labels = frozenset({
                    'job_name': name,
                    'job_type': job_type,
                    'job_id': job_id
                }.items())
                new_labels.add(labels)
                labels_dict = dict(labels)

                # Set basic job metrics
                self.set_basic_job_metrics(state, labels_dict)
                
                # Get last session details
                last_session = self.job_states_manager.get_last_session_by_job_id(state.get('id'))
                if last_session:
                    # Set timing metrics
                    creation_time = last_session.get('creationTime')
                    end_time = last_session.get('endTime')
                    
                    if creation_time:
                        try:
                            creation_dt = parser.parse(creation_time)
                            creation_timestamp = creation_dt.astimezone(pytz.UTC).timestamp()
                            self.job_start_time.labels(**labels_dict).set(creation_timestamp)
                        except Exception as e:
                            logger.error(f"Error parsing creation time for job {name}: {str(e)}")
                            self.job_start_time.labels(**labels_dict).set(0)
                    
                    if end_time:
                        try:
                            end_dt = parser.parse(end_time)
                            end_timestamp = end_dt.astimezone(pytz.UTC).timestamp()
                            self.job_end_time.labels(**labels_dict).set(end_timestamp)
                            
                            if creation_time:
                                duration_seconds = int((end_dt - creation_dt).total_seconds())
                                self.job_duration_seconds.labels(**labels_dict).set(duration_seconds)
                        except Exception as e:
                            logger.error(f"Error parsing end time for job {name}: {str(e)}")
                            self.job_end_time.labels(**labels_dict).set(0)
                            self.job_duration_seconds.labels(**labels_dict).set(0)
                    
                    # Get task session metrics
                    task_metrics = self.get_task_session_metrics(last_session.get('id'))
                    self.job_processed_data_size.labels(**labels_dict).set(task_metrics.get('processed_size', 0))
                    self.job_transferred_data_size.labels(**labels_dict).set(task_metrics.get('transferred_size', 0))
                    self.job_objects_processed.labels(**labels_dict).set(task_metrics.get('objects_processed', 0))
                    self.job_objects_successful.labels(**labels_dict).set(task_metrics.get('objects_successful', 0))
                    self.job_objects_failed.labels(**labels_dict).set(task_metrics.get('objects_failed', 0))
                    self.job_objects_warning.labels(**labels_dict).set(task_metrics.get('objects_warning', 0))
                
                # Get backup metrics
                backup_metrics = self.get_backup_metrics(state.get('id'))
                self.job_backup_size.labels(**labels_dict).set(backup_metrics.get('backup_size', 0))
                self.job_deduplication_ratio.labels(**labels_dict).set(backup_metrics.get('dedup_ratio', 0))
                self.job_compression_ratio.labels(**labels_dict).set(backup_metrics.get('compress_ratio', 0))
                
                # Set total objects count
                self.job_objects_total.labels(**labels_dict).set(state.get('objectsCount', 0))
            
            # Clear metrics for jobs that no longer exist
            self.clear_old_metrics(new_labels)
            logger.info("Job metrics collected successfully for %d jobs", len(job_states))
            
        except Exception as e:
            logger.error(f"Error collecting job metrics: {str(e)}")
            self.reset_metrics()
            raise


    def clear_old_metrics(self, current_jobs: set):
        """Clear metrics for jobs that no longer exist"""
        try:
            jobs_to_remove = self._metric_labels - current_jobs
            for labels in jobs_to_remove:
                labels_dict = dict(labels)
                self.job_last_result.remove(*[labels_dict[key] for key in ['job_name', 'job_type', 'job_id']])
                self.job_last_run.remove(*[labels_dict[key] for key in ['job_name', 'job_type', 'job_id']])
                self.job_next_run.remove(*[labels_dict[key] for key in ['job_name', 'job_type', 'job_id']])
                self.job_status.remove(*[labels_dict[key] for key in ['job_name', 'job_type', 'job_id']])
                self.job_duration.remove(*[labels_dict[key] for key in ['job_name', 'job_type', 'job_id']])
            self._metric_labels = current_jobs
        except Exception as e:
            logger.error(f"Error in clear_old_metrics: {str(e)}")

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


class RepositoryMetricsCollector(MetricsCollector):
    def __init__(self, auth: VeeamAuth):
        self.repository_states_manager = VeeamRepositoryStatesManager(auth)
        self.capacity_gb = Gauge('veeam_repository_capacity_gb', 
                                'Capacity of the repository in GB', 
                                ['repo_name', 'repo_type'])  # تغییر نام label ها
        self.free_gb = Gauge('veeam_repository_free_gb', 
                             'Free space in the repository in GB', 
                             ['repo_name', 'repo_type'])
        self.used_gb = Gauge('veeam_repository_used_gb', 
                             'Used space in the repository in GB', 
                             ['repo_name', 'repo_type'])
        self._metric_labels = set()

    def reset_metrics(self):
        """Reset all repository metrics to 0"""
        try:
            for labels in self._metric_labels:
                labels_dict = dict(labels)
                self.capacity_gb.labels(**labels_dict).set(0)
                self.free_gb.labels(**labels_dict).set(0)
                self.used_gb.labels(**labels_dict).set(0)
        except Exception as e:
            logger.error(f"Error in reset_metrics: {str(e)}")


    def collect_metrics(self):
        try:
            repository_states = self.repository_states_manager.get_all_repository_states()
            new_labels = set()
            
            for state in repository_states:
                labels = {
                    'repo_name': sanitize_label_value(state.get('name', 'N/A')),
                    'repo_type': sanitize_label_value(state.get('type', 'N/A'))
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
password = "admin"

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
    app.run(host='0.0.0.0', port=8001)
