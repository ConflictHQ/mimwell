"""Four isolated sync workers; a watchdog replaces stalled processes."""
import json

bind = '0.0.0.0:8000'
worker_class = 'sync'
workers = 4
threads = 1
backlog = 4
timeout = 3
graceful_timeout = 3
keepalive = 0
max_requests = 1000
max_requests_jitter = 50
worker_tmp_dir = '/tmp'
control_socket_disable = True
forwarded_allow_ips = ''
secure_scheme_headers = {}
forwarder_headers = ''
limit_request_line = 1024
limit_request_fields = 32
limit_request_field_size = 8190
accesslog = None
errorlog = '/dev/null'  # Parser/error text can contain caller-controlled secrets.
capture_output = False


def post_fork(server, worker):
    print(json.dumps({'event': 'worker-started', 'pid': worker.pid}), flush=True)


def child_exit(server, worker):
    print(json.dumps({'event': 'worker-exited', 'pid': worker.pid}), flush=True)
