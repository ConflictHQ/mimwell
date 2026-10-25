"""Loopback-only App host worker; enabled by the portal operator explicitly."""

bind = "127.0.0.1:8082"
worker_class = "sync"
workers = 4
threads = 1
backlog = 4
timeout = 3
graceful_timeout = 3
keepalive = 0
max_requests = 1000
max_requests_jitter = 50
worker_tmp_dir = "/tmp"
control_socket_disable = True
forwarded_allow_ips = ""
secure_scheme_headers = {}
forwarder_headers = ""
limit_request_line = 1024
limit_request_fields = 32
limit_request_field_size = 8190
accesslog = None
# Request parse errors can contain caller-controlled bearer/header text.
errorlog = "/dev/null"
capture_output = False
