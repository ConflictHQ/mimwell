"""The brain's MCP endpoint behind the portal container's nginx (#459).

Loopback only: nginx is the one way in. The brain is read once in the master
(preload) and the workers share it.
"""

bind = "127.0.0.1:8081"
worker_class = "gthread"
workers = 2
threads = 4
preload_app = True
timeout = 30
graceful_timeout = 10
keepalive = 2
max_requests = 2000
max_requests_jitter = 100
control_socket_disable = True
forwarded_allow_ips = ""
limit_request_line = 4094
limit_request_fields = 64
limit_request_field_size = 16384
accesslog = None
# Warnings and worse only: request parse errors (debug) can carry header text.
errorlog = "-"
loglevel = "warning"
capture_output = False
