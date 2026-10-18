#!/bin/bash
# Two processes in one container (#459): gunicorn serves the brain's MCP
# endpoint on loopback, nginx serves the portal on 8080 and proxies /mcp to it.
# Either one exiting stops the other and ends the container, so the platform
# restarts it whole. As PID 1, bash ignores any signal it has no handler for,
# so the trap is set first.
set -u
mcp="" web=""
stop() { kill -TERM ${mcp:+"$mcp"} ${web:+"$web"} 2>/dev/null; }
trap stop TERM INT
gunicorn --config /opt/brain/portal/gunicorn.conf.py 'brain_mcp:create_application()' &
mcp=$!
# nginx, and so /health, comes up only once the endpoint listens (gunicorn reads
# the brain before it binds), so a starting pod never answers /mcp with a 502.
until (exec 3<>/dev/tcp/127.0.0.1/8081) 2>/dev/null; do
    if ! kill -0 "$mcp" 2>/dev/null; then
        wait "$mcp"
        exit $?
    fi
    sleep 0.2
done
nginx -c /opt/brain/portal/nginx.conf -e /dev/stderr -g 'daemon off;' &
web=$!
wait -n "$mcp" "$web"
status=$?
stop
wait
exit "$status"
