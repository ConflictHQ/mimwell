#!/bin/bash
# The portal's MCP endpoint and nginx are always enabled. An operator may also
# opt in to the native App host as a third, loopback-only worker. Any child exit
# stops the others so the platform restarts the container as a unit. As PID 1,
# bash ignores signals without an explicit trap, so install it before launching.
set -u
mcp="" apps="" web=""
stop() { kill -TERM ${mcp:+"$mcp"} ${apps:+"$apps"} ${web:+"$web"} 2>/dev/null; }
trap stop TERM INT

native_routes=/tmp/native-app-routes.conf
native_routes_tmp=$(mktemp /tmp/native-app-routes.XXXXXX) || exit 1
native_enabled=0
case "${BRAIN_PORTAL_NATIVE_APPS-}" in
    ""|0)
        if [ -n "${BRAIN_APPS_HOST-}${BRAIN_APP_BUNDLE_ROOT-}${BRAIN_APP_BROWSER_PROXY_PREFIX-}${BRAIN_APP_PUBLICATION_REGISTRY-}${BRAIN_APP_HOST_BRAIN_ID-}${BRAIN_APP_ENVIRONMENT_ID-}" ]; then
            echo "Native App host settings require BRAIN_PORTAL_NATIVE_APPS=1" >&2
            rm -f "$native_routes_tmp"
            exit 64
        fi
        ;;
    1)
        native_enabled=1
        missing=""
        [ -n "${BRAIN_APPS_HOST-}" ] || missing="BRAIN_APPS_HOST"
        [ -n "${BRAIN_APP_BUNDLE_ROOT-}" ] || missing="${missing:-BRAIN_APP_BUNDLE_ROOT}"
        [ -n "${BRAIN_OPERATIONS_ROOT-}" ] || missing="${missing:-BRAIN_OPERATIONS_ROOT}"
        [ -n "${BRAIN_APP_BROWSER_PROXY_PREFIX-}" ] || missing="${missing:-BRAIN_APP_BROWSER_PROXY_PREFIX}"
        [ -n "${BRAIN_APP_PUBLICATION_REGISTRY-}" ] || missing="${missing:-BRAIN_APP_PUBLICATION_REGISTRY}"
        [ -n "${BRAIN_APP_HOST_BRAIN_ID-}" ] || missing="${missing:-BRAIN_APP_HOST_BRAIN_ID}"
        [ -n "${BRAIN_APP_ENVIRONMENT_ID-}" ] || missing="${missing:-BRAIN_APP_ENVIRONMENT_ID}"
        [ -n "${BRAIN_CONTEXT_CREDENTIALS-}" ] || missing="${missing:-BRAIN_CONTEXT_CREDENTIALS}"
        if [ -n "$missing" ]; then
            echo "Native App host requires $missing" >&2
            rm -f "$native_routes_tmp"
            exit 64
        fi
        if [ -z "${BRAIN_CANON_DSN-}" ] && [ -z "${BRAIN_CANON_DSN_FILE-}" ]; then
            echo "Native App host requires BRAIN_CANON_DSN or BRAIN_CANON_DSN_FILE" >&2
            rm -f "$native_routes_tmp"
            exit 64
        fi
        if [ "${BRAIN_APP_BROWSER_PROXY_PREFIX-}" != "/api/native-brain" ]; then
            echo "Native App host requires the fixed /api/native-brain proxy prefix" >&2
            rm -f "$native_routes_tmp"
            exit 64
        fi
        if ! cat >"$native_routes_tmp" <<'NATIVE_APP_ROUTES'
        location = /apps {
            access_log off;
            error_log /dev/null emerg;
            client_max_body_size 64k;
            proxy_pass http://127.0.0.1:8082;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header Connection "";
            proxy_set_header X-Forwarded-For "";
            proxy_set_header X-Forwarded-Proto "";
            proxy_set_header X-Forwarded-User "";
            proxy_connect_timeout 1s;
            proxy_send_timeout 4s;
            proxy_read_timeout 5s;
            proxy_next_upstream off;
        }
        location ~ "^/apps/[a-z][a-z0-9-]{0,63}/?$" {
            access_log off;
            error_log /dev/null emerg;
            client_max_body_size 64k;
            proxy_pass http://127.0.0.1:8082;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header Connection "";
            proxy_set_header X-Forwarded-For "";
            proxy_set_header X-Forwarded-Proto "";
            proxy_set_header X-Forwarded-User "";
            proxy_connect_timeout 1s;
            proxy_send_timeout 4s;
            proxy_read_timeout 5s;
            proxy_next_upstream off;
        }
        location ~ "^/brain/(record|revision|context)$" {
            access_log off;
            error_log /dev/null emerg;
            client_max_body_size 64k;
            proxy_pass http://127.0.0.1:8082;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header Connection "";
            proxy_set_header X-Forwarded-For "";
            proxy_set_header X-Forwarded-Proto "";
            proxy_set_header X-Forwarded-User "";
            proxy_connect_timeout 1s;
            proxy_send_timeout 4s;
            proxy_read_timeout 5s;
            proxy_next_upstream off;
        }
        location ~ "^/brain/records/[^/]{1,128}$" {
            access_log off;
            error_log /dev/null emerg;
            client_max_body_size 64k;
            proxy_pass http://127.0.0.1:8082;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header Connection "";
            proxy_set_header X-Forwarded-For "";
            proxy_set_header X-Forwarded-Proto "";
            proxy_set_header X-Forwarded-User "";
            proxy_connect_timeout 1s;
            proxy_send_timeout 4s;
            proxy_read_timeout 5s;
            proxy_next_upstream off;
        }
NATIVE_APP_ROUTES
        then
            echo "Could not prepare the native App route configuration" >&2
            rm -f "$native_routes_tmp"
            exit 1
        fi
        ;;
    *)
        echo "BRAIN_PORTAL_NATIVE_APPS must be unset, 0, or 1" >&2
        rm -f "$native_routes_tmp"
        exit 64
        ;;
esac
if ! mv -f "$native_routes_tmp" "$native_routes"; then
    echo "Could not prepare the native App route configuration" >&2
    rm -f "$native_routes_tmp"
    exit 1
fi

fail_startup() {
    status=$1
    stop
    wait 2>/dev/null
    exit "$status"
}

wait_for_apps() {
    deadline=$((SECONDS + 60))
    while ! python3 -c 'import http.client,sys; c=http.client.HTTPConnection("127.0.0.1",8082,timeout=1); c.request("GET","/apps"); r=c.getresponse(); r.read(1); sys.exit(0 if r.status == 401 else 1)' >/dev/null 2>&1; do
        if ! kill -0 "$apps" 2>/dev/null; then
            wait "$apps"
            status=$?
            [ "$status" -ne 0 ] || status=1
            return "$status"
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            return 1
        fi
        sleep 0.2
    done
}

gunicorn --config /opt/brain/portal/gunicorn.conf.py 'brain_mcp:create_application()' &
mcp=$!
# nginx, and so /health, comes up only once the endpoint listens (gunicorn reads
# the brain before it binds), so a starting pod never answers /mcp with a 502.
until (exec 3<>/dev/tcp/127.0.0.1/8081) 2>/dev/null; do
    if ! kill -0 "$mcp" 2>/dev/null; then
        wait "$mcp"
        status=$?
        [ "$status" -ne 0 ] || status=1
        fail_startup "$status"
    fi
    sleep 0.2
done
if [ "$native_enabled" -eq 1 ]; then
    gunicorn --config /opt/brain/portal/app-gunicorn.conf.py 'context_service:create_application()' &
    apps=$!
    wait_for_apps
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "Native App host failed startup readiness" >&2
        fail_startup "$status"
    fi
    if ! kill -0 "$mcp" 2>/dev/null; then
        wait "$mcp"
        status=$?
        [ "$status" -ne 0 ] || status=1
        fail_startup "$status"
    fi
fi
nginx -c /opt/brain/portal/nginx.conf -e /dev/stderr -g 'daemon off;' &
web=$!
if [ -n "$apps" ]; then
    wait -n "$mcp" "$apps" "$web"
else
    wait -n "$mcp" "$web"
fi
status=$?
stop
wait
exit "$status"
