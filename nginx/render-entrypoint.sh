#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL must be configured}"
: "${TILESERV_DATABASE_URL:?TILESERV_DATABASE_URL must be configured}"
: "${JWT_SECRET:?JWT_SECRET must be configured}"

cp /etc/nginx/render-nginx.conf.template /etc/nginx/conf.d/default.conf

nginx -t

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/render.conf