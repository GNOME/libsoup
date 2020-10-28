#!/bin/sh

REPORTS_DIR="${PWD}/reports"

cd "$(dirname "$0")"

[ ! -d "${REPORTS_DIR}" ] && mkdir "${REPORTS_DIR}"

docker run -it --rm \
       -v "${PWD}:/config" \
       -v "${REPORTS_DIR}:/reports" \
       -p 9001:9001 \
       --name fuzzingserver \
       crossbario/autobahn-testsuite
