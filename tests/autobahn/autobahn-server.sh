#!/usr/bin/env bash

# set -x

REPORTS_DIR="${PWD}/reports"

cd "$(dirname "$0")"

[ ! -d "${REPORTS_DIR}" ] && mkdir "${REPORTS_DIR}"

ACTION=${1:---start}
PORT=${2:-9001}

autobahn_pid() {
   echo $(lsof -i:$PORT | tail -1 | awk '{ print $2 }')
}

ensure_autobahn_is_not_running() {
   local pid=$(autobahn_pid)
   if [[ $pid -gt 0 ]]; then
      autobahn_stop
      pid=$(autobahn_pid)
      if [[ $pid -gt 0 ]]; then
         echo "Cannot start autobahn server: $PORT already in use"
         exit 1
      fi
   fi
}

autobahn_start() {
   ensure_autobahn_is_not_running

   if [[ -n "${USE_DOCKER}" ]]; then
      docker run -it --rm \
             -v "${PWD}:/config" \
             -v "${REPORTS_DIR}:/reports" \
             -p $PORT:$PORT \
             --name fuzzingserver \
             crossbario/autobahn-testsuite
   else
      virtualenv ~/wstest
      wstest -m fuzzingserver &> autobahn-server.log
   fi
}

autobahn_stop() {
   local pid=$(autobahn_pid)
   kill $pid &> /dev/null
}

case "$ACTION" in
   "--start")
      autobahn_start
   ;;
   "--stop")
      autobahn_stop
   ;;
   *)
      echo "Unknown argument: $ACTION"
      exit 1
esac
