#!/bin/bash

set -e

TAG="registry.gitlab.gnome.org/gnome/libsoup/master:v5"

SUDO_CMD="sudo"
if docker -v |& grep -q podman; then
        # Using podman
        SUDO_CMD=""
        # Docker is actually implemented by podman, and its OCI output
        # is incompatible with some of the dockerd instances on GitLab
        # CI runners.
        export BUILDAH_FORMAT=docker
fi

cd "$(dirname "$0")"
$SUDO_CMD docker build --build-arg HOST_USER_ID="$UID" --tag "${TAG}" \
    --file "Dockerfile" .

if [ "$1" = "--push" ]; then
  $SUDO_CMD docker login registry.gitlab.gnome.org
  $SUDO_CMD docker push $TAG
else
  $SUDO_CMD docker run --rm \
      --volume "$(pwd)/..:/home/user/app" --workdir "/home/user/app" \
      --tty --interactive "${TAG}" bash
fi
