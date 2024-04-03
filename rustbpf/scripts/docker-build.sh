#!/bin/sh
exec scripts/docker-run.sh pipenv run scripts/build.sh "$@"
