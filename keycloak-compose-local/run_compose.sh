#!/bin/bash

# $1 -> -d to run compose detached 
mkdir -p instance/database/mbackups

docker-compose down --remove-orphans
docker-compose up $1