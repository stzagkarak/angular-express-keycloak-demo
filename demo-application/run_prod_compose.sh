#!/bin/bash

# $1 -> -d to run compose detached 
mkdir -p instance/nginx

docker-compose down --remove-orphans
docker-compose build
docker-compose up $1
