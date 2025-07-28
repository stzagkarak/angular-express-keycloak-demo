#!/bin/bash
# $1 -> --build to build the image
# $2 -> -d to run compose detached

#mv .env development.env # rename .env file to keep it from being used in docker-compose file 
cp angular.prod.environment.ts ./backend/angular-frontend/src/environments/environment.ts

docker compose down --remove-orphans
docker compose up $1 $2
