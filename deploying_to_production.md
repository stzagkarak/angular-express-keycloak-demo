# Moving from development to production

## Running a "secure" keycloak instance on a production server

You may use [the following repo](https://github.com/stzagkarak/keycloak-compose) to kickstart a **basic** production-ready keycloak instance.  Please keep in mind that this repo is not *yet* fully documented. 

## Running the fullstack project on a production server 

> Note: The following guidelines are preferences.

1. Setup a nginx reverse proxy for on the production server.
2. Secure the nginx server using let's encrypt. 
> Note: You may use the `jonasal/nginx-certbot` image to automate that process.

1. Build and containarize the backend application. 