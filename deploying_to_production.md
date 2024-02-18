# Moving from development to production

## Running a "secure" keycloak instance on a production server

You may use [the following repo](https://github.com/stzagkarak/keycloak-compose) to kickstart a **basic** production-ready keycloak instance.  Please keep in mind that the repo is not fully documented. 

## Running the fullstack project on a production server 

> Note: The following guidelines are preferences.

> Note: You need to acquire a domain name and bind it to your machine's ip in order for the configuration to work.

You may use the configuration inside the demo-application folder. 

**Note that you will have to change values inside the config files to much your deployment.**

The deployment configuration (initiated by running `./run_prod_compose.yml`): 
1. Configures a https nginx reverse proxy for your acquired domain 
    - Using `prod-configs/nginx-certbot.env` .
    - Using the nginx .conf file inside `prod-configs/user_conf.d/app.nginx.conf` .  
    - More info on [this repo](https://github.com/JonasAlfredsson/docker-nginx-certbot)
  
2. Builds and runs the express-server backend inside a container 
    - Using the configuration file `prod-configs/backend.env`
The nginx configuration binds the webserver on `https://your.domain.com/api/`.

3. Builds and binds your frontend code to the nginx html directory.
    - Before building, it replaces the `environment.ts` angular file with the one located on `prod-configs/angular_environment`
The nginx configuration serves your frontend files on `https://your.domain.com/`.
