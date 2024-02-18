# Demo Application to demonstrate "secure" authorization and session management using keycloak as the OIDC provider

> Warning: DO NOT USE the same configuration for production environments. For guidence on moving to production see `deploying_to_production.md` TODO

### Conseptual Ideas behind this demo

See the appropriate presentation `Securing-Servers-with-Keycloak.pdf`.

### Run this demo 

> Prerequisites: Install docker, docker-compose, node.js, npm in order to run this demo. 

> Note: The instructions bellow were tested on linux.

#### Spin Up and Configure KeyCloak

1. Startup a keycloak instance. Open a terminal on the `keycloak-compose-local` folder and run `./run_compose.sh`. This will spin up a keycloak instance on `http://localhost:8080`

> Warning: DO NOT USE this configuration to spin up a keycloak instance in production. See `deploying_to_production.md` for more information.

2. Open a browser and navigate to `http://localhost:8080`. 

3. Click administration panel and login using "demo" as username and password. 

4. Create a new realm with name "demoRealm" clicking the "Create Realm" button on the top left dropdown of the UI. 

5. Create a Client by navigating on the Clients->Create client.
- Use `demoClient` as client ID. 
- Enable Client Authentication ( in order for the client to be secure )
- Make sure Standard flow is checked.
- Uncheck Direct Access Grants.
- Add `https://localhost:8181/login/success` on Valid redirect URIs
- Add `https://localhost:8181/logout/success` on Valid Post Logout redirect URIs
- Add `https://localhost:8181` on Web Origins

6. Create 2 users using the admin panel. Navigate to Users->Add User. Provide usernames. After creating a user, navigate to credentials tab and a password. No need to set the password as temporary. 

##### Create another kind of user

7. Navigate to Clients->demoClient->Client Scopes->demoClient-Dedicated->Configure A New Mapper->User Attribute. 
- Provide a name.
- Set User Attribute to `user-role`.
- Set Token Claim Name to `user-role`.

8. On **1** of the 2 created users, navigate on their attributes tab, add an attribute with name `user-role` and value `admin`.

#### Setup and Spin Up the Backend Service

1. Navigate to Clients->demoClient->Credentials and copy the client_secret value.

2. Open express-backend/.env file and change paste the value on the `CLIENT_SECRET` field.

> Note: Notice that there are other fields (e.g ISSUER_URL, CLIENT_ID ) that are pre-filled with the demoClient information. When creating realms/clients with different names, those values need to be updated accordingly. 

3. Open a terminal on on path `demo-application/express-backend`. Run in sequence: 
```
npm i
npm run dev
```
You should see "Server running on https://localhost:8181" when  

> Note: DO NOT RUN a server this way in production. See `deploying_to_production.md`.

#### Setup and Spin Up the Frontend Server 

1. Open a terminal on path `demo-application/angular-demo-frontend`. Run in sequence:
```
npm i
npx ng serve --ssl
```

> Note: DO NOT SERVE your frontend this way in production. See `deploying_to_production.md`.

All should be ok. navigate to `https://localhost:4200` to see the demo application UI.

#### Extra Features

- Enable user-registration, forgot-password, Remember-Me in Realm Settings->Login.

- Setup Email Sender (for specific actions )
    - An an email address to your admin "demo" account.
    - Configure mailhost Realm Settings->Email.

- Enable Consent Page under Clients->demoClient

### Creating Custom Themes

TODO

### Further reading

Please study the provided code and read through the provided presentation. Additionally, I highly encourage you to check the bellow resources (random order): 

1. https://medium.com/@prashantramnyc/node-js-with-passport-authentication-simplified-76ca65ee91e5
2. https://medium.com/keycloak/keycloak-express-openid-client-fabea857f11f
3. https://dev.to/zachgoll/the-ultimate-guide-to-passport-js-k2l
4. https://dev.to/cristain/how-to-set-up-typescript-with-nodejs-and-express-2023-gf
5. https://medium.com/@ramanamuttana/custom-attribute-in-keycloak-access-token-831b4be7384a

Credits: stzagkarak@Feb2024