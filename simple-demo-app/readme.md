# A simple Demo Application

## How It Works

demo application showcases an The server typescript server that serves an Angular SPA frontend application and as well as some demo api routes. The server authenticates it's users using a remote Auth2.0 OpenID Connect complient SSO Authorization Server ( e.g Keycloak ). Once succesful Authentication is achieved, the server maintains a secure stateless JWT token session with the client frontend code. The approach used for session management is _mostly_ stateless. Traditional cookies are only used for state management during login with the SSO and are then immediately deleted.

The client executes the [OAuth2.0 Authorization Code grant](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow) with PKCE parameters on an Authorization Server to Authenticate it's users.

The goal for the server is to limit access to specific routes to authorized users. The server is also able to distinguish between users ( admin, provider etc ) by parsing assigned roles assigned by the authorization server ( keycloak server ), this allows the server to further limit specific routes.

### Key Terms

> **Note**: Read more about the Authorization Server an key terms [official Keycloak Server guide](https://www.keycloak.org/docs/latest/server_admin/index.html)

**Authorization Server**: An Auth2.0 OpenID Connect complient SSO Authorization Server ( e.g Keycloak ).

**users**: Users are entities that are able to log into your system. They can have attributes associated with themselves like email, username, address, phone number, and birthday. They can be assigned group membership and have specific roles assigned to them.

**authentication**: The process of identifying and validating a user.

**authorization**: The process of granting access to a user.

**roles**: Roles identify a type or category of user. Admin, user, manager, and employee are all typical roles that may exist in an organization. Applications often assign access and permissions to specific roles rather than individual users as dealing with users can be too fine-grained and hard to manage.

**clients**: Clients are entities that can request Keycloak to authenticate a user. Most often, clients are applications and services that want to use Keycloak to secure themselves and provide a single sign-on solution. Clients can also be entities that just want to request identity information or an access token so that they can securely invoke other services on the network that are secured by Keycloak.

**Authorization Code**: A code that a registered client is able to provide to an Authorization Server in exchange of access,id,refresh tokens.

**Access Token**: A JWT token that can be transmitted to resource servers in order to gain access to sensitive information. Has a relatively short expiry date.

**ID Token**: A JWT token that mainly contains information about the signed user. The token is mainly used by applications to setup and maintain secure sessions between client and server code (frontend and backend ). Sending the token in the Authorization Server's logout endpoint also allows logout from the SSO. Expiry date rarely matters as it is mainly used to get user info.

**Refresh Token**: A JWT token used to issue a new pair of Access, ID and refresh tokens. The token is sent to the Authorization Server to issue refresh. Old tokens are invalidated. The refresh token is often kept secure in HTTPonly cookies, databases, or, in this example, encrypted and sent as part of an JWT token to the client frotend application for storage. Has a relative long expiry date.

### How The Login Flow works

1. The frontend SPA client ( Angular in our case ) **redirects** to a specific backend route ( here `/api/auth/jwt/login` ) in order to initiate the login process.

2. The backend application initiates the Authorization Code Grant.

In short, the backend **redirects** to the Authorization Server's login Screen. Uppon succesful user login, the Authorization Server returns to the backend application with an "Authorization Code". The server then redirects to the Authorization server while providing the Authorization Code in order to receive a pair of access,id,refresh tokens for the signed in user.

3. The Authorization server returns to a specific backend route ( here `/api/auth/jwt/callback` ) with the tokens included. The backend generates its own JWT tokens to initiate a secure session with browser client code ( Angular SPA ). It **redirects** the user back to the SPA with the generated, short lived, session's JWT token as a URL parameter.

4. The Frontend SPA Application captures the URL parameter and **keeps the token in memory**. It is a bad practice for the frontend to store tokens in localstorage ( due to scripting vunerabilities ).

5. The Frontend SPA Application now calls limited, to logged in users, backend routes by adding an Authorization `Bearer `+token header and using the includeCredentials flag.

> **Note**: The backend also manages token renewal when the session JWT access token expires. It calls the refresh endpoint on the Authentication Server and if a new tokenset is returned from the Authorization Server, it issues a new JWT for the session. Otherwise it returns a hint for the frontend to login again as the client is in an invalid state or the oidc session has expired.

### How the Logout Flow works

1. Similarly to the login flow, the SPA **redirects** to a specific backend route ( here `/api/auth/jwt/logout` ).

2. If an access token is provided, the backend **redirects** to the Authorization Server's end Session endpoint. Otherwise, it just redirects to frontend host as there is no way to end Session without an access token.

3. After successful logout, the Authorization Server **redirects** to a specific URL ( here is the domain root ).

### Limitations

1. The Angular Frontend Application code doesn't really follow standard conventions or best practices. This was mostly done this way to limit the files being touched in the project. Same applies for the backend code. The code could be structured more efficiently.

2. The project does not implement custom parameters in login or logout routes ( but contains comments on the backend login route that briefly explain how they can be implemented using the state variable ). In a real project, custom parameters are most likely needed to provide hints about actions to be retried after login, navigation that need to happen inside the SPA after login etc.

3. The approach of the backend application serving the SPA using the `/public` folder is not efficient for production environments. Instead, and if a reverse proxy needs to be configured, make the proxy server the SPA directly. This will increase performance.

## Setup

### Setup the Client on Keycloak

1. Startup or use a keycloak instance. You may use [keycloak-compose](https://github.com/stzagkarak/keycloak-compose) repo to spin up a quick development keycloak instance.

2. Create the following configuration:

- Create a new realm called `demo-realm`.
- Create 1 Client the following configuration:

Replace HOST with above

```
HOST =  if local dev use http://localhost:3001
        if production use <protocol>://<domain>
```

```
Client ID:              demo-client
Client authentication:  ON
Authorization:          OFF
Standard flow:          On
Root URL:                           ${HOST}
Valid Redirect URIs:                ${HOST}/api/auth/jwt/callback
Valid Post logout redirect URIs:    ${HOST}
```

Generate client secret and copy to server's .env file. If production, the backend.prod.env file used ( located in the `simple-demo-app` folder ).

3. Create a user from the Users tab.

### Setup roles appearing in tokens

To allow our backend server to distinguish between users, we need to include assigned roles in our generated tokens.

- First let's create the realm role `admin` inside the `demo-realm`.
- Now, in `Clients->"demo-client"->Client scopes->"demoClient-dedicated"->Mappers->Add Predefined Mapper` we locate `realm-roles`. We enable "Add to ID Token" and Save.
- We assign the admin role to users from `<our_user>->Role Mapping->Assign->realm Roles`.

### Start in dev mode ( no docker container )

- Edit the environemnt variables found in `/backend/.env` so that they match the active configuration. Make sure to set `DOCKER_EXISTS=0`, `NODE_ENV=development`, `PROXY_EXISTS=0`.

- Run `npm i` followed by `npm run dev`.

- Navigate on `FRONTEND_URL` from your browser.

> **Note**: If you make any changes to the HOST URL, make sure to also update the environment file located in `simple-demo-app/backend/angular-frontend/src/environments/environment.development.ts`.

### Start local using a docker container

- Install docker and docker compose to your machine.

- Edit the environemnt variables found in `/backend/.env` so that they match the active configuration. Make sure to set `DOCKER_EXISTS=1`, `NODE_ENV=development`, `PROXY_EXISTS=0`.

- Run `docker compose up` on the `simple-demo-app` folder.

- Navigate on `FRONTEND_URL` from your browser.

> **Note**: If you make any changes to the HOST part(s), make use to update the environment file located in `simple-demo-app/backend/angular-frontend/src/environments/environment.development.ts`.

### Start in production

- Register and bind a domain to owned server.

- git clone this repo on your server.

- Install docker and docker compose on your server.

- Edit the environemnt variables found in `backend.prod.env` and `angualar.prod.environemnt.ts` so that they match the active configuration. Make sure to set `DOCKER_EXISTS=1`, `NODE_ENV=development`, `PROXY_EXISTS=0`.

- Run `run_prod.sh` on the `simple-demo-app` folder.

- Navigate on `FRONTEND_URL` from your browser.

> **Note**: Highly recomended to setup a reverse proxy. If so, make sure to set `PROXY_EXISTS=1` in the `backend.prod.env` file. See instruction in the `setup-nginx` folder found on the [keycloak-compose](https://github.com/stzagkarak/keycloak-compose) repo.

> **Note**: Explaination about env files in production: The `backend.prod.env` environment file is passed on the express-server container using the env_file directive. The official node js docker images inject env files provided in docker-compose directives directly in the application environment. ( no need to `dotenv.config();` ).
