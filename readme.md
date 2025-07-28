# OIDC Application Samples

## Overview

The repository covers Authentication scenarios with remote Auth2.0 OpenID Connect complient SSO Authorization Servers.

- The first scenario ( found in `simple-demo-app` ) showcases user Authentication using the [OAuth2.0 Authorization Code grant](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow). The demo application ( express typescript backend - Angular SPA frontend ) Authenticates users using a remote Auth2.0 OpenID Connect complient SSO Authorization Server ( e.g Keycloak Authorization Server but others should work aswell ).

- The second scenario ( found in `server-to-server-demo-app` ) showcases a use case for the [Client Credentials OAuth2.0 Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow) in order to authorize server to server data communication.

## Introduction / Basics

> See the `Authentication Basics.pdf` resource for a general introduction to concepts seen in this repo.

## Extending to Other Frameworks

The underlying concepts and strategies shown in this repo are used in most frontend frameworks, regardless of language or library. Starting with a clear goal or plan in mind makes developing much easier.

## Credits and Acknowledgements

The author would like to specify that parts of the node.js code found in this repo were AI-Generated.

stzagkarka@0725
