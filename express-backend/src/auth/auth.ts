import { Application } from "express";
import passport from 'passport';
import { BaseClient, Issuer, Strategy } from 'openid-client';


export async function create_client() {

    const keycloakIssuer = await Issuer.discover(process.env.ISSUER_URL as string);
    console.log('Discovered issuer %s', keycloakIssuer.issuer);

    return new keycloakIssuer.Client({
        client_id: process.env.CLIENT_ID as string,
        client_secret: process.env.CLIENT_SECRET as string,
        redirect_uris: process.env.VALID_REDIRECT_URIS?.split(' '),
        post_logout_redirect_uris: process.env.VALID_POST_LOGOUT_REDIRECT_URIS?.split(' '),
        response_types: ['code'],
    });
}

export async function setup_auth_strategy(app: Application, client: BaseClient) {

    app.use(passport.initialize())
    app.use(passport.session()) // test if session is authenticated

    passport.use('oidc', new Strategy(
        {client}, 
        (tokenSet: { claims: () => any; }, userinfo: any, done: (arg0: null, arg1: any) => any)=>{
            return done(null, tokenSet.claims());
        })
    )

    passport.serializeUser(function(user, done) {
        done(null, user);
    });
    
    passport.deserializeUser(function(user:Express.User, done) {
        done(null, user);
    });

    return app;
}

