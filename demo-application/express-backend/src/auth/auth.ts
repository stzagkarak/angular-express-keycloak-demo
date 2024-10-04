import { Application, NextFunction, Request, Response } from "express";
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

declare module 'express-session' {
    interface SessionData {
        useCallback: string;
    }
}

export const post_register_fr_redirect_URIs = process.env.FRONTEND_POST_REGISTER_REDIRECT_URIS?.split(' ') || [];
export async function storeRegisterCallback(req: Request, res: Response, next: NextFunction) {
    if(req.query && req.query.userType && req.query.userType == "provider") {
        // redirect URI for 
        req.session.useCallback = post_register_fr_redirect_URIs[1];
    }
    
    // default redirectURI
    else req.session.useCallback = post_register_fr_redirect_URIs[0];

    return next();
}

export const post_login_fr_redirect_URIs = process.env.FRONTEND_POST_LOGIN_REDIRECT_URIS?.split(' ') || [];
export async function storeLoginCallback(req: Request, res: Response, next: NextFunction) {
    if(req.query && req.query.userType && req.query.userType == "provider") {
        // redirect URI for 
        req.session.useCallback = post_login_fr_redirect_URIs[1];
    }
    
    // default redirectURI
    else req.session.useCallback = post_login_fr_redirect_URIs[0];

    return next();
}

