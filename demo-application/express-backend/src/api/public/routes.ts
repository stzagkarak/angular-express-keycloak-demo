import { Router } from "express";
import passport from 'passport';
import { oidc_client } from "../..";
import { post_login_fr_redirect_URIs, post_register_fr_redirect_URIs, storeLoginCallback, storeRegisterCallback } from "../../auth/auth";

const FRONTEND_HOST = process.env.FROTNEND_HOST || "";

const ISSUER_HOST = process.env.ISSUER_HOST || "";
const REALM_NAME = process.env.REALM_NAME || "";
const CLIENT_ID = process.env.CLIENT_ID || "";
const SELF_HOST = process.env.SELF_HOSTNAME || "";
const SELF_HOST_REG = SELF_HOST + "/register/success";

const REGISTARTION_PATH = `${ISSUER_HOST}/realms/${REALM_NAME}/protocol/openid-connect/registrations?client_id=${CLIENT_ID}&scope=openid%20profile&redirect_uri=${SELF_HOST_REG}&response_type=code`;

export const publicRoutes = Router();

publicRoutes.get("/register", storeRegisterCallback, (req, res, next) => {
    res.redirect(REGISTARTION_PATH)
})

publicRoutes.get('/register/success', (req, res, next) => {

    // retrieve callback stored by storeRegisterCallback middleware 
    const callback = req.session.useCallback || post_register_fr_redirect_URIs[0];
    delete req.session.useCallback;

    res.redirect(FRONTEND_HOST + callback);
});

publicRoutes.get("/login", storeLoginCallback, passport.authenticate('oidc'));

const FAILED_LOGIN_PATH = process.env.FRONTEND_POST_LOGIN_FAILED_URI || "/fail";
publicRoutes.get('/login/success', (req, res, next) => {

    const callback = req.session.useCallback || post_login_fr_redirect_URIs[0];
    delete req.session.useCallback;

    console.log("Retrieved callback: " + FRONTEND_HOST + callback)

    passport.authenticate('oidc', {
        successRedirect: FRONTEND_HOST + callback,
        failureRedirect: FRONTEND_HOST + FAILED_LOGIN_PATH
    })(req, res, next)
});

publicRoutes.get('/logout', (req, res, next) => {
    req.session.destroy((err)=> {
        res.redirect(oidc_client.endSessionUrl());
    })
});

publicRoutes.get('/logout/success', (req, res, next) => {

    // also clear the local session
    req.session.destroy((err) => {
        // redirects the user to a public route
        res.redirect(FRONTEND_HOST + '/welcome');
    }); 
});

publicRoutes.post('/login/status', passport.authenticate("session"), (req, res, next) => {
    if(req.isAuthenticated()) {
        return res.status(200).send({status: 1})
    }
    return res.status(200).send({status: 0})
})