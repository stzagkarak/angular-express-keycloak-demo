import { Router } from "express";
import passport from 'passport';
import { oidc_client } from "../..";

const FRONTEND_HOST = process.env.FROTNEND_HOST || "";

export const publicRoutes = Router();

publicRoutes.get("/login", passport.authenticate('oidc'))

publicRoutes.get('/login/success', passport.authenticate('oidc', {
    successRedirect: FRONTEND_HOST + "/welcome",
    failureRedirect: FRONTEND_HOST + "/fail"
}));

publicRoutes.get('/logout', (req, res, next) => {
    res.redirect(oidc_client.endSessionUrl());
});

publicRoutes.get('/logout/success', (req, res, next) => {

    // also clear the local session 
    req.logout((err)=> {
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