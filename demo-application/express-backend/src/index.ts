import "dotenv/config";
import express, { Application } from "express";
import expressSession from 'express-session';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { BaseClient, Issuer, Strategy } from "openid-client";
import { apiRouter } from "./api/api";
import https from "https";
import passport from 'passport';
import fs from "fs";
import { create_client, setup_auth_strategy } from "./auth/auth";

let app: Application = express();
const port = parseInt(process.env.SERVER_PORT as string) || 8181;
export let oidc_client: BaseClient;

async function setup_defaults() {

    app.use(cookieParser())

    app.use(cors({
        credentials: true,
        origin: [process.env.FROTNEND_HOST as string],
    }))

    let memoryStore = new expressSession.MemoryStore();
    app.use(
        expressSession({
            secret: process.env.EXPRESS_SESSION_SECRET as string,
            resave: false,
            saveUninitialized: true,
            store: memoryStore,
            cookie: {
                sameSite: "lax",
                httpOnly: true,
                secure: (process.env.LOCAL_DEV_SSL === 'true') 
                || (process.env.TLS_TERMINATION_PROXY === 'true'), 
                maxAge: 1000*60*60*10 
                    // 30 minute session ( session length should be close to or identical to realms session idle expiration timeout  )
            }
        })
    )
}

async function initialize() {
    
    // discover client information 
    oidc_client = await create_client()

    // trust proxy if server runs behind reverse proxy
    if(process.env.TLS_TERMINATION_PROXY === 'true') {
        app.set('trust proxy', 1)
    }

    await setup_defaults()
    app = await setup_auth_strategy(app, oidc_client);

    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    app.use(apiRouter)

    if(process.env.LOCAL_DEV_SSL === "true") {

        https.createServer({
            key: fs.readFileSync("example.key"),
            cert: fs.readFileSync("example.crt")
        },app).listen(port, "0.0.0.0", () => {
            console.log("Server running on " + process.env.SELF_HOSTNAME)
        })
        return;
    }

    app.listen(port, "0.0.0.0", () => {
        console.log(`Server at http://localhost:${port}`);
    });

    
}

// entrypoint
initialize()