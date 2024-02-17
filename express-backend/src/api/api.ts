import { NextFunction, Request, Response, Router } from "express";
import { userRoutes } from "./user/routes";
import { publicRoutes } from "./public/routes";
import { adminRoutes } from "./admin/routes";

export const apiRouter = Router()

apiRouter
    .use(publicRoutes)
    .use(userRoutes)
    .use(adminRoutes)  

apiRouter
    .use(notFound)
    .use(errorFunction)


async function notFound(req: Request, res:Response, next: NextFunction) {
    return next(404)
}

async function errorFunction(errorcode: number, req: Request, res:Response, next: NextFunction) {
    res.status(errorcode).send();
    console.warn("Invalid request at: " 
        + req.url + " raised at: " + Date.now())
    return;
}