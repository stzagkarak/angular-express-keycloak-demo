import { Request, Response , NextFunction } from 'express';

export async function isAuthenticated(req:Request, res:Response, next:NextFunction) {
    if(req.isAuthenticated()) return next();
    return next(401);
}

export  async function isAdmin(req:Request, res:Response, next:NextFunction) {
    try {
        // @ts-ignore
        if(req.user?.["user-role"] === 'admin') return next();
    }
    catch(err) {
        return next(401);
    }
    return next(401);
}