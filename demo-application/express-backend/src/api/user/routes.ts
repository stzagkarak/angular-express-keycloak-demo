import { Router } from "express";
import { isAuthenticated } from "../../auth/middleware";

export const userRoutes = Router();

/** DO NOT SEND UNFILTERED USER INFORMATION TO FRONTEND APPLICATIONS */
/** THIS IS AN EXAMPLE TO SHOWCASE AUTHNETICATED ROUTES */
userRoutes.post("/user/info", 
    isAuthenticated,
    (req, res, next) => {
        return res.status(200).send(req.user)
    }
)

