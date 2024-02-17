import { Router } from "express";
import { isAdmin, isAuthenticated } from "../../auth/middleware";

export const adminRoutes = Router();

adminRoutes.post("/admin/task", 
    isAuthenticated,
    isAdmin,
    (req, res, next) => {
        return res.status(200).send({status: "done"})
    }
)