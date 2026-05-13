import { Router, type IRouter } from "express";
import healthRouter from "./health";
import phishingRouter from "./phishing";
import dashboardRouter from "./dashboard";
import checkUrlRouter from "./checkUrl";

const router: IRouter = Router();

router.use(healthRouter);
router.use(phishingRouter);
router.use(dashboardRouter);
router.use(checkUrlRouter);

export default router;
