import * as trpcExpress from "@trpc/server/adapters/express";
import express from "express";
import cors from "cors";
import { cloudfrontRouter } from "./router/cloudfrontRouter";
import { router } from "./trpc";

const appRouter = router({
  cloudfront: cloudfrontRouter,
});

export type AppRouter = typeof appRouter;

const app = express();
app.use(cors());

app.use(
  "/",
  trpcExpress.createExpressMiddleware({
    router: appRouter,
  })
);

const port = process.env.PORT || 2022;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
