import { initTRPC } from "@trpc/server";\n\nconst t = initTRPC.create();\n\nexport const router = t.router;\nexport const publicProcedure = t.procedure;\n
