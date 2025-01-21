import { z } from "zod";

export const CloudFrontCheckResult = z.object({
  distributionId: z.string(),
  checkNumber: z.number(),
  checkName: z.string(),
  status: z.enum(['OK', 'WARNING', 'INFO']),
  details: z.string()
});

export type CloudFrontCheckResult = z.infer<typeof CloudFrontCheckResult>;
