import { publicProcedure, router } from "../trpc";
import { CloudFrontCheckResult } from "../types/cloudfront";
import { z } from "zod";
import { 
  CloudFrontClient, 
  ListDistributionsCommand, 
  GetDistributionCommand,
  Distribution
} from "@aws-sdk/client-cloudfront";

type ExtendedDistribution = Distribution & {
  Id?: string;
  DistributionConfig?: {
    ViewerCertificate?: {
      MinimumProtocolVersion?: string;
    };
    Origins?: {
      Items?: Array<{
        CustomOriginConfig?: {
          OriginProtocolPolicy?: string;
        };
      }>;
    };
    DefaultRootObject?: string;
    Logging?: {
      Enabled?: boolean;
    };
    DefaultCacheBehavior?: {
      ViewerProtocolPolicy?: string;
      MinTTL?: number;
    };
    WebACLId?: string;
    Restrictions?: {
      GeoRestriction?: {
        Quantity?: number;
      };
    };
  };
};

const cloudfront = new CloudFrontClient({ region: process.env.AWS_DEFAULT_REGION || 'us-east-1' });

// Helper function to get full distribution details
const getDistributionDetails = async (distributionId: string): Promise<ExtendedDistribution> => {
  const command = new GetDistributionCommand({ Id: distributionId });
  const response = await cloudfront.send(command);
  if (!response.Distribution) {
    throw new Error(`Failed to get details for distribution ${distributionId}`);
  }
  return response.Distribution;
};

// Helper function to perform checks on a distribution
const performDistributionChecks = (distribution: ExtendedDistribution): CloudFrontCheckResult[] => {
  const checks: CloudFrontCheckResult[] = [];
  
  // Check 1: SSL Certificate check
  checks.push({
    distributionId: distribution.Id || 'unknown',
    checkNumber: 1,
    checkName: 'SSL Certificate',
    status: distribution.DistributionConfig?.ViewerCertificate?.MinimumProtocolVersion === 'TLSv1.2_2021' ? 'OK' : 'WARNING',
    details: `SSL Protocol Version: ${distribution.DistributionConfig?.ViewerCertificate?.MinimumProtocolVersion || 'N/A'}`
  });

  // Check 2: Origin Protocol Policy
  checks.push({
    distributionId: distribution.Id || 'unknown',
    checkNumber: 2,
    checkName: 'Origin Protocol Policy',
    status: distribution.DistributionConfig?.Origins?.Items?.[0]?.CustomOriginConfig?.OriginProtocolPolicy === 'https-only' ? 'OK' : 'WARNING',
    details: `Protocol Policy: ${distribution.DistributionConfig?.Origins?.Items?.[0]?.CustomOriginConfig?.OriginProtocolPolicy || 'N/A'}`
  });

  // Check 3: Default Root Object
  checks.push({
    distributionId: distribution.Id || 'unknown',
    checkNumber: 3,
    checkName: 'Default Root Object',
    status: distribution.DistributionConfig?.DefaultRootObject ? 'OK' : 'WARNING',
    details: `Root Object: ${distribution.DistributionConfig?.DefaultRootObject || 'Not Set'}`
  });

  // Check 4: Logging Enabled
  checks.push({
    distributionId: distribution.Id || 'unknown',
    checkNumber: 4,
    checkName: 'Logging Status',
    status: distribution.DistributionConfig?.Logging?.Enabled ? 'OK' : 'WARNING',
    details: distribution.DistributionConfig?.Logging?.Enabled ? 'Logging Enabled' : 'Logging Disabled'
  });

  // Check 5: HTTPS Redirect
  checks.push({
    distributionId: distribution.Id || 'unknown',
    checkNumber: 5,
    checkName: 'HTTPS Redirect',
    status: distribution.DistributionConfig?.DefaultCacheBehavior?.ViewerProtocolPolicy === 'redirect-to-https' ? 'OK' : 'WARNING',
    details: `Viewer Protocol Policy: ${distribution.DistributionConfig?.DefaultCacheBehavior?.ViewerProtocolPolicy || 'N/A'}`
  });

  // Check 6: WAF Integration
  checks.push({
    distributionId: distribution.Id || 'unknown',
    checkNumber: 6,
    checkName: 'WAF Integration',
    status: distribution.DistributionConfig?.WebACLId ? 'OK' : 'WARNING',
    details: distribution.DistributionConfig?.WebACLId ? 'WAF Enabled' : 'No WAF Association'
  });

  // Check 7: Geographic Restrictions
  checks.push({
    distributionId: distribution.Id || 'unknown',
    checkNumber: 7,
    checkName: 'Geographic Restrictions',
    status: (distribution.DistributionConfig?.Restrictions?.GeoRestriction?.Quantity ?? 0) > 0 ? 'OK' : 'INFO',
    details: `Geo Restrictions: ${distribution.DistributionConfig?.Restrictions?.GeoRestriction?.Quantity || 0} countries`
  });

  // Check 8: Cache TTL Settings
  checks.push({
    distributionId: distribution.Id || 'unknown',
    checkNumber: 8,
    checkName: 'Cache TTL Settings',
    status: distribution.DistributionConfig?.DefaultCacheBehavior?.MinTTL !== undefined ? 'OK' : 'WARNING',
    details: `Min TTL: ${distribution.DistributionConfig?.DefaultCacheBehavior?.MinTTL || 'Not Set'}`
  });

  return checks;
};

export const cloudfrontRouter = router({
  comprehensiveChecks: publicProcedure
    .output(z.array(CloudFrontCheckResult))
    .query(async () => {
      console.log('[DEBUG] Fetching CloudFront distributions...');
      
      const command = new ListDistributionsCommand({});
      const response = await cloudfront.send(command);
      const items = response.DistributionList?.Items || [];
      
      console.log(`[DEBUG] Processing ${items.length} distributions`);
      console.log(`[DEBUG] Expected checks = ${items.length * 8}`);

      const results: CloudFrontCheckResult[] = [];
      for (const summary of items) {
        if (!summary.Id) {
          console.warn('[DEBUG] Skipping distribution without ID');
          continue;
        }
        
        console.log(`[DEBUG] Fetching details for distribution ${summary.Id}`);
        try {
          const distribution = await getDistributionDetails(summary.Id);
          const distributionChecks = performDistributionChecks(distribution);
          results.push(...distributionChecks);
        } catch (error) {
          console.error(`[DEBUG] Error processing distribution ${summary.Id}:`, error);
          // Add error check result
          results.push({
            distributionId: summary.Id,
            checkNumber: 0,
            checkName: 'Distribution Access',
            status: 'WARNING',
            details: `Failed to get distribution details: ${error instanceof Error ? error.message : 'Unknown error'}`
          });
        }
      }

      console.log(`[DEBUG] Total checks performed: ${results.length}`);
      return results;
    }),
});
