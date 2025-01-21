import { createTRPCProxyClient, httpBatchLink } from '@trpc/client';
import type { AppRouter } from './index';

const client = createTRPCProxyClient<AppRouter>({
  links: [
    httpBatchLink({
      url: 'http://localhost:2022',
    }),
  ],
});

async function testCloudFrontChecks() {
  try {
    console.log('Testing CloudFront comprehensive checks...');
    const results = await client.cloudfront.comprehensiveChecks.query();
    console.log(`Total results: ${results.length}`);
    console.log(`Number of distributions: ${results.length / 8}`);
    console.log('\nSample check result:');
    if (results.length > 0) {
      console.log(JSON.stringify(results[0], null, 2));
    }
  } catch (error) {
    console.error('Error testing endpoint:', error);
  }
}

testCloudFrontChecks();
