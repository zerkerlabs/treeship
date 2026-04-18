// AWS Lambda function that verifies a Treeship receipt by URL.
//
// Deploy with SAM, serverless framework, or the AWS console -- bundle the
// dist/handler.mjs emitted by `npm run build`.

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { verifyReceipt } from '@treeship/verify';

export const handler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyResultV2> => {
  if (event.requestContext?.http?.method && event.requestContext.http.method !== 'POST') {
    return { statusCode: 405, body: 'POST only' };
  }
  let body: { url?: string };
  try {
    body = JSON.parse(event.body ?? '{}') as { url?: string };
  } catch {
    return { statusCode: 400, body: 'invalid JSON body' };
  }
  if (!body.url) {
    return { statusCode: 400, body: 'missing url' };
  }

  try {
    const result = await verifyReceipt(body.url);
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(result),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      statusCode: 500,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ outcome: 'error', message }),
    };
  }
};
