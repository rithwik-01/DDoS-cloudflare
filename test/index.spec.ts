import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src';

describe('ShieldGuard worker', () => {
	describe('dashboard endpoint', () => {
		it('responds with dashboard HTML (unit style)', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/');
			// Create execution context for worker
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			// Wait for promises to settle
			await waitOnExecutionContext(ctx);
			expect(response.headers.get('content-type')).toContain('text/html');
		});

		it('responds with dashboard HTML (integration style)', async () => {
			const request = new Request('http://example.com/');
			const response = await SELF.fetch(request);
			expect(response.headers.get('content-type')).toContain('text/html');
		});
	});

	describe('status API endpoint', () => {
		it('responds with JSON status (unit style)', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/api/status');
			// Create execution context for worker
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			// Wait for promises to settle
			await waitOnExecutionContext(ctx);
			expect(response.headers.get('content-type')).toContain('application/json');
		});

		it('responds with JSON status (integration style)', async () => {
			const request = new Request('http://example.com/api/status');
			const response = await SELF.fetch(request);
			expect(response.headers.get('content-type')).toContain('application/json');
		});
	});
});
