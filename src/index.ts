/**
 * ShieldGuard - Basic DDoS Protection Worker
 * 
 * A simple DDoS protection implementation using Cloudflare Workers with:
 * - Rate limiting per IP address
 * - Basic IP reputation tracking
 * - Simple challenge pages for suspicious traffic
 * - Attack logging and monitoring
 * - Bot detection using user agent patterns
 */

import { Env, RequestContext, ProtectionResult } from './types';
import { ProtectionService } from './protection';
import { AnalyticsService } from './analytics';
import { LoggingService } from './logging';
import { UIService } from './ui';
import { APIService } from './api';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const requestId = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    
    // Parse request information
    const context: RequestContext = {
      ip: request.headers.get('cf-connecting-ip') || 'unknown',
      country: request.headers.get('cf-ipcountry') || 'unknown',
      city: request.headers.get('cf-ipcity') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
      timestamp,
      requestId,
      path: url.pathname,
      method: request.method,
      headers: Object.fromEntries(request.headers.entries())
    };

    try {
      // Handle different routes
      switch (url.pathname) {
        case '/':
          return UIService.handleDashboard(request, context, env);
        
        case '/api/status':
          return await APIService.handleStatusAPI(request, context, env);
        
        case '/api/analytics':
          return await APIService.handleAnalyticsAPI(request, context, env);
        
        case '/api/fast-analytics':
          return await APIService.handleFastAnalyticsAPI(request, context, env);
        
        case '/api/reputation':
          return await APIService.handleReputationAPI(request, context, env);
        
        case '/api/challenge':
          return APIService.handleChallengeAPI(request, context, env);
        
        case '/api/test-attack':
          return await APIService.handleTestAttack(request, context, env);
        
        case '/api/whitelist':
          return await APIService.handleWhitelistAPI(request, context, env);
        
        case '/api/blacklist':
          return await APIService.handleBlacklistAPI(request, context, env);
        
        case '/api/generate-sample-data':
          return await APIService.handleGenerateSampleData(request, context, env);
        
        case '/api/kv-test':
          return await APIService.handleKVTest(request, context, env);
        
        case '/api/analytics-diagnostic':
          return await APIService.handleAnalyticsDiagnostic(request, context, env);
        
        case '/api/cache-clear':
          return await APIService.handleCacheClear(request, context, env);
        
        default:
          // Apply protection to all other routes
          return await this.applyProtection(request, context, env, ctx);
      }
    } catch (error) {
      console.error(`Error in ShieldGuard request ${requestId}:`, error);
      return this.handleError(error, context);
    }
  },

  // Main protection logic
  async applyProtection(request: Request, context: RequestContext, env: Env, ctx: ExecutionContext): Promise<Response> {
    const protection = await ProtectionService.checkProtection(request, context, env);
    
    // Always log suspicious activities, not just blocked requests
    if (!protection.allowed || (protection.reputation && protection.reputation.score < parseInt(env.REPUTATION_THRESHOLD))) {
      await LoggingService.logAttack(context, protection.reason || 'Suspicious activity detected', env);
    }
    
    if (!protection.allowed) {
      if (protection.challenge) {
        return UIService.generateChallengePage(context);
      }
      
      return new Response(JSON.stringify({
        error: 'Access Denied',
        reason: protection.reason,
        requestId: context.requestId,
        timestamp: context.timestamp
      }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'X-ShieldGuard-Status': 'blocked',
          'X-Request-ID': context.requestId
        }
      });
    }

    // Update rate limiting counters
    await ProtectionService.updateRateLimit(context, env);
    
    // Update IP reputation score
    await ProtectionService.updateReputation(context.ip, 1, env);
    
    // Process the request normally
    return this.handleProtectedRoute(request, context, env);
  },

  // Protected route handler
  handleProtectedRoute(request: Request, context: RequestContext, env: Env): Response {
    // Handle the actual application logic
    return new Response(JSON.stringify({
      message: 'Request processed successfully',
      protected: true,
      requestId: context.requestId,
      timestamp: context.timestamp,
      ip: context.ip,
      country: context.country
    }), {
      headers: {
        'Content-Type': 'application/json',
        'X-ShieldGuard-Protected': 'true',
        'X-Request-ID': context.requestId
      }
    });
  },

  // Error handler
  handleError(error: any, context: RequestContext): Response {
    console.error(`Error in ShieldGuard request ${context.requestId}:`, error);
    
    const errorResponse = {
      error: 'Internal server error',
      message: 'Something went wrong in ShieldGuard',
      requestId: context.requestId,
      timestamp: context.timestamp,
      location: context.country
    };

    return new Response(JSON.stringify(errorResponse, null, 2), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': context.requestId
      }
    });
  }
} as ExportedHandler<Env> & {
  applyProtection: (request: Request, context: RequestContext, env: Env, ctx: ExecutionContext) => Promise<Response>;
  handleProtectedRoute: (request: Request, context: RequestContext, env: Env) => Response;
  handleError: (error: any, context: RequestContext) => Response;
};
