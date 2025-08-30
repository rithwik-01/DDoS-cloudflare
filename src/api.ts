import { Env, RequestContext, AttackLog, IPReputation, RateLimitData } from './types';
import { ProtectionService } from './protection';
import { AnalyticsService } from './analytics';
import { LoggingService } from './logging';

export class APIService {
  // Status API
  static async handleStatusAPI(request: Request, context: RequestContext, env: Env): Promise<Response> {
    // Get current metrics
    const realMetrics = await AnalyticsService.getRealMetrics(env);
    
    const status = {
      system: {
        name: env.APP_NAME,
        version: env.APP_VERSION,
        environment: env.ENVIRONMENT,
        uptime: '99.9%',
        status: 'active'
      },
      metrics: realMetrics,
      protection: {
        rateLimiting: {
          enabled: true,
          maxPerMinute: parseInt(env.MAX_REQUESTS_PER_MINUTE),
          maxPerHour: parseInt(env.MAX_REQUESTS_PER_HOUR)
        },
        reputation: {
          enabled: true,
          threshold: parseInt(env.REPUTATION_THRESHOLD)
        },
        botDetection: {
          enabled: env.BOT_DETECTION_ENABLED === 'true'
        },
        challenges: {
          enabled: env.CHALLENGE_ENABLED === 'true'
        }
      },
      request: {
        id: context.requestId,
        timestamp: context.timestamp,
        ip: context.ip,
        country: context.country
      }
    };

    return new Response(JSON.stringify(status, null, 2), {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': context.requestId
      }
    });
  }

  // Analytics API
  static async handleAnalyticsAPI(request: Request, context: RequestContext, env: Env): Promise<Response> {
    try {
      console.log('APIService: Starting analytics API request');
      
      // Get attack data from KV storage
      const attackData = await AnalyticsService.getRealAttackData(env);
      const reputationData = await AnalyticsService.getReputationStats(env);
      
      const analytics = {
        overview: {
          totalRequests: attackData.totalRequests,
          blockedRequests: attackData.blockedRequests,
          uniqueIPs: attackData.uniqueIPs,
          attackTypes: attackData.attackTypes
        },
        recentAttacks: attackData.recentAttacks,
        topThreats: reputationData.topThreats,
        hourlyData: attackData.hourlyData
      };

      console.log('APIService: Analytics data prepared successfully');

      return new Response(JSON.stringify(analytics, null, 2), {
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    } catch (error) {
      console.error('APIService: Analytics API error:', error);
      
      return new Response(JSON.stringify({
        error: 'Analytics API failed',
        message: error instanceof Error ? error.message : 'Unknown error',
        requestId: context.requestId,
        timestamp: context.timestamp
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    }
  }

  // Reputation API
  static async handleReputationAPI(request: Request, context: RequestContext, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const ip = url.searchParams.get('ip') || context.ip;
    
    const reputation = await ProtectionService.getIPReputation(ip, env);
    
    return new Response(JSON.stringify({
      ip,
      reputation,
      requestId: context.requestId,
      timestamp: context.timestamp
    }, null, 2), {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': context.requestId
      }
    });
  }

  // Challenge API
  static handleChallengeAPI(request: Request, context: RequestContext, env: Env): Response {
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({
        error: 'Method not allowed',
        allowedMethods: ['POST']
      }), {
        status: 405,
        headers: {
          'Content-Type': 'application/json',
          'Allow': 'POST'
        }
      });
    }

    // Validate the challenge response
    return new Response(JSON.stringify({
      success: true,
      message: 'Challenge completed successfully',
      requestId: context.requestId,
      timestamp: context.timestamp
    }), {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': context.requestId
      }
    });
  }

  // Test attack API
  static async handleTestAttack(request: Request, context: RequestContext, env: Env): Promise<Response> {
    // Simulate multiple types of attacks for testing
    const attackTypes = [
      'rate_limit_exceeded',
      'bot_detected',
      'suspicious_patterns',
      'blacklisted_ip',
      'test_attack'
    ];
    
    const randomAttackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
    
    // Log the attack
    await LoggingService.logAttack(context, randomAttackType, env);
    
    // Update reputation based on attack type
    let scoreChange = -5;
    if (randomAttackType === 'rate_limit_exceeded') scoreChange = -10;
    if (randomAttackType === 'bot_detected') scoreChange = -15;
    if (randomAttackType === 'blacklisted_ip') scoreChange = -50;
    
    await ProtectionService.updateReputation(context.ip, scoreChange, env);
    
    // Also simulate some rate limiting data
    const minuteKey = `rate:${context.ip}:minute:${Math.floor(Date.now() / 60000)}`;
    const currentData = await env.RATE_LIMITS.get(minuteKey, { type: 'json' }) as RateLimitData | null;
    const newData: RateLimitData = {
      requests: (currentData?.requests || 0) + 50, // Simulate high request rate
      windowStart: Math.floor(Date.now() / 60000) * 60000,
      blocked: true
    };
    await env.RATE_LIMITS.put(minuteKey, JSON.stringify(newData), { expirationTtl: 120 });
    
    return new Response(JSON.stringify({
      message: 'Test attack logged successfully',
      attackType: randomAttackType,
      ip: context.ip,
      reputation: await ProtectionService.getIPReputation(context.ip, env),
      rateLimit: newData,
      requestId: context.requestId,
      timestamp: context.timestamp
    }, null, 2), {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': context.requestId
      }
    });
  }

  // Whitelist API
  static async handleWhitelistAPI(request: Request, context: RequestContext, env: Env): Promise<Response> {
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({
        error: 'Method not allowed',
        allowedMethods: ['POST']
      }), {
        status: 405,
        headers: {
          'Content-Type': 'application/json',
          'Allow': 'POST'
        }
      });
    }

    try {
      const body = await request.json() as { ip: string };
      const { ip } = body;
      const reputation = await ProtectionService.getIPReputation(ip, env);
      reputation.score = 100;
      reputation.isBlacklisted = false;
      
      const key = `reputation_${ip.replace(/[.:]/g, '_')}`;
      await env.IP_REPUTATION.put(key, JSON.stringify(reputation), {
        expirationTtl: 86400
      });
      
      return new Response(JSON.stringify({
        success: true,
        message: `IP ${ip} has been whitelisted`,
        reputation,
        requestId: context.requestId,
        timestamp: context.timestamp
      }), {
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'Invalid request body',
        requestId: context.requestId
      }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    }
  }

  // Blacklist API
  static async handleBlacklistAPI(request: Request, context: RequestContext, env: Env): Promise<Response> {
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({
        error: 'Method not allowed',
        allowedMethods: ['POST']
      }), {
        status: 405,
        headers: {
          'Content-Type': 'application/json',
          'Allow': 'POST'
        }
      });
    }

    try {
      const body = await request.json() as { ip: string };
      const { ip } = body;
      const reputation = await ProtectionService.getIPReputation(ip, env);
      reputation.score = 0;
      reputation.isBlacklisted = true;
      
      const key = `reputation_${ip.replace(/[.:]/g, '_')}`;
      await env.IP_REPUTATION.put(key, JSON.stringify(reputation), {
        expirationTtl: 86400
      });
      
      return new Response(JSON.stringify({
        success: true,
        message: `IP ${ip} has been blacklisted`,
        reputation,
        requestId: context.requestId,
        timestamp: context.timestamp
      }), {
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'Invalid request body',
        requestId: context.requestId
      }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    }
  }

  // Generate sample data API
  static async handleGenerateSampleData(request: Request, context: RequestContext, env: Env): Promise<Response> {
    try {
      const sampleIPs = [
        '192.168.1.100',
        '10.0.0.50',
        '172.16.0.25',
        '203.0.113.10',
        '198.51.100.5'
      ];
      
      const attackTypes = [
        'rate_limit_exceeded',
        'bot_detected',
        'suspicious_patterns',
        'blacklisted_ip',
        'test_attack'
      ];
      
      const countries = ['US', 'CN', 'RU', 'DE', 'FR', 'JP', 'GB', 'CA', 'AU', 'BR'];
      
      // Generate sample attack logs for the last 24 hours
      const now = Date.now();
      const oneDayAgo = now - (24 * 60 * 60 * 1000);
      
      for (let i = 0; i < 50; i++) {
        const timestamp = new Date(oneDayAgo + Math.random() * (now - oneDayAgo));
        const ip = sampleIPs[Math.floor(Math.random() * sampleIPs.length)];
        const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
        const country = countries[Math.floor(Math.random() * countries.length)];
        
        const log: AttackLog = {
          timestamp: timestamp.toISOString(),
          ip,
          country,
          userAgent: 'Mozilla/5.0 (compatible; TestBot/1.0)',
          attackType,
          severity: LoggingService.calculateSeverity(attackType),
          details: {
            path: '/api/test',
            method: 'GET',
            requestId: crypto.randomUUID()
          }
        };
        
        const key = `attack_${timestamp.getTime()}_${ip.replace(/[.:]/g, '_')}`;
        await env.ATTACK_LOGS.put(key, JSON.stringify(log), { 
          expirationTtl: 604800 // 7 days
        });
        
        // Update reputation for this IP
        const reputation = await ProtectionService.getIPReputation(ip, env);
        reputation.attackCount++;
        reputation.score = Math.max(0, reputation.score - Math.floor(Math.random() * 10) - 1);
        reputation.lastSeen = timestamp.toISOString();
        
        if (reputation.score <= 0) {
          reputation.isBlacklisted = true;
        }
        
        const repKey = `reputation_${ip.replace(/[.:]/g, '_')}`;
        await env.IP_REPUTATION.put(repKey, JSON.stringify(reputation), {
          expirationTtl: 86400 // 24 hours
        });
      }
      
      return new Response(JSON.stringify({
        success: true,
        message: 'Generated 50 sample attack logs',
        requestId: context.requestId,
        timestamp: context.timestamp
      }), {
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    } catch (error) {
      console.error('Error generating sample data:', error);
      return new Response(JSON.stringify({
        error: 'Failed to generate sample data',
        requestId: context.requestId
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    }
  }

  // KV Test Endpoint
  static async handleKVTest(request: Request, context: RequestContext, env: Env): Promise<Response> {
    try {
      const key = `test:kv:${context.requestId}`;
      const value = `Test value for ${context.requestId}`;
      await env.ATTACK_LOGS.put(key, value, { expirationTtl: 60 }); // 1 minute TTL

      return new Response(JSON.stringify({
        success: true,
        message: `KV test successful. Key: ${key}, Value: ${value}`,
        requestId: context.requestId,
        timestamp: context.timestamp
      }), {
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    } catch (error) {
      console.error('KV Test failed:', error);
      return new Response(JSON.stringify({
        success: false,
        message: `KV test failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        requestId: context.requestId,
        timestamp: context.timestamp
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    }
  }

  // Analytics Diagnostic Endpoint
  static async handleAnalyticsDiagnostic(request: Request, context: RequestContext, env: Env): Promise<Response> {
    try {
      const diagnostics = {
        timestamp: context.timestamp,
        requestId: context.requestId,
        environment: env.ENVIRONMENT,
        kvNamespaces: {
          attackLogs: 'ATTACK_LOGS' in env ? 'Available' : 'Missing',
          ipReputation: 'IP_REPUTATION' in env ? 'Available' : 'Missing',
          rateLimits: 'RATE_LIMITS' in env ? 'Available' : 'Missing'
        },
        dataChecks: {} as any
      };

      // Check ATTACK_LOGS namespace
      try {
        const attackLogsList = await env.ATTACK_LOGS.list({ prefix: 'attack_', limit: 10 });
        diagnostics.dataChecks.attackLogs = {
          totalKeys: attackLogsList.keys.length,
          keys: attackLogsList.keys.map(k => k.name).slice(0, 5),
          hasMore: !attackLogsList.list_complete
        };
      } catch (error) {
        diagnostics.dataChecks.attackLogs = {
          error: error instanceof Error ? error.message : 'Unknown error'
        };
      }

      // Check IP_REPUTATION namespace
      try {
        const reputationList = await env.IP_REPUTATION.list({ prefix: 'reputation_', limit: 10 });
        diagnostics.dataChecks.ipReputation = {
          totalKeys: reputationList.keys.length,
          keys: reputationList.keys.map(k => k.name).slice(0, 5),
          hasMore: !reputationList.list_complete
        };
      } catch (error) {
        diagnostics.dataChecks.ipReputation = {
          error: error instanceof Error ? error.message : 'Unknown error'
        };
      }

      // Check RATE_LIMITS namespace
      try {
        const rateLimitsList = await env.RATE_LIMITS.list({ prefix: 'rate:', limit: 10 });
        diagnostics.dataChecks.rateLimits = {
          totalKeys: rateLimitsList.keys.length,
          keys: rateLimitsList.keys.map(k => k.name).slice(0, 5),
          hasMore: !rateLimitsList.list_complete
        };
      } catch (error) {
        diagnostics.dataChecks.rateLimits = {
          error: error instanceof Error ? error.message : 'Unknown error'
        };
      }

      // Test sample data generation
      try {
        const sampleKey = `diagnostic:${context.requestId}`;
        const sampleData = {
          timestamp: context.timestamp,
          ip: context.ip,
          test: true
        };
        await env.ATTACK_LOGS.put(sampleKey, JSON.stringify(sampleData), { expirationTtl: 300 });
        
        const retrievedData = await env.ATTACK_LOGS.get(sampleKey, { type: 'json' });
        diagnostics.dataChecks.writeReadTest = {
          success: true,
          written: sampleData,
          retrieved: retrievedData
        };
      } catch (error) {
        diagnostics.dataChecks.writeReadTest = {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        };
      }

      return new Response(JSON.stringify(diagnostics, null, 2), {
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    } catch (error) {
      console.error('Analytics diagnostic failed:', error);
      return new Response(JSON.stringify({
        error: 'Diagnostic failed',
        message: error instanceof Error ? error.message : 'Unknown error',
        requestId: context.requestId,
        timestamp: context.timestamp
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': context.requestId
        }
      });
    }
  }
}
