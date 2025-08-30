import { Env, IPReputation, RequestContext, ProtectionResult, RateLimitData, AttackLog } from './types';

export class ProtectionService {
  // IP reputation management
  static async getIPReputation(ip: string, env: Env): Promise<IPReputation> {
    const key = `reputation_${ip.replace(/[.:]/g, '_')}`;
    const data = await env.IP_REPUTATION.get(key, { type: 'json' });
    
    if (!data) {
      return {
        score: 0,
        lastSeen: new Date().toISOString(),
        attackCount: 0,
        isBlacklisted: false,
        challengesPassed: 0,
        challengesFailed: 0
      };
    }
    
    return data as IPReputation;
  }

  static async updateReputation(ip: string, scoreChange: number, env: Env): Promise<void> {
    const reputation = await this.getIPReputation(ip, env);
    reputation.score = Math.max(0, Math.min(100, reputation.score + scoreChange));
    reputation.lastSeen = new Date().toISOString();
    
    if (reputation.score <= 0) {
      reputation.isBlacklisted = true;
    }
    
    const key = `reputation_${ip.replace(/[.:]/g, '_')}`;
    await env.IP_REPUTATION.put(key, JSON.stringify(reputation), {
      expirationTtl: 86400 // 24 hours
    });
  }

  // Rate limiting
  static async checkRateLimit(context: RequestContext, env: Env): Promise<RateLimitData> {
    const minuteKey = `rate:${context.ip}:minute:${Math.floor(Date.now() / 60000)}`;
    const hourKey = `rate:${context.ip}:hour:${Math.floor(Date.now() / 3600000)}`;
    
    const [minuteData, hourData] = await Promise.all([
      env.RATE_LIMITS.get(minuteKey, { type: 'json' }) as Promise<RateLimitData | null>,
      env.RATE_LIMITS.get(hourKey, { type: 'json' }) as Promise<RateLimitData | null>
    ]);

    const maxPerMinute = parseInt(env.MAX_REQUESTS_PER_MINUTE);
    const maxPerHour = parseInt(env.MAX_REQUESTS_PER_HOUR);

    const currentMinute = minuteData?.requests || 0;
    const currentHour = hourData?.requests || 0;

    const blocked = currentMinute >= maxPerMinute || currentHour >= maxPerHour;

    return {
      requests: currentMinute,
      windowStart: Math.floor(Date.now() / 60000) * 60000,
      blocked
    };
  }

  static async updateRateLimit(context: RequestContext, env: Env): Promise<void> {
    const minuteKey = `rate:${context.ip}:minute:${Math.floor(Date.now() / 60000)}`;
    const hourKey = `rate:${context.ip}:hour:${Math.floor(Date.now() / 3600000)}`;
    
    const [minuteData, hourData] = await Promise.all([
      env.RATE_LIMITS.get(minuteKey, { type: 'json' }) as Promise<RateLimitData | null>,
      env.RATE_LIMITS.get(hourKey, { type: 'json' }) as Promise<RateLimitData | null>
    ]);

    const newMinuteData: RateLimitData = {
      requests: (minuteData?.requests || 0) + 1,
      windowStart: Math.floor(Date.now() / 60000) * 60000,
      blocked: false
    };

    const newHourData: RateLimitData = {
      requests: (hourData?.requests || 0) + 1,
      windowStart: Math.floor(Date.now() / 3600000) * 3600000,
      blocked: false
    };

    await Promise.all([
      env.RATE_LIMITS.put(minuteKey, JSON.stringify(newMinuteData), { expirationTtl: 120 }),
      env.RATE_LIMITS.put(hourKey, JSON.stringify(newHourData), { expirationTtl: 7200 })
    ]);
  }

  // Bot detection
  static detectBot(context: RequestContext): boolean {
    const userAgent = context.userAgent.toLowerCase();
    const botPatterns = [
      'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 'java',
      'headless', 'phantom', 'selenium', 'webdriver', 'automation'
    ];
    
    return botPatterns.some(pattern => userAgent.includes(pattern));
  }

  // Suspicious pattern detection
  static detectSuspiciousPatterns(context: RequestContext): string[] {
    const patterns: string[] = [];
    
    // Check for missing headers
    if (!context.headers['accept'] || !context.headers['accept-language']) {
      patterns.push('missing_headers');
    }
    
    // Check for suspicious user agents
    if (context.userAgent.length < 10 || context.userAgent.includes('curl')) {
      patterns.push('suspicious_user_agent');
    }
    
    // Check for suspicious paths
    const suspiciousPaths = ['/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config'];
    if (suspiciousPaths.some(path => context.path.includes(path))) {
      patterns.push('suspicious_path');
    }
    
    return patterns;
  }

  // Check protection rules
  static async checkProtection(request: Request, context: RequestContext, env: Env): Promise<ProtectionResult> {
    // Check IP reputation
    const reputation = await this.getIPReputation(context.ip, env);
    if (reputation.isBlacklisted) {
      return { allowed: false, reason: 'IP is blacklisted', reputation };
    }

    // Check rate limiting
    const rateLimit = await this.checkRateLimit(context, env);
    if (rateLimit.blocked) {
      return { 
        allowed: false, 
        reason: 'Rate limit exceeded', 
        rateLimit,
        challenge: reputation.score < parseInt(env.REPUTATION_THRESHOLD)
      };
    }

    // Check for bots
    if (env.BOT_DETECTION_ENABLED === 'true') {
      const isBot = this.detectBot(context);
      if (isBot) {
        await this.updateReputation(context.ip, -10, env);
        return { 
          allowed: false, 
          reason: 'Bot detected',
          challenge: true
        };
      }
    }

    // Check for suspicious patterns
    const suspiciousPatterns = this.detectSuspiciousPatterns(context);
    if (suspiciousPatterns.length > 0) {
      await this.updateReputation(context.ip, -5, env);
      return {
        allowed: false,
        reason: `Suspicious patterns detected: ${suspiciousPatterns.join(', ')}`,
        challenge: true
      };
    }

    return { allowed: true, reputation, rateLimit };
  }
}
