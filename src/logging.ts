import { Env, RequestContext, AttackLog } from './types';

export class LoggingService {
  // Attack logging
  static async logAttack(context: RequestContext, attackType: string, env: Env): Promise<void> {
    const log: AttackLog = {
      timestamp: context.timestamp,
      ip: context.ip,
      country: context.country,
      userAgent: context.userAgent,
      attackType,
      severity: this.calculateSeverity(attackType),
      details: {
        path: context.path,
        method: context.method,
        requestId: context.requestId
      }
    };

    // Use a simpler key format
    const timestamp = new Date(context.timestamp).getTime();
    const key = `attack_${timestamp}_${context.ip.replace(/[.:]/g, '_')}`;
    
    try {
      await env.ATTACK_LOGS.put(key, JSON.stringify(log), { 
        expirationTtl: 604800 // 7 days
      });
      
      // Also store a recent attacks list for quick access
      const recentKey = `recent_${context.ip.replace(/[.:]/g, '_')}`;
      const recentData = await env.ATTACK_LOGS.get(recentKey, { type: 'json' }) as any;
      const recentAttacks = recentData?.attacks || [];
      
      // Add new attack to recent list
      recentAttacks.unshift({
        timestamp: context.timestamp,
        attackType,
        severity: log.severity
      });
      
      // Keep only last 10 attacks per IP
      if (recentAttacks.length > 10) {
        recentAttacks.splice(10);
      }
      
      await env.ATTACK_LOGS.put(recentKey, JSON.stringify({ attacks: recentAttacks }), {
        expirationTtl: 86400 // 24 hours
      });
      
    } catch (error) {
      console.error('Failed to log attack:', error);
    }
  }

  static calculateSeverity(attackType: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (attackType) {
      case 'Rate limit exceeded':
        return 'medium';
      case 'IP is blacklisted':
        return 'high';
      case 'Bot detected':
        return 'medium';
      default:
        return 'low';
    }
  }
}
