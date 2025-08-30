import { Env, AttackLog, IPReputation } from './types';

export class AnalyticsService {
  // Get attack data from KV storage - Improved version
  static async getRealAttackData(env: Env): Promise<any> {
    try {
      // Add debug logging for production troubleshooting
      console.log('AnalyticsService: Starting getRealAttackData');
      
      // Get attack logs from the last 24 hours
      const now = Date.now();
      const oneDayAgo = now - (24 * 60 * 60 * 1000);
      
      // Initialize data structures
      const hourlyData: Record<number, { attacks: number; blocked: number }> = {};
      const uniqueIPs = new Set<string>();
      const attackTypes: Record<string, number> = {};
      const recentAttacks: AttackLog[] = [];
      
      // Initialize hourly data
      for (let i = 0; i < 24; i++) {
        hourlyData[i] = { attacks: 0, blocked: 0 };
      }
      
      let totalRequests = 0;
      let blockedRequests = 0;
      
      // Use a more efficient approach - list keys with prefix and process in batches
      let cursor: string | undefined;
      const processedKeys = new Set<string>();
      
      console.log('AnalyticsService: Listing attack logs from KV');
      
      do {
        const listResult = await env.ATTACK_LOGS.list({
          prefix: 'attack_',
          limit: 1000,
          cursor
        });
        
        console.log(`AnalyticsService: Found ${listResult.keys.length} keys in batch`);
        
        // Process each log entry
        for (const key of listResult.keys) {
          if (processedKeys.has(key.name)) continue;
          processedKeys.add(key.name);
          
          try {
            const attackData = await env.ATTACK_LOGS.get(key.name, { type: 'json' }) as AttackLog;
            
            if (attackData) {
              const attackTime = new Date(attackData.timestamp);
              const attackTimestamp = attackTime.getTime();
              
              // Only include recent attacks
              if (attackTimestamp >= oneDayAgo) {
                const hour = attackTime.getHours();
                
                // Update hourly data
                hourlyData[hour].attacks++;
                hourlyData[hour].blocked++;
                
                // Update counters
                totalRequests++;
                blockedRequests++;
                
                // Track unique IPs
                uniqueIPs.add(attackData.ip);
                
                // Track attack types
                attackTypes[attackData.attackType] = (attackTypes[attackData.attackType] || 0) + 1;
                
                // Add to recent attacks
                recentAttacks.push(attackData);
              }
            }
          } catch (error) {
            console.error(`Error processing attack log ${key.name}:`, error);
          }
        }
        
        cursor = listResult.list_complete ? undefined : listResult.cursor;
      } while (cursor && processedKeys.size < 5000); // Limit to prevent infinite loops
      
      console.log(`AnalyticsService: Processed ${processedKeys.size} total keys`);
      console.log(`AnalyticsService: Found ${recentAttacks.length} recent attacks`);
      
      // Sort recent attacks by timestamp
      recentAttacks.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      const latestAttacks = recentAttacks.slice(0, 10);
      
      const result = {
        totalRequests,
        blockedRequests,
        uniqueIPs: uniqueIPs.size,
        attackTypes,
        recentAttacks: latestAttacks,
        hourlyData
      };
      
      console.log('AnalyticsService: Returning analytics data:', {
        totalRequests: result.totalRequests,
        blockedRequests: result.blockedRequests,
        uniqueIPs: result.uniqueIPs,
        recentAttacksCount: result.recentAttacks.length
      });
      
      return result;
    } catch (error) {
      console.error('Error getting real attack data:', error);
      return {
        totalRequests: 0,
        blockedRequests: 0,
        uniqueIPs: 0,
        attackTypes: {},
        recentAttacks: [],
        hourlyData: {}
      };
    }
  }

  // Get reputation statistics - Improved version
  static async getReputationStats(env: Env): Promise<any> {
    try {
      // Get IP reputation data from KV storage
      const topThreats: Array<{ ip: string; attacks: number; score: number }> = [];
      
      // List reputation entries
      let cursor: string | undefined;
      const processedKeys = new Set<string>();
      
      do {
        const listResult = await env.IP_REPUTATION.list({
          prefix: 'reputation_',
          limit: 1000,
          cursor
        });
        
        // Process each reputation record
        for (const key of listResult.keys) {
          if (processedKeys.has(key.name)) continue;
          processedKeys.add(key.name);
          
          try {
            const reputationData = await env.IP_REPUTATION.get(key.name, { type: 'json' }) as IPReputation;
            
            if (reputationData && reputationData.attackCount > 0) {
              const ip = key.name.replace('reputation_', '').replace(/_/g, '.');
              topThreats.push({
                ip,
                attacks: reputationData.attackCount,
                score: reputationData.score
              });
            }
          } catch (error) {
            console.error(`Error processing reputation ${key.name}:`, error);
          }
        }
        
        cursor = listResult.list_complete ? undefined : listResult.cursor;
      } while (cursor && processedKeys.size < 1000); // Limit to prevent infinite loops
      
      // Sort by attack count and take top 10
      topThreats.sort((a, b) => b.attacks - a.attacks);
      
      return { topThreats: topThreats.slice(0, 10) };
    } catch (error) {
      console.error('Error getting reputation stats:', error);
      return { topThreats: [] };
    }
  }

  // Get current metrics - Improved version
  static async getRealMetrics(env: Env): Promise<any> {
    try {
      // Get metrics from KV storage
      const now = Date.now();
      const oneMinuteAgo = now - (60 * 1000);
      
      let requestsPerMinute = 0;
      let blockedRequests = 0;
      let activeThreats = 0;
      
      // Count recent requests using a more efficient approach
      let cursor: string | undefined;
      const processedKeys = new Set<string>();
      
      do {
        const listResult = await env.ATTACK_LOGS.list({
          prefix: 'attack_',
          limit: 1000,
          cursor
        });
        
        for (const key of listResult.keys) {
          if (processedKeys.has(key.name)) continue;
          processedKeys.add(key.name);
          
          try {
            const attackData = await env.ATTACK_LOGS.get(key.name, { type: 'json' }) as AttackLog;
            
            if (attackData) {
              const attackTime = new Date(attackData.timestamp).getTime();
              
              // Count requests in last minute
              if (attackTime >= oneMinuteAgo) {
                requestsPerMinute++;
              }
              
              // Count all blocked requests
              blockedRequests++;
            }
          } catch (error) {
            console.error(`Error processing metric ${key.name}:`, error);
          }
        }
        
        cursor = listResult.list_complete ? undefined : listResult.cursor;
      } while (cursor && processedKeys.size < 2000); // Limit for metrics
      
      // Count active threats
      cursor = undefined;
      processedKeys.clear();
      
      let reputationListResult;
      do {
        reputationListResult = await env.IP_REPUTATION.list({
          prefix: 'reputation_',
          limit: 1000,
          cursor
        });
        
        for (const key of reputationListResult.keys) {
          if (processedKeys.has(key.name)) continue;
          processedKeys.add(key.name);
          
          try {
            const reputationData = await env.IP_REPUTATION.get(key.name, { type: 'json' }) as IPReputation;
            
            if (reputationData && reputationData.score < 0) {
              activeThreats++;
            }
          } catch (error) {
            console.error(`Error processing reputation for metrics ${key.name}:`, error);
          }
        }
        
        cursor = reputationListResult.list_complete ? undefined : reputationListResult.cursor;
      } while (cursor && processedKeys.size < 1000);
      
      return {
        requestsPerMinute,
        blockedRequests,
        activeThreats,
        protectionLevel: activeThreats > 10 ? 'high' : activeThreats > 5 ? 'medium' : 'low'
      };
    } catch (error) {
      console.error('Error getting real metrics:', error);
      return {
        requestsPerMinute: 0,
        blockedRequests: 0,
        activeThreats: 0,
        protectionLevel: 'high'
      };
    }
  }
}
