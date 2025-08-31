import { Env, AttackLog, IPReputation } from './types';

// Cache for analytics data
interface AnalyticsCache {
  data: any;
  timestamp: number;
  ttl: number;
}

const analyticsCache: AnalyticsCache = {
  data: null,
  timestamp: 0,
  ttl: 30000 // 30 seconds cache
};

const metricsCache: AnalyticsCache = {
  data: null,
  timestamp: 0,
  ttl: 10000 // 10 seconds cache
};

export class AnalyticsService {
  // Get attack data from KV storage - Optimized version with caching
  static async getRealAttackData(env: Env): Promise<any> {
    const now = Date.now();
    
    // Check cache first
    if (analyticsCache.data && (now - analyticsCache.timestamp) < analyticsCache.ttl) {
      console.log('AnalyticsService: Returning cached attack data');
      return analyticsCache.data;
    }
    
    try {
      console.log('AnalyticsService: Starting getRealAttackData');
      
      // Get attack logs from the last 24 hours
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
      
      // Use batch processing with limits
      let cursor: string | undefined;
      let processedCount = 0;
      const maxProcessed = 1000; // Limit to prevent excessive processing
      
      console.log('AnalyticsService: Listing attack logs from KV');
      
      do {
        const listResult = await env.ATTACK_LOGS.list({
          prefix: 'attack_',
          limit: 100,
          cursor
        });
        
        console.log(`AnalyticsService: Found ${listResult.keys.length} keys in batch`);
        
        // Process keys in parallel for better performance
        const batchPromises = listResult.keys.map(async (key) => {
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
                
                // Add to recent attacks (limit to 20 for performance)
                if (recentAttacks.length < 20) {
                  recentAttacks.push(attackData);
                }
              }
            }
          } catch (error) {
            console.error(`Error processing attack log ${key.name}:`, error);
          }
        });
        
        // Wait for batch to complete
        await Promise.all(batchPromises);
        
        processedCount += listResult.keys.length;
        cursor = listResult.list_complete ? undefined : listResult.cursor;
      } while (cursor && processedCount < maxProcessed);
      
      console.log(`AnalyticsService: Processed ${processedCount} total keys`);
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
      
      // Update cache
      analyticsCache.data = result;
      analyticsCache.timestamp = now;
      
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

  // Get reputation statistics - Optimized version
  static async getReputationStats(env: Env): Promise<any> {
    try {
      // Get IP reputation data from KV storage with limits
      const topThreats: Array<{ ip: string; attacks: number; score: number }> = [];
      
      // List reputation entries with limit
      let cursor: string | undefined;
      let processedCount = 0;
      const maxProcessed = 500; // Limit for performance
      
      do {
        const listResult = await env.IP_REPUTATION.list({
          prefix: 'reputation_',
          limit: 100,
          cursor
        });
        
        // Process each reputation record
        for (const key of listResult.keys) {
          if (processedCount >= maxProcessed) break;
          
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
          
          processedCount++;
        }
        
        cursor = listResult.list_complete ? undefined : listResult.cursor;
      } while (cursor && processedCount < maxProcessed);
      
      // Sort by attack count and take top 10
      topThreats.sort((a, b) => b.attacks - a.attacks);
      
      return { topThreats: topThreats.slice(0, 10) };
    } catch (error) {
      console.error('Error getting reputation stats:', error);
      return { topThreats: [] };
    }
  }

  // Get current metrics - Optimized version with caching
  static async getRealMetrics(env: Env): Promise<any> {
    const now = Date.now();
    
    // Check cache first
    if (metricsCache.data && (now - metricsCache.timestamp) < metricsCache.ttl) {
      console.log('AnalyticsService: Returning cached metrics');
      return metricsCache.data;
    }
    
    try {
      // Get metrics from KV storage with optimized approach
      const oneMinuteAgo = now - (60 * 1000);
      
      let requestsPerMinute = 0;
      let blockedRequests = 0;
      let activeThreats = 0;
      
      // Count recent requests with limits
      let cursor: string | undefined;
      let processedCount = 0;
      const maxProcessed = 500; // Limit for metrics
      
      do {
        const listResult = await env.ATTACK_LOGS.list({
          prefix: 'attack_',
          limit: 100,
          cursor
        });
        
        for (const key of listResult.keys) {
          if (processedCount >= maxProcessed) break;
          
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
          
          processedCount++;
        }
        
        cursor = listResult.list_complete ? undefined : listResult.cursor;
      } while (cursor && processedCount < maxProcessed);
      
      // Count active threats with limits
      cursor = undefined;
      processedCount = 0;
      
      do {
        const reputationListResult = await env.IP_REPUTATION.list({
          prefix: 'reputation_',
          limit: 100,
          cursor
        });
        
        for (const key of reputationListResult.keys) {
          if (processedCount >= maxProcessed) break;
          
          try {
            const reputationData = await env.IP_REPUTATION.get(key.name, { type: 'json' }) as IPReputation;
            
            if (reputationData && reputationData.score < 0) {
              activeThreats++;
            }
          } catch (error) {
            console.error(`Error processing reputation for metrics ${key.name}:`, error);
          }
          
          processedCount++;
        }
        
        cursor = reputationListResult.list_complete ? undefined : reputationListResult.cursor;
      } while (cursor && processedCount < maxProcessed);
      
      const result = {
        requestsPerMinute,
        blockedRequests,
        activeThreats,
        protectionLevel: activeThreats > 10 ? 'high' : activeThreats > 5 ? 'medium' : 'low'
      };
      
      // Update cache
      metricsCache.data = result;
      metricsCache.timestamp = now;
      
      return result;
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

  // Clear cache method for testing
  static clearCache(): void {
    analyticsCache.data = null;
    analyticsCache.timestamp = 0;
    metricsCache.data = null;
    metricsCache.timestamp = 0;
    console.log('AnalyticsService: Cache cleared');
  }
}
