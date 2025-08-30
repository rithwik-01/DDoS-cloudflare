// Environment interface for Cloudflare Worker configuration
export interface Env {
  IP_REPUTATION: KVNamespace;
  ATTACK_LOGS: KVNamespace;
  RATE_LIMITS: KVNamespace;
  APP_NAME: string;
  APP_VERSION: string;
  ENVIRONMENT: string;
  MAX_REQUESTS_PER_MINUTE: string;
  MAX_REQUESTS_PER_HOUR: string;
  REPUTATION_THRESHOLD: string;
  CHALLENGE_ENABLED: string;
  BOT_DETECTION_ENABLED: string;
}

export interface IPReputation {
  score: number;
  lastSeen: string;
  attackCount: number;
  isBlacklisted: boolean;
  challengesPassed: number;
  challengesFailed: number;
}

export interface AttackLog {
  timestamp: string;
  ip: string;
  country: string;
  userAgent: string;
  attackType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: any;
}

export interface RateLimitData {
  requests: number;
  windowStart: number;
  blocked: boolean;
}

export interface RequestContext {
  ip: string;
  country: string;
  city: string;
  userAgent: string;
  timestamp: string;
  requestId: string;
  path: string;
  method: string;
  headers: Record<string, string>;
}

export interface ProtectionResult {
  allowed: boolean;
  reason?: string;
  challenge?: boolean;
  reputation?: IPReputation;
  rateLimit?: RateLimitData;
}
