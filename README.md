# ShieldGuard - DDoS Protection Worker

A comprehensive DDoS protection system built with Cloudflare Workers, featuring rate limiting, IP reputation tracking, bot detection, and real-time analytics.

## 🏗️ Architecture

The application has been refactored into a modular architecture for better maintainability and separation of concerns:

### 📁 File Structure

```
src/
├── index.ts          # Main entry point and request routing
├── types.ts          # TypeScript interfaces and type definitions
├── protection.ts     # Core protection logic (rate limiting, reputation, bot detection)
├── analytics.ts      # Analytics and metrics collection
├── logging.ts        # Attack logging and severity calculation
├── api.ts           # API endpoint handlers
└── ui.ts            # UI components (dashboard, challenge pages)
```

### 🔧 Modules Overview

#### `types.ts`
- Contains all TypeScript interfaces and type definitions
- `Env` - Cloudflare Worker environment configuration
- `RequestContext` - Request metadata and context
- `IPReputation` - IP reputation tracking data
- `AttackLog` - Attack logging structure
- `RateLimitData` - Rate limiting data
- `ProtectionResult` - Protection check results

#### `protection.ts` - ProtectionService
- **IP Reputation Management**: Track and update IP reputation scores
- **Rate Limiting**: Per-minute and per-hour request limits
- **Bot Detection**: User agent pattern matching
- **Suspicious Pattern Detection**: Header analysis and path checking
- **Protection Rules**: Main protection logic coordination

#### `analytics.ts` - AnalyticsService
- **Attack Data Retrieval**: Efficient KV storage queries for attack logs
- **Reputation Statistics**: Top threats and IP analysis
- **Real-time Metrics**: Current protection status and statistics
- **Hourly Data Aggregation**: Time-based attack analysis

#### `logging.ts` - LoggingService
- **Attack Logging**: Structured attack event logging
- **Severity Calculation**: Attack type to severity mapping
- **Recent Attacks Tracking**: Quick access to recent attack data

#### `api.ts` - APIService
- **Status API**: System health and metrics
- **Analytics API**: Attack data and statistics
- **Reputation API**: IP reputation queries
- **Management APIs**: Whitelist/blacklist operations
- **Test APIs**: Sample data generation and testing

#### `ui.ts` - UIService
- **Dashboard**: Real-time protection monitoring interface
- **Challenge Pages**: Security verification for suspicious traffic
- **Interactive Charts**: Attack activity visualization
- **Responsive Design**: Mobile-friendly interface

#### `index.ts` - Main Application
- **Request Routing**: URL-based endpoint dispatching
- **Protection Application**: Main protection logic coordination
- **Error Handling**: Centralized error management
- **Context Creation**: Request metadata extraction

## 🚀 Features

### Core Protection
- ✅ **Rate Limiting**: Configurable per-minute and per-hour limits
- ✅ **IP Reputation**: Dynamic scoring based on behavior
- ✅ **Bot Detection**: User agent and pattern analysis
- ✅ **Challenge Pages**: Interactive security verification
- ✅ **Whitelist/Blacklist**: Manual IP management

### Analytics & Monitoring
- ✅ **Real-time Metrics**: Live protection statistics
- ✅ **Attack Logging**: Comprehensive event tracking
- ✅ **Hourly Analytics**: Time-based attack analysis
- ✅ **Top Threats**: Most active malicious IPs
- ✅ **Interactive Dashboard**: Visual monitoring interface

### Developer Experience
- ✅ **Modular Architecture**: Clean separation of concerns
- ✅ **TypeScript**: Full type safety and IntelliSense
- ✅ **Comprehensive Testing**: Unit and integration tests
- ✅ **API Documentation**: Well-documented endpoints
- ✅ **Sample Data Generation**: Testing and demonstration tools

## 🛠️ Development

### Prerequisites
- Node.js 18+
- npm or yarn
- Cloudflare account with Workers enabled

### Setup
```bash
# Install dependencies
npm install

# Run tests
npm run test

# Start development server
npm run dev

# Deploy to Cloudflare
npm run deploy
```

### Environment Variables
Configure these in your `wrangler.toml`:

```toml
[vars]
APP_NAME = "ShieldGuard"
APP_VERSION = "1.0.0"
ENVIRONMENT = "production"
MAX_REQUESTS_PER_MINUTE = "60"
MAX_REQUESTS_PER_HOUR = "1000"
REPUTATION_THRESHOLD = "50"
CHALLENGE_ENABLED = "true"
BOT_DETECTION_ENABLED = "true"
```

### KV Namespaces
Required KV namespaces:
- `IP_REPUTATION` - IP reputation data
- `ATTACK_LOGS` - Attack event logs
- `RATE_LIMITS` - Rate limiting counters

## 📊 API Endpoints

### Dashboard
- `GET /` - Main dashboard interface

### Status & Analytics
- `GET /api/status` - System status and metrics
- `GET /api/analytics` - Attack data and statistics
- `GET /api/reputation?ip=<ip>` - IP reputation lookup

### Management
- `POST /api/whitelist` - Whitelist an IP
- `POST /api/blacklist` - Blacklist an IP
- `POST /api/challenge` - Challenge response validation

### Testing & Development
- `POST /api/test-attack` - Simulate attack for testing
- `POST /api/generate-sample-data` - Generate test data
- `GET /api/kv-test` - KV storage test

## 🔍 Troubleshooting

### Analytics Not Showing
1. Check KV namespace permissions
2. Verify environment variables are set
3. Generate sample data using `/api/generate-sample-data`
4. Check browser console for JavaScript errors

### Protection Not Working
1. Verify all KV namespaces are configured
2. Check rate limiting configuration
3. Ensure bot detection is enabled
4. Review Cloudflare Worker logs

### Performance Issues
1. Monitor KV storage usage
2. Check rate limiting effectiveness
3. Review analytics query performance
4. Consider adjusting TTL values

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
