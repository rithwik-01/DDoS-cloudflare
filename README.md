# ShieldGuard - Basic DDoS Protection Worker

A simple DDoS protection implementation using Cloudflare Workers with rate limiting, IP reputation tracking, and basic attack detection.

## Features

### Core Functionality
- **Rate Limiting**: Configurable limits per IP address
- **IP Reputation**: Track and score IP addresses based on behavior
- **Bot Detection**: Simple bot detection using user agent patterns
- **Attack Logging**: Log suspicious activity for monitoring
- **Challenge Pages**: Basic challenge system for suspicious traffic
- **Dashboard**: Simple web interface for monitoring

### Protection Features
- **Request Rate Limiting**: Per-minute and per-hour limits
- **IP Blacklisting**: Automatic blacklisting of malicious IPs
- **Suspicious Pattern Detection**: Basic pattern matching
- **Real-time Monitoring**: Simple metrics and analytics

## Prerequisites

- Node.js 18+ 
- npm or yarn
- Cloudflare account
- Wrangler CLI

## Installation & Setup

### 1. Install Wrangler CLI
```bash
npm install -g wrangler
```

### 2. Authenticate with Cloudflare
```bash
wrangler login
```

### 3. Install Dependencies
```bash
npm install
```

### 4. Development
```bash
npm run dev
```

### 5. Deploy
```bash
npm run deploy
```

## Project Structure

```
edge-computing/
├── src/
│   └── index.ts          # Main Worker implementation
├── public/               # Static assets
├── wrangler.jsonc        # Wrangler configuration
├── package.json          # Dependencies and scripts
└── README.md            # This file
```

## Configuration

### Environment Variables
The following environment variables are configured in `wrangler.jsonc`:

- `APP_NAME`: Application name
- `APP_VERSION`: Version number
- `ENVIRONMENT`: Deployment environment
- `MAX_REQUESTS_PER_MINUTE`: Rate limit per minute
- `MAX_REQUESTS_PER_HOUR`: Rate limit per hour
- `REPUTATION_THRESHOLD`: Reputation score threshold
- `CHALLENGE_ENABLED`: Enable challenge pages
- `BOT_DETECTION_ENABLED`: Enable bot detection

### Adding Secrets
For sensitive data, use Wrangler secrets:

```bash
wrangler secret put API_KEY
```

## API Endpoints

### Dashboard
- **URL**: `/`
- **Method**: GET
- **Description**: Web dashboard for monitoring protection status

### Status API
- **URL**: `/api/status`
- **Method**: GET
- **Description**: Current system status and metrics
- **Response**: JSON with system information

### Analytics API
- **URL**: `/api/analytics`
- **Method**: GET
- **Description**: Attack analytics and statistics
- **Response**: JSON with attack data and metrics

### Reputation API
- **URL**: `/api/reputation?ip={ip}`
- **Method**: GET
- **Description**: Check IP reputation score
- **Parameters**: `ip` - IP address to check

### Challenge API
- **URL**: `/api/challenge`
- **Method**: POST
- **Description**: Submit challenge response
- **Request**: JSON with challenge answer

### Test Attack API
- **URL**: `/api/test-attack`
- **Method**: POST
- **Description**: Simulate an attack for testing
- **Response**: JSON with test results

### Whitelist API
- **URL**: `/api/whitelist`
- **Method**: POST
- **Description**: Add IP to whitelist
- **Request**: JSON with IP address

### Blacklist API
- **URL**: `/api/blacklist`
- **Method**: POST
- **Description**: Add IP to blacklist
- **Request**: JSON with IP address

## Protection Features

### Rate Limiting
- Per-minute and per-hour request limits
- Configurable thresholds via environment variables
- Automatic blocking of excessive requests

### IP Reputation
- Track IP behavior over time
- Score-based reputation system
- Automatic blacklisting of malicious IPs

### Bot Detection
- User agent pattern matching
- Common bot signature detection
- Configurable bot detection rules

### Attack Logging
- Log all suspicious activity
- Store attack data in KV storage
- Basic analytics and reporting

## Monitoring & Debugging

### Request Tracking
Every request includes:
- Unique request ID
- Timestamp
- Client IP and location
- Request path and method

### Error Handling
Basic error handling with:
- HTTP status codes
- Error messages
- Request tracking

### Logging
- Console logging for debugging
- Request metadata
- Attack logging

## Deployment

### Development
```bash
npm run dev
```
Access at: http://localhost:8787

### Production
```bash
npm run deploy
```
Access at: `https://shieldguard.{your-subdomain}.workers.dev`

### Custom Domain
To use a custom domain:
1. Add your domain to Cloudflare
2. Configure DNS records
3. Update `wrangler.jsonc` with custom routes

## Performance

### Response Times
- **Dashboard**: ~50ms
- **API Endpoints**: ~30ms
- **Protected Routes**: ~20ms

### Storage
- **KV Storage**: For logs and reputation data
- **TTL**: 24 hours for reputation, 7 days for logs

## Customization

### Adding New Endpoints
1. Add route handler in `src/index.ts`
2. Implement request/response logic
3. Add error handling
4. Update documentation

### Environment-Specific Configuration
```bash
# Development
wrangler dev --env development

# Staging
wrangler dev --env staging

# Production
wrangler deploy --env production
```

### Adding External APIs
1. Configure API credentials as secrets
2. Implement API client in Worker
3. Add error handling
4. Update environment variables

## Security Features

- **SSL/TLS**: Automatic HTTPS termination
- **Rate Limiting**: Configurable request limits
- **IP Reputation**: Track and block malicious IPs
- **Bot Detection**: Basic bot filtering
- **Input Validation**: Request sanitization

## Learning Resources

- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
- [Wrangler CLI Guide](https://developers.cloudflare.com/workers/wrangler/)
- [KV Storage](https://developers.cloudflare.com/workers/configuration/workers-kv/)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Check the [Cloudflare Workers documentation](https://developers.cloudflare.com/workers/)
- Visit the [Cloudflare Community](https://community.cloudflare.com/)
- Open an issue in this repository

---

**Built with Cloudflare Workers**
