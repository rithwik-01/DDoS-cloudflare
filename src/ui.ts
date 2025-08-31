import { Env, RequestContext } from './types';

export class UIService {
  // Challenge page generation
  static generateChallengePage(context: RequestContext): Response {
    const challengeId = crypto.randomUUID();
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShieldGuard Security Challenge</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            margin: 0; padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .challenge-container { 
            background: rgba(255,255,255,0.1); 
            padding: 40px; 
            border-radius: 15px; 
            backdrop-filter: blur(10px);
            text-align: center;
            max-width: 500px;
            width: 100%;
        }
        .shield-icon { font-size: 48px; margin-bottom: 20px; }
        .challenge-form { margin-top: 30px; }
        .challenge-input { 
            padding: 12px; 
            border: none; 
            border-radius: 8px; 
            margin: 10px 0; 
            width: 100%; 
            box-sizing: border-box;
            font-size: 16px;
        }
        .challenge-button { 
            background: #4caf50; 
            color: white; 
            padding: 12px 24px; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer; 
            font-size: 16px;
            margin-top: 10px;
        }
        .challenge-button:hover { background: #45a049; }
        .info { font-size: 14px; opacity: 0.8; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="challenge-container">
        <div class="shield-icon">🛡️</div>
        <h1>Security Challenge</h1>
        <p>To continue, please complete this security verification.</p>
        
        <div class="challenge-form">
            <p><strong>Question:</strong> What is 2 + 3?</p>
            <input type="text" id="answer" class="challenge-input" placeholder="Enter your answer">
            <br>
            <button onclick="submitChallenge()" class="challenge-button">Submit</button>
        </div>
        
        <div class="info">
            <p>Request ID: ${context.requestId}</p>
            <p>IP: ${context.ip}</p>
            <p>Location: ${context.country}</p>
        </div>
    </div>

    <script>
        function submitChallenge() {
            const answer = document.getElementById('answer').value;
            if (answer === '5') {
                // In a real implementation, you would send this to your API
                window.location.href = '/?challenge=passed&id=${challengeId}';
            } else {
                alert('Incorrect answer. Please try again.');
            }
        }
    </script>
</body>
</html>`;

    return new Response(html, {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'X-ShieldGuard-Challenge': 'true',
        'X-Request-ID': context.requestId
      }
    });
  }

  // Dashboard page
  static handleDashboard(request: Request, context: RequestContext, env: Env): Response {
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ ShieldGuard - DDoS Protection Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            margin: 0; padding: 20px; 
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); 
            color: white; 
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 40px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { 
            background: rgba(255,255,255,0.1); 
            padding: 25px; 
            border-radius: 15px; 
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
        }
        .metric { 
            background: rgba(0,0,0,0.2); 
            padding: 15px; 
            border-radius: 10px; 
            margin: 10px 0; 
            text-align: center;
        }
        .metric-value { font-size: 2em; font-weight: bold; color: #4caf50; }
        .metric-label { font-size: 0.9em; opacity: 0.8; }
        .status { display: inline-block; padding: 8px 16px; border-radius: 20px; font-size: 14px; font-weight: bold; }
        .status.active { background: #4caf50; }
        .status.warning { background: #ff9800; }
        .status.danger { background: #f44336; }
        .endpoint { 
            background: rgba(0,0,0,0.3); 
            padding: 12px; 
            border-radius: 8px; 
            margin: 8px 0; 
            font-family: monospace;
            border-left: 4px solid #4caf50;
        }
        .chart-container { 
            height: 300px; 
            background: rgba(0,0,0,0.2); 
            border-radius: 10px; 
            margin: 15px 0; 
            position: relative;
        }
        .chart-wrapper {
            position: relative;
            height: 100%;
            padding: 20px;
        }
        .button { 
            background: #4caf50; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer; 
            text-decoration: none;
            display: inline-block;
            margin: 5px;
        }
        .button:hover { background: #45a049; }
        .button.danger { background: #f44336; }
        .button.danger:hover { background: #da190b; }
        .attack-list {
            max-height: 200px;
            overflow-y: auto;
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            padding: 10px;
        }
        .attack-item {
            padding: 8px;
            margin: 5px 0;
            border-radius: 5px;
            background: rgba(255,255,255,0.1);
            border-left: 4px solid #f44336;
        }
        .attack-item.medium { border-left-color: #ff9800; }
        .attack-item.high { border-left-color: #f44336; }
        .attack-item.critical { border-left-color: #9c27b0; }
        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100%;
            font-style: italic;
            opacity: 0.7;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ShieldGuard</h1>
            <p>Advanced DDoS Protection System - Powered by Cloudflare Workers</p>
            <span class="status active">ACTIVE</span>
            <span class="status active">GLOBAL PROTECTION</span>
        </div>
        
        <div class="card">
            <h3>📈 Attack Activity Chart</h3>
            <div class="chart-container">
                <div class="chart-wrapper">
                    <canvas id="attackChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h3>🚨 Recent Attacks</h3>
            <div class="attack-list" id="recentAttacks">
                <div class="loading">Loading recent attacks...</div>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>📊 Real-time Metrics</h3>
                <div class="metric">
                    <div class="metric-value" id="requestsPerMinute">--</div>
                    <div class="metric-label">Requests/Minute</div>
                </div>
                <div class="metric">
                    <div class="metric-value" id="blockedRequests">--</div>
                    <div class="metric-label">Blocked Requests</div>
                </div>
                <div class="metric">
                    <div class="metric-value" id="activeThreats">--</div>
                    <div class="metric-label">Active Threats</div>
                </div>
                <div class="metric">
                    <div class="metric-value" id="protectionLevel">--</div>
                    <div class="metric-label">Protection Level</div>
                </div>
            </div>
            
            <div class="card">
                <h3>🌍 Global Coverage</h3>
                <div class="metric">
                    <div class="metric-value">200+</div>
                    <div class="metric-label">Edge Locations</div>
                </div>
                <div class="metric">
                    <div class="metric-value">99.9%</div>
                    <div class="metric-label">Uptime</div>
                </div>
                <div class="metric">
                    <div class="metric-value">&lt;10ms</div>
                    <div class="metric-label">Response Time</div>
                </div>
                <div class="metric">
                    <div class="metric-value">∞</div>
                    <div class="metric-label">Bandwidth</div>
                </div>
            </div>
            
            <div class="card">
                <h3>🔧 Protection Features</h3>
                <ul>
                    <li>✅ Rate Limiting (${env.MAX_REQUESTS_PER_MINUTE}/min)</li>
                    <li>✅ IP Reputation Tracking</li>
                    <li>✅ Bot Detection & Fingerprinting</li>
                    <li>✅ Challenge Pages</li>
                    <li>✅ Real-time Analytics</li>
                    <li>✅ Global CDN Optimization</li>
                    <li>✅ Attack Logging</li>
                    <li>✅ Whitelist/Blacklist Management</li>
                </ul>
            </div>
            
            <div class="card">
                <h3>📡 API Endpoints</h3>
                <div class="endpoint">GET /api/status</div>
                <div class="endpoint">GET /api/analytics</div>
                <div class="endpoint">GET /api/reputation</div>
                <div class="endpoint">POST /api/challenge</div>
                <div class="endpoint">POST /api/test-attack</div>
                <div class="endpoint">POST /api/whitelist</div>
                <div class="endpoint">POST /api/blacklist</div>
                <div class="endpoint">POST /api/generate-sample-data</div>
            </div>
        </div>
        
        <div class="card">
            <h3>🎯 Quick Actions</h3>
            <a href="/api/status" class="button">View Status</a>
            <a href="/api/analytics" class="button">View Analytics</a>
            <a href="/api/test-attack" class="button danger">Test Attack</a>
            <button onclick="generateSampleData()" class="button">Generate Sample Data</button>
            <button onclick="refreshMetrics()" class="button">Refresh Metrics</button>
            <button onclick="loadAttackChart()" class="button">Refresh Chart</button>
            <button onclick="clearCache()" class="button">Clear Cache</button>
        </div>
    </div>

    <script>
        let attackChart = null;
        let lastMetricsUpdate = 0;
        let lastChartUpdate = 0;
        let lastAttacksUpdate = 0;
        let isLoadingMetrics = false;
        let isLoadingChart = false;
        let isLoadingAttacks = false;
        
        // Initialize the attack chart
        function initAttackChart() {
            const ctx = document.getElementById('attackChart').getContext('2d');
            attackChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Attack Attempts',
                        data: [],
                        borderColor: '#f44336',
                        backgroundColor: 'rgba(244, 67, 54, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'Blocked Requests',
                        data: [],
                        borderColor: '#ff9800',
                        backgroundColor: 'rgba(255, 152, 0, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: 'white'
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: 'white'
                            },
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            }
                        },
                        y: {
                            ticks: {
                                color: 'white'
                            },
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            }
                        }
                    }
                }
            });
        }
        
        // Load attack chart data with throttling
        async function loadAttackChart() {
            const now = Date.now();
            if (isLoadingChart || (now - lastChartUpdate) < 30000) return; // 30 second throttle
            
            isLoadingChart = true;
            lastChartUpdate = now;
            
            try {
                const response = await fetch('/api/fast-analytics');
                const data = await response.json();
                
                if (!data.hourlyData) {
                    console.error('No hourly data available');
                    return;
                }
                
                // Generate time labels for the last 24 hours
                const labels = [];
                const attackData = [];
                const blockedData = [];
                
                for (let i = 23; i >= 0; i--) {
                    const time = new Date(Date.now() - i * 60 * 60 * 1000);
                    labels.push(time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
                    
                    // Use real hourly data from the API
                    const hour = time.getHours();
                    const hourData = data.hourlyData[hour] || { attacks: 0, blocked: 0 };
                    
                    attackData.push(hourData.attacks);
                    blockedData.push(hourData.blocked);
                }
                
                if (attackChart) {
                    attackChart.data.labels = labels;
                    attackChart.data.datasets[0].data = attackData;
                    attackChart.data.datasets[1].data = blockedData;
                    attackChart.update('none'); // Use 'none' for better performance
                }
            } catch (error) {
                console.error('Failed to load attack chart:', error);
            } finally {
                isLoadingChart = false;
            }
        }
        
        // Load recent attacks with throttling
        async function loadRecentAttacks() {
            const now = Date.now();
            if (isLoadingAttacks || (now - lastAttacksUpdate) < 15000) return; // 15 second throttle
            
            isLoadingAttacks = true;
            lastAttacksUpdate = now;
            
            try {
                const response = await fetch('/api/fast-analytics');
                const data = await response.json();
                
                const attacksContainer = document.getElementById('recentAttacks');
                
                if (data.recentAttacks && data.recentAttacks.length > 0) {
                    attacksContainer.innerHTML = data.recentAttacks.map(attack => 
                        '<div class="attack-item ' + attack.severity + '">' +
                        '<strong>' + attack.attackType + '</strong> from ' + attack.ip + '<br>' +
                        '<small>' + new Date(attack.timestamp).toLocaleString() + '</small>' +
                        '</div>'
                    ).join('');
                } else {
                    attacksContainer.innerHTML = '<div class="loading">No recent attacks detected</div>';
                }
            } catch (error) {
                console.error('Failed to load recent attacks:', error);
                document.getElementById('recentAttacks').innerHTML = '<div class="loading">Failed to load attacks</div>';
            } finally {
                isLoadingAttacks = false;
            }
        }
        
        // Refresh metrics with throttling
        async function refreshMetrics() {
            const now = Date.now();
            if (isLoadingMetrics || (now - lastMetricsUpdate) < 10000) return; // 10 second throttle
            
            isLoadingMetrics = true;
            lastMetricsUpdate = now;
            
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                
                document.getElementById('requestsPerMinute').textContent = data.metrics.requestsPerMinute;
                document.getElementById('blockedRequests').textContent = data.metrics.blockedRequests;
                document.getElementById('activeThreats').textContent = data.metrics.activeThreats;
                document.getElementById('protectionLevel').textContent = data.metrics.protectionLevel;
            } catch (error) {
                console.error('Failed to refresh metrics:', error);
            } finally {
                isLoadingMetrics = false;
            }
        }
        
        // Generate sample data
        async function generateSampleData() {
            try {
                const response = await fetch('/api/generate-sample-data', { method: 'POST' });
                const data = await response.json();
                
                if (data.success) {
                    alert('Sample data generated successfully! Refreshing dashboard...');
                    refreshMetrics();
                    loadAttackChart();
                    loadRecentAttacks();
                } else {
                    alert('Failed to generate sample data: ' + data.error);
                }
            } catch (error) {
                console.error('Failed to generate sample data:', error);
                alert('Failed to generate sample data');
            }
        }
        
        // Clear cache
        async function clearCache() {
            try {
                const response = await fetch('/api/cache-clear');
                const data = await response.json();
                
                if (data.success) {
                    alert('Cache cleared successfully! Refreshing dashboard...');
                    // Force refresh all data
                    lastMetricsUpdate = 0;
                    lastChartUpdate = 0;
                    lastAttacksUpdate = 0;
                    refreshMetrics();
                    loadAttackChart();
                    loadRecentAttacks();
                } else {
                    alert('Failed to clear cache: ' + data.error);
                }
            } catch (error) {
                console.error('Failed to clear cache:', error);
                alert('Failed to clear cache');
            }
        }
        
        // Initialize everything when page loads
        document.addEventListener('DOMContentLoaded', function() {
            initAttackChart();
            
            // Initial load
            refreshMetrics();
            loadAttackChart();
            loadRecentAttacks();
            
            // Set up intervals with longer intervals for better performance
            setInterval(refreshMetrics, 30000); // 30 seconds
            setInterval(loadAttackChart, 60000); // 1 minute
            setInterval(loadRecentAttacks, 45000); // 45 seconds
        });
    </script>
</body>
</html>`;

    return new Response(html, {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'public, max-age=300',
        'X-ShieldGuard-Dashboard': 'true',
        'X-Request-ID': context.requestId
      }
    });
  }
}
