# MCP Atlassian Grafana Dashboards

This directory contains pre-built Grafana dashboard JSON files for monitoring MCP Atlassian deployments.

## Available Dashboards

### 1. **Overview Dashboard** (`mcp-atlassian-overview.json`)
**Primary monitoring dashboard with key metrics at a glance.**

**Panels:**
- Total Users, Concurrent Requests, Error Rate, P95 Response Time
- Request Rate by Status Code
- Response Time Percentiles (P50, P95, P99)
- Active Users (1h)
- Activity by Type

**Use Case:** Executive summary, daily monitoring, first-look health check

---

### 2. **User Activity Dashboard** (`mcp-atlassian-user-activity.json`)
**Deep dive into user engagement and behavior patterns.**

**Panels:**
- Total Unique Users, Active Users (1h), Daily Active Users (24h)
- User Activity Over Time
- Activity Distribution by Type (pie chart)
- User Agent Distribution (pie chart)
- Top 10 Most Active Users (table)

**Use Case:** Business intelligence, user adoption tracking, engagement analysis

---

### 3. **Performance Monitoring Dashboard** (`mcp-atlassian-performance.json`)
**Technical performance metrics and SLA monitoring.**

**Panels:**
- Request Rate, Error Rate, Average Response Time, Concurrent Requests
- Request Rate by Status (2xx, 4xx, 5xx)
- Response Time Distribution (P50, P95, P99, Average)
- Request Rate by Endpoint
- Concurrent Requests by Pod
- Endpoint Performance Summary (table)

**Use Case:** SRE monitoring, performance optimization, troubleshooting

---

### 4. **Kubernetes Pods Dashboard** (`mcp-atlassian-kubernetes.json`)
**Multi-pod deployment monitoring for Kubernetes environments.**

**Panels:**
- Total Pods, Active Pods, Total Load
- Request Distribution Across Pods
- Load Balance - Concurrent Requests per Pod
- Error Rate by Pod
- P95 Response Time by Pod
- User Activity Distribution Across Pods
- Pod Performance Summary (table)

**Use Case:** Container orchestration monitoring, scaling decisions, load balancing analysis

## How to Import Dashboards

### Method 1: Manual Import (Grafana UI)

1. **Open Grafana** → Navigate to your Grafana instance
2. **Go to Dashboards** → Click the "+" icon → Select "Import"
3. **Upload JSON** → Click "Upload JSON file" and select one of the dashboard files
4. **Configure Data Source** → Select your Prometheus data source
5. **Import** → Click "Import" to add the dashboard

### Method 2: Grafana API Import

```bash
# Replace with your Grafana details
GRAFANA_URL="http://your-grafana-instance:3000"
GRAFANA_API_KEY="your-api-key"
DASHBOARD_FILE="mcp-atlassian-overview.json"

curl -X POST \
  -H "Authorization: Bearer $GRAFANA_API_KEY" \
  -H "Content-Type: application/json" \
  -d @$DASHBOARD_FILE \
  "$GRAFANA_URL/api/dashboards/db"
```

### Method 3: Kubernetes ConfigMap (Automated)

If using the MCP Atlassian Helm chart with Grafana operator:

```yaml
# values.yaml
monitoring:
  grafana:
    enabled: true
    dashboards:
      enabled: true
      # Dashboards will be auto-provisioned via ConfigMaps
```

## Dashboard Variables

All dashboards use the following template variables:

- `${DS_PROMETHEUS}` - Prometheus data source (auto-configured during import)

## Customization

### Adding Filters

To add environment or namespace filtering, modify the dashboard JSON:

```json
"templating": {
  "list": [
    {
      "name": "namespace",
      "type": "query",
      "query": "label_values(mcp_atlassian_http_requests_total, namespace)",
      "datasource": "${DS_PROMETHEUS}"
    }
  ]
}
```

Then update queries to use the variable:
```promql
sum(rate(mcp_atlassian_http_requests_total{namespace="$namespace"}[5m]))
```

### Alert Integration

To add alerting to dashboards, configure alert rules in your Prometheus or Grafana setup:

```yaml
# Example alert rule
- alert: MCPAtlassianHighErrorRate
  expr: |
    (
      sum(rate(mcp_atlassian_http_requests_total{status_code=~"4..|5.."}[5m])) / 
      sum(rate(mcp_atlassian_http_requests_total[5m]))
    ) > 0.05
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "MCP Atlassian high error rate detected"
```

## Troubleshooting

### No Data Showing
1. **Check Prometheus Data Source** - Verify connection in Grafana
2. **Verify Metrics** - Ensure MCP Atlassian is exposing metrics at `/metrics`
3. **Check Time Range** - Adjust dashboard time range if no recent data

### Missing Panels
1. **Prometheus Version** - Ensure you're using a compatible Prometheus version
2. **Metric Names** - Verify metric names match your MCP Atlassian version
3. **Grafana Version** - Dashboards are tested with Grafana 10.x+

### Performance Issues
1. **Query Optimization** - Increase step interval for long time ranges
2. **Data Retention** - Consider Prometheus retention policies for historical data
3. **Dashboard Refresh** - Adjust auto-refresh interval based on your needs

## Dashboard Maintenance

- **Version Compatibility** - Update dashboards when upgrading MCP Atlassian
- **Metric Evolution** - Monitor for new metrics in future releases
- **Custom Modifications** - Keep track of local customizations for easier updates

## Contributing

Found an issue or want to improve a dashboard? Please submit a pull request or open an issue in the MCP Atlassian repository.