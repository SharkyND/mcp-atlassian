# MCP Atlassian Helm Chart

A Helm chart for deploying the MCP (Model Context Protocol) Atlassian server, which provides integration with Jira and Confluence services.

## Description

This chart deploys the MCP Atlassian server on a Kubernetes cluster using Helm. The MCP Atlassian server enables AI assistants and applications to interact with Atlassian services (Jira and Confluence) through the Model Context Protocol.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- Access to Atlassian services (Jira and/or Confluence)

### Install the chart

```bash
# Basic installation with default values
helm install mcp-atlassian oci://ghcr.io/sharkynd/charts/mcp-atlassian --version ???

# Install with custom values
helm install mcp-atlassian oci://ghcr.io/sharkynd/charts/mcp-atlassian -f values.yaml

# Install in a specific namespace
helm install mcp-atlassian oci://ghcr.io/sharkynd/charts/mcp-atlassian --namespace mcp-system --create-namespace
```

## Configuration

The following table lists the configurable parameters and their default values.

### Application Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Container image repository | `ghcr.io/sharkynd/mcp-atlassian` |
| `image.tag` | Container image tag | `""` (uses appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets | `[]` |

### Service Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `80` |
| `service.targetPort` | Container target port | `8000` |

### Environment Variables

| Parameter | Description | Default |
|-----------|-------------|---------|
| `env.PORT` | Server port | `"8000"` |
| `env.TRANSPORT` | MCP transport protocol | `"streamable-http"` |
| `env.CONFLUENCE_URL` | Confluence base URL | `""` (commented) |
| `env.JIRA_URL` | Jira base URL | `""` (commented) |
| `env.MCP_VERBOSE` | Enable verbose logging | `""` (commented) |

### Ingress Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Ingress hosts configuration | `[{host: "mcp-atlassian.local", paths: [{path: "/", pathType: "Prefix"}]}]` |
| `ingress.tls` | Ingress TLS configuration | `[]` |

### High Availability Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podDisruptionBudget.enabled` | Enable Pod Disruption Budget | `false` |
| `podDisruptionBudget.minAvailable` | Minimum available pods during disruptions | `1` |
| `podDisruptionBudget.maxUnavailable` | Maximum unavailable pods during disruptions | `""` |

### Security Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.automount` | Automount service account token | `true` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.name` | Service account name | `""` |
| `podSecurityContext` | Pod security context | `{}` |
| `securityContext` | Container security context | `{}` |

### Resource Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources` | Resource limits and requests | `{}` |

### Autoscaling Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable horizontal pod autoscaling | `false` |
| `autoscaling.minReplicas` | Minimum number of replicas | `1` |
| `autoscaling.maxReplicas` | Maximum number of replicas | `100` |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU utilization | `80` |
| `autoscaling.targetMemoryUtilizationPercentage` | Target memory utilization | `""` (disabled) |

### Health Checks

| Parameter | Description | Default |
|-----------|-------------|---------|
| `livenessProbe.httpGet.path` | Liveness probe path | `/healthz` |
| `livenessProbe.httpGet.port` | Liveness probe port | `http` |
| `livenessProbe.initialDelaySeconds` | Liveness probe initial delay | `30` |
| `livenessProbe.periodSeconds` | Liveness probe period | `10` |
| `readinessProbe.httpGet.path` | Readiness probe path | `/healthz` |
| `readinessProbe.httpGet.port` | Readiness probe port | `http` |
| `readinessProbe.initialDelaySeconds` | Readiness probe initial delay | `5` |
| `readinessProbe.periodSeconds` | Readiness probe period | `5` |

## Authentication

The MCP Atlassian server supports multiple authentication methods:

### API Token Authentication (Atlassian Cloud)

```yaml
secrets:
  jiraApiToken: "your-jira-api-token"
  confluenceApiToken: "your-confluence-api-token"
```

### Personal Access Token (Atlassian Server/DC)

```yaml
secrets:
  jiraPersonalToken: "your-jira-personal-token"
  confluencePersonalToken: "your-confluence-personal-token"
```

### OAuth 2.0 Authentication (Atlassian Cloud)

```yaml
secrets:
  oauth:
    clientId: "your-oauth-client-id"
    clientSecret: "your-oauth-client-secret"
    redirectUri: "your-redirect-uri"
    scope: "read:jira-work read:confluence-content.summary"
    cloudId: "your-cloud-id"
    accessToken: "your-access-token"
```

## Example Configurations

### Basic Deployment with Environment Variables

```yaml
env:
  CONFLUENCE_URL: "https://your-company.atlassian.net"
  JIRA_URL: "https://your-company.atlassian.net"
  MCP_VERBOSE: "true"

secrets:
  jiraApiToken: "your-jira-api-token"
  confluenceApiToken: "your-confluence-api-token"
```

### Production Deployment with Ingress and TLS

```yaml
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  hosts:
    - host: mcp-atlassian.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: mcp-atlassian-tls
      hosts:
        - mcp-atlassian.yourdomain.com

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

### High Availability Deployment with Sticky Sessions

```yaml
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    # NGINX sticky sessions
    nginx.ingress.kubernetes.io/affinity: "cookie"
    nginx.ingress.kubernetes.io/session-cookie-name: "mcp-atlassian-session"
    nginx.ingress.kubernetes.io/session-cookie-expires: "86400"
    nginx.ingress.kubernetes.io/session-cookie-max-age: "86400"
    nginx.ingress.kubernetes.io/session-cookie-path: "/"
    nginx.ingress.kubernetes.io/session-cookie-change-on-failure: "true"
    # NGINX proxy settings for long-running connections
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-http-version: "1.1"
  hosts:
    - host: mcp-atlassian.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: mcp-atlassian-tls
      hosts:
        - mcp-atlassian.yourdomain.com

# Enable Pod Disruption Budget for high availability
podDisruptionBudget:
  enabled: true
  minAvailable: 1

# Anti-affinity to spread pods across different nodes
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - mcp-atlassian
        topologyKey: kubernetes.io/hostname

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi
```
### Autoscaling Deployment

```yaml
# Enable autoscaling instead of fixed replica count
# Note: replicaCount is ignored when autoscaling is enabled
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

# Resource requests/limits are required for autoscaling to work
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

### High-Security Deployment

```yaml

podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 2000

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1000
  capabilities:
    drop:
    - ALL

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

## Uninstalling the Chart

```bash
helm uninstall mcp-atlassian
```

## Troubleshooting

### Common Issues

1. **Authentication Failures**: Ensure your API tokens or credentials are correctly configured in the secrets section.
2. **Network Connectivity**: Verify that your Kubernetes cluster can reach your Atlassian services.
3. **Health Check Failures**: The `/healthz` endpoint should return 200 OK when the service is healthy.

### Debugging

```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/name=mcp-atlassian

# Check pod logs
kubectl logs -l app.kubernetes.io/name=mcp-atlassian

# Check service endpoints
kubectl get endpoints

# Port forward for local testing
kubectl port-forward svc/mcp-atlassian 8080:80
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test the changes
5. Submit a pull request

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.
