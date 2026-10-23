# kubectl apply

Plain manifests rendered from the Helm chart (`make manifests` regenerates them, do not edit by hand):

| File | Contents |
|---|---|
| `gateway-on-node.yaml` | everything for a cluster whose gateway is a labelled node: namespace, RBAC, NAD, policies, config, Caddy + sandboxd pod |
| `cluster-only.yaml` | only the cluster side for a gateway VM: namespace, RBAC, NAD, agent ServiceAccount, token for sandboxd |
| `secret.example.yaml` | the one Secret you create yourself |

```sh
kubectl apply -f deploy/k8s/secret.example.yaml     # after editing the values
kubectl apply -k deploy/k8s                          # gateway-on-node layout with policies taken from ../../policies
# or
kubectl apply -f deploy/k8s/cluster-only.yaml        # gateway VM layout
```

After a policy merge the rollout is `make manifests && kubectl apply -k deploy/k8s`: the policies ConfigMap
changes, sandboxd hot-reloads and re-renders the gateway. Image names, the VLAN interface and the preview domain
are plain values in the ConfigMap `agent-sandbox-sandboxd-config` and the Deployment; override them with a
kustomize patch or regenerate with `helm template -f your-values.yaml`.
