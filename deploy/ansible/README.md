# Ansible rollout

Two playbooks, one inventory. Secrets come from variables you keep in `ansible-vault`; the playbooks only reference them.

```sh
cp inventory.example.yaml inventory.yaml          # hosts and variables
ansible-vault create group_vars/all/vault.yaml   # sandboxd_api_token, preview_ticket_key, postgres_password
ansible-playbook -i inventory.yaml playbooks/cluster.yaml   # namespace, RBAC, NAD, Secret, (gateway pod if mode=node)
ansible-playbook -i inventory.yaml playbooks/gateway.yaml   # gateway VM: firewall, docker, compose, policies checkout
```

| Playbook | Hosts | What it does |
|---|---|---|
| `cluster.yaml` | `localhost` with a kubeconfig | applies `deploy/k8s/*.yaml` (rendered from the chart), creates the Secret from vault variables, labels the gateway node, or extracts the token for an external gateway |
| `gateway.yaml` | group `gateway` | nftables for the VLAN interface, no forwarding, Docker, `/opt/agent-sandbox` with compose files, `.env`, kubeconfig, policies (git clone or copy), `docker compose up -d` |

Both are idempotent; re-run after a policy or image change.
