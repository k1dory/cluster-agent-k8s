#!/usr/bin/env python3
"""Test shipped firewall behavior on an isolated Docker network, without a cluster.

Usage: python3 hack/test-netlock.py agent-sandbox/agent:review
Build the image first. No ports are published, no external services are contacted,
and only containers/network created by this invocation are removed on exit.
"""

import argparse
import json
import subprocess
import time
import uuid


def docker(*args, check=True):
    return subprocess.run(
        ["docker", *args], check=check, text=True, capture_output=True, timeout=30
    )


def request(container, address, port):
    code = (
        "import urllib.request; "
        "r=urllib.request.urlopen('http://%s:%d/', timeout=1); "
        "assert r.status == 200" % (address, port)
    )
    return docker("exec", "--user", "1000:1000", container, "python3", "-c", code, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    args = parser.parse_args()
    suffix = uuid.uuid4().hex[:12]
    network = "sandbox-review-" + suffix
    containers = []
    network_created = False
    failed = []
    try:
        docker("network", "create", "--internal", network)
        network_created = True

        def server(role, port, gateway_ip=None):
            name = network + "-" + role
            options = ["run", "-d", "--pull=never", "--name", name, "--network", network, "--user", "0:0"]
            if gateway_ip is None:
                options += ["--entrypoint", "python3", args.image, "-m", "http.server", str(port)]
            else:
                options += ["--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "-e", "GATEWAY_IP=" + gateway_ip,
                            "--entrypoint", "/bin/sh", args.image, "-c",
                            "/usr/local/bin/netlock.sh && exec python3 -m http.server " + str(port)]
            # Retain the unique name for cleanup even if Docker fails after creating it.
            containers.append(name)
            docker(*options)
            details = json.loads(docker("inspect", name).stdout)[0]
            address = details["NetworkSettings"]["Networks"][network]["IPAddress"]
            deadline = time.monotonic() + 10
            while request(name, "127.0.0.1", port).returncode:
                if time.monotonic() >= deadline:
                    raise RuntimeError("server did not start: " + name + "\n" + docker("logs", name, check=False).stderr)
                time.sleep(0.1)
            return name, address

        gateway, gateway_ip = server("gateway", 443)
        peer, peer_ip = server("peer", 8080)
        sandbox, sandbox_ip = server("sandbox", 8080, gateway_ip)

        def expect(label, source, target, port, allowed):
            result = request(source, target, port)
            # A denied request must actually fail at the network, not because the probe broke.
            reachable = result.returncode == 0
            network_failure = "timed out" in result.stderr or "Operation not permitted" in result.stderr or "Network is unreachable" in result.stderr
            passed = reachable if allowed else not reachable and network_failure
            print(("PASS " if passed else "FAIL ") + label, flush=True)
            if not passed:
                failed.append(label)
                print(result.stderr.strip(), flush=True)

        expect("fixture: gateway can reach peer", gateway, peer_ip, 8080, True)
        expect("sandbox can reach allowed gateway port", sandbox, gateway_ip, 443, True)
        expect("sandbox cannot reach peer directly", sandbox, peer_ip, 8080, False)
        expect("peer cannot initiate connections to sandbox", peer, sandbox_ip, 8080, False)
        expect("gateway can reach sandbox preview", gateway, sandbox_ip, 8080, True)
    finally:
        for name in reversed(containers):
            docker("rm", "-f", name, check=False)
        if network_created:
            docker("network", "rm", network, check=False)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
