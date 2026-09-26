"""Assessment-plane extensions (Phase 13): container & IaC posture adapters.

Two adapters that close the cloud/container gap without touching the design
laws. Both audit files/runtime the operator ALREADY possesses on their own
machine:

  * :class:`DockerAuditAdapter` — ``docker-audit``: local container-runtime
    posture (running containers, exposed daemon sockets, published ports)
    using ``docker`` in read-only inspection modes only. No container is
    started, stopped, pulled or built; no registry is contacted.
  * :class:`IacAuditAdapter`   — ``iac-audit``: offline IaC posture audit
    (trivy config for Dockerfile/compose/K8s/Terraform). The file already
    sits on the operator's disk; nothing is uploaded, nothing is built, and
    ``--scanners config`` is pinned so no CVE database download or image
    pull can ever be triggered by a param.

The two remaining Phase 13 planes are deliberately NOT argv adapters (the
no-fake-adapter law forbids inventing an argv for an in-process capability):

  * credentialed authenticated auditing → :mod:`rebel_profiler.intel.auth_audit`
    (``web-auth-audit`` resolves the CredentialBroker secret in-process;
    the secret never crosses a process boundary, never reaches argv,
    never reaches stdout),
  * loopback recording proxy → :mod:`rebel_profiler.intel.traffic_proxy`
    (``traffic-proxy`` is a stdlib http.server bound to 127.0.0.1;
    observe-only, never a forwarder).

Both in-process planes register hash-chained evidence and honor scope,
exactly like every adapter result. Neither can be proposed to the broker:
the planner reaches them through their own CLI/agent surfaces.
"""

from __future__ import annotations

from .adapters import _single_token
from .broker import ActionRequest, Adapter

_PATH = r"/?[A-Za-z0-9][A-Za-z0-9._/@+-]{2,300}"


class DockerAuditAdapter(Adapter):
    """Local container-runtime posture audit (docker, read-only modes only).

    One fixed, whitelisted invocation: ``docker ps -a --no-trunc --format …``
    (optionally against an explicit unix socket path). The parser turns the
    pipe-delimited rows into container claims. There is deliberately no
    param that could start, stop, exec, pull, build or remove anything.
    """

    name = "docker-audit"
    binary = "docker"
    capability_class = "config_assessment"
    allowed_params = ("socket",)
    required_params = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        argv = [self.binary]
        socket_param = request.params.get("socket")
        if socket_param is not None:
            sock = _single_token(socket_param, field="socket", pattern=_PATH)
            argv += ["-H", f"unix://{sock}"]
        argv += ["ps", "-a", "--no-trunc", "--format",
                 "{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}|{{.Ports}}"]
        return argv


class IacAuditAdapter(Adapter):
    """Offline IaC posture audit (trivy config; Dockerfile/compose/K8s/IaC).

    The target is a FILE PATH the operator owns — the scope engine treats it
    like the RE plane's sample paths. trivy reads it and prints
    misconfigurations (root users, added capabilities, host mounts, plaintext
    secret patterns, missing resource limits). Nothing is uploaded, nothing
    is built, nothing is executed; ``--offline-scan`` keeps it fully local.
    """

    name = "iac-audit"
    binary = "trivy"
    capability_class = "config_assessment"
    allowed_params = ("severity",)
    required_params = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        path = _single_token(request.target, field="path", pattern=_PATH)
        argv = [self.binary, "config", "--quiet", "--scanners", "config",
                "--format", "json", "--offline-scan"]
        severity = request.params.get("severity")
        if severity is not None:
            severity = _single_token(severity, field="severity",
                                     pattern=r"(?i)(unknown|low|medium|high|critical)")
            argv += ["--severity", severity.upper()]
        argv += [path]
        return argv


# The in-process plane names, exported as constants so knowledge surfaces can
# reference them without pretending an argv adapter exists.
WEB_AUTH_AUDIT_ACTION = "web-auth-audit"
TRAFFIC_PROXY_ACTION = "traffic-proxy"

AUDIT_EXT_ADAPTERS: tuple[type[Adapter], ...] = (
    DockerAuditAdapter,
    IacAuditAdapter,
)
