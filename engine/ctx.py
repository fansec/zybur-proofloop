# rules/engine/ctx.py
"""Services container passed to every executor plugin."""
from dataclasses import dataclass

@dataclass
class Ctx:
    cfg: dict
    caldera: object = None        # CalderaClient
    winrm_factory: object = None  # callable() -> winrm.Session
    dedup: object = None          # DedupAllocator
    firewall: object = None       # FirewallService
    listener: object = None       # KerberosListener
