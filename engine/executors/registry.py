# rules/engine/executors/registry.py
"""Executor plugin registry: name -> handler(usecase, ctx) -> Result."""
REGISTRY = {}

def register(name):
    def deco(fn):
        REGISTRY[name] = fn
        return fn
    return deco

def get(name):
    if name not in REGISTRY:
        raise KeyError(f"unknown executor {name!r} (known: {sorted(REGISTRY)})")
    return REGISTRY[name]

def executor_names():
    return set(REGISTRY)
