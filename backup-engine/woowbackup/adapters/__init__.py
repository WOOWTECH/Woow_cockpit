"""Trusted adapters shipped with the engine. Archives can never supply adapter code."""


def _registry():
    from .quadlet_postgres import QuadletPostgresAdapter
    return {QuadletPostgresAdapter.name: QuadletPostgresAdapter}


def get_adapter(name):
    """Adapter class registered under `name`, or None."""
    return _registry().get(name)


def adapter_names():
    return sorted(_registry())
