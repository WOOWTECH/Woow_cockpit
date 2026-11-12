"""Trusted adapters shipped with the engine. Archives can never supply adapter code."""
ADAPTERS = {}


def get_adapter(name):
    from .quadlet_postgres import QuadletPostgresAdapter
    registry = {QuadletPostgresAdapter.name: QuadletPostgresAdapter}
    return registry.get(name)
