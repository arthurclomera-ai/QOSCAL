"""
Deterministic UUID helpers for OSCAL document generation.

All recurring OSCAL entities (findings, risks, observations, hosts) receive
UUIDv5 identifiers so that re-running the generator from the same QVD data
produces the same UUIDs — enabling idempotent updates and diff-friendly output.

Document-level UUIDs (the POA&M root itself) are random (UUIDv4) so each
generation run produces a distinct document revision.
"""

import uuid

# Fixed namespace UUID for the CLaaS project.
# UUIDv5 is computed as SHA-1(CLAAS_NAMESPACE + seed), so as long as this
# namespace stays constant, identical seeds always produce identical UUIDs.
CLAAS_NAMESPACE = uuid.UUID("9c3a4a7e-b8f5-5a9d-8e1c-2d4f6b7c8e9a")


def det_uuid(seed: str) -> str:
    """Return a deterministic UUIDv5 string derived from *seed*.

    Args:
        seed: A unique, stable string that identifies the OSCAL object,
              e.g. ``"obs:10.0.0.1:22869"`` or ``"risk:22869"``.

    Returns:
        Lowercase hyphenated UUID string, e.g. ``"550e8400-e29b-41d4-a716-..."``.
    """
    return str(uuid.uuid5(CLAAS_NAMESPACE, seed))


def rand_uuid() -> str:
    """Return a random UUIDv4 string for document-root identifiers."""
    return str(uuid.uuid4())
