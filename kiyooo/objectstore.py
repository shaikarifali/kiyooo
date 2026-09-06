"""MinIO/S3-compatible object store client factory.

Raw recon evidence — HTTP response bodies, screenshots, full scanner JSON —
lives here, not in Postgres. Only its metadata and content hash go in the
`evidence` table (`db/models.py`); see `recon/orchestrator.py`'s
`EvidenceWriter` for the inline-vs-object-store split.
"""

from __future__ import annotations

from minio import Minio

from kiyooo.config import Settings


def make_minio_client(settings: Settings) -> Minio:
    return Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure,
    )


def ensure_bucket(client: Minio, bucket: str) -> None:
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)
