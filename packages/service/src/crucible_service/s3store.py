"""The journal on S3 (docs/phase0-deployment.md, "Write-once journal").

The store's one write is ``PutObject`` with ``If-None-Match: *``: S3 creates the
key only if it does not exist, and answers 412 otherwise, which is the
create-if-absent rule `journal.ObjectStore` asks for. The bucket is under
Object Lock (governance mode), so nothing the service writes can be deleted or
overwritten while its retention lasts.

**Startup is a check** (`check_write_once`): the bucket must report Object Lock
enabled with a default retention rule (governance or compliance mode, for a
period), so every object the service creates is retained without the service
asking; and its version listing must hold exactly one version of each key and
no delete marker. A second version or a delete marker means something
was removed or overwritten -- under governance mode only an administrator's
explicit bypass can do that -- and the service refuses to start rather than
serve a log whose tail may have been cut (``log.py``, "What startup cannot
see").
"""

from __future__ import annotations

import base64
import time

from .journal import JournalError, check_key


def _client():
    import boto3

    return boto3.client("s3")


class S3Store:
    """An `ObjectStore` on one S3 bucket (and an optional key prefix)."""

    def __init__(self, bucket: str, *, prefix: str = "", client=None) -> None:
        self.bucket = bucket
        self.prefix = prefix
        self.client = client or _client()

    @property
    def identity(self) -> str:
        """Which journal this is, as a genesis claim records it."""
        return f"s3://{self.bucket}/{self.prefix}"

    def _key(self, key: str) -> str:
        return self.prefix + check_key(key)

    def create(self, key: str, data: bytes) -> bool:
        from botocore.exceptions import BotoCoreError, ClientError

        for attempt in range(5):
            try:
                self.client.put_object(
                    Bucket=self.bucket, Key=self._key(key), Body=data, IfNoneMatch="*",
                    ChecksumAlgorithm="SHA256",  # Object Lock buckets refuse a PUT without an integrity checksum
                )
                return True
            except ClientError as exc:
                status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
                code = exc.response.get("Error", {}).get("Code")
                if status == 412 or code == "PreconditionFailed":
                    return False  # it exists: another process created it first
                if status == 409 or code == "ConditionalRequestConflict":
                    time.sleep(0.05 * (attempt + 1))  # a create of the same key is in flight; it decides
                    continue
                raise JournalError(f"cannot create {key}: {code}: {exc}") from exc
            except BotoCoreError as exc:
                raise JournalError(f"cannot create {key}: {exc}") from exc
        raise JournalError(f"cannot create {key}: concurrent creates kept conflicting")

    def get(self, key: str) -> bytes | None:
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            resp = self.client.get_object(Bucket=self.bucket, Key=self._key(key))
            return resp["Body"].read()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                return None
            raise JournalError(f"cannot read {key}: {exc}") from exc
        except BotoCoreError as exc:
            raise JournalError(f"cannot read {key}: {exc}") from exc

    def list(self, prefix: str) -> list[str]:
        from botocore.exceptions import BotoCoreError, ClientError

        keys = []
        try:
            for page in self.client.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=self.prefix + prefix):
                keys += [o["Key"][len(self.prefix):] for o in page.get("Contents", [])]
        except (ClientError, BotoCoreError) as exc:
            raise JournalError(f"cannot list {prefix}: {exc}") from exc
        return sorted(keys)

    def _lock(self) -> dict:
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            return self.client.get_object_lock_configuration(Bucket=self.bucket)["ObjectLockConfiguration"]
        except (ClientError, BotoCoreError, KeyError) as exc:
            raise JournalError(f"cannot read the Object Lock configuration of {self.bucket}: {exc}") from exc

    def object_sha256(self, bucket: str, key: str) -> str | None:
        """The full-object SHA-256 S3 holds for ``bucket/key`` (S3 checked it against the bytes when
        they were stored), as ``sha256:<hex>``, or None if it holds none: what genesis compares with
        leaf 0's statement of the archive's digest."""
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            head = self.client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
        except (ClientError, BotoCoreError) as exc:
            raise JournalError(f"cannot read s3://{bucket}/{key}: {exc}") from exc
        value = head.get("ChecksumSHA256")
        if not isinstance(value, str) or head.get("ChecksumType", "FULL_OBJECT") != "FULL_OBJECT" or "-" in value:
            return None  # none, or a multipart upload's checksum of its parts' checksums
        return "sha256:" + base64.b64decode(value).hex()

    def default_retention(self) -> dict | None:
        """The bucket's default Object Lock rule as S3 gives it (e.g. {"Mode": "GOVERNANCE", "Years": 10}),
        or None: what genesis compares with leaf 0's statement of it."""
        lock = self._lock()
        if lock.get("ObjectLockEnabled") != "Enabled":
            return None
        return (lock.get("Rule") or {}).get("DefaultRetention") or None

    def check_write_once(self) -> None:
        """Refuse a bucket that is not write-once, or that shows something removed or overwritten."""
        from botocore.exceptions import BotoCoreError, ClientError

        lock = self._lock()
        if lock.get("ObjectLockEnabled") != "Enabled":
            raise JournalError(f"{self.bucket} does not have Object Lock enabled; the journal must be write-once")
        rule = (lock.get("Rule") or {}).get("DefaultRetention") or {}
        period = [rule.get(k) for k in ("Days", "Years") if isinstance(rule.get(k), int) and not isinstance(rule.get(k), bool)]
        if rule.get("Mode") not in ("GOVERNANCE", "COMPLIANCE") or not period or min(period) <= 0:
            raise JournalError(f"{self.bucket} has no default Object Lock retention (a mode and a period); "
                               "a leaf written there could be deleted, so the journal would not be write-once")
        seen: set[str] = set()
        try:
            for page in self.client.get_paginator("list_object_versions").paginate(Bucket=self.bucket, Prefix=self.prefix):
                if page.get("DeleteMarkers"):
                    raise JournalError(f"{self.bucket} holds a delete marker ({page['DeleteMarkers'][0]['Key']}); "
                                       "something was removed from the journal")
                for v in page.get("Versions", []):
                    if v["Key"] in seen:
                        raise JournalError(f"{v['Key']} has more than one version; the journal was overwritten")
                    seen.add(v["Key"])
        except (ClientError, BotoCoreError) as exc:
            raise JournalError(f"cannot list the versions in {self.bucket}: {exc}") from exc


__all__ = ["S3Store"]
