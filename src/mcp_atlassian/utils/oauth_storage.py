from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol, SupportsFloat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from key_value.aio.protocols.key_value import AsyncKeyValue
from key_value.aio.wrappers.base import BaseWrapper

ENCRYPTION_VERSION = 1
_CIPHERTEXT_KEY = "__kms_ciphertext__"
_DATA_KEY_KEY = "__kms_encrypted_data_key__"
_NONCE_KEY = "__kms_nonce__"
_VERSION_KEY = "__kms_encryption_version__"


class KmsClient(Protocol):
    """Subset of the asynchronous KMS client used by the storage wrapper."""

    async def generate_data_key(self, **kwargs: object) -> Mapping[str, Any]: ...

    async def decrypt(self, **kwargs: object) -> Mapping[str, Any]: ...


KmsClientFactory = Callable[[], AbstractAsyncContextManager[KmsClient]]


class KmsEnvelopeEncryptionWrapper(BaseWrapper):
    """Encrypt key-value records with AES-GCM and KMS-wrapped data keys."""

    def __init__(
        self,
        key_value: AsyncKeyValue,
        *,
        kms_key_id: str,
        product: str,
        region_name: str | None = None,
        endpoint_url: str | None = None,
        kms_client_factory: KmsClientFactory | None = None,
    ) -> None:
        if not kms_key_id.strip():
            raise ValueError("kms_key_id cannot be empty")
        if not product.strip():
            raise ValueError("product cannot be empty")

        self.key_value = key_value
        self.kms_key_id = kms_key_id
        self.product = product
        self.region_name = region_name
        self.endpoint_url = endpoint_url
        self._kms_client_factory = kms_client_factory
        self._kms_session: Any = None

    def _client(self) -> AbstractAsyncContextManager[KmsClient]:
        if self._kms_client_factory is not None:
            return self._kms_client_factory()

        if self._kms_session is None:
            try:
                import aioboto3
            except ImportError as exc:
                message = (
                    "DynamoDB OAuth storage requires the "
                    "py-key-value-aio[dynamodb] dependency"
                )
                raise RuntimeError(message) from exc
            self._kms_session = aioboto3.Session(region_name=self.region_name)

        return self._kms_session.client("kms", endpoint_url=self.endpoint_url)

    def _encryption_context(self, collection: str | None, key: str) -> dict[str, str]:
        return {
            "application": "mcp-atlassian",
            "product": self.product,
            "collection": collection or "default_collection",
            "record_key": key,
        }

    @staticmethod
    def _additional_data(context: Mapping[str, str]) -> bytes:
        return json.dumps(context, sort_keys=True, separators=(",", ":")).encode()

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def _decode(value: object, field: str) -> bytes:
        if not isinstance(value, str):
            message = f"Encrypted OAuth record has invalid {field}"
            raise ValueError(message)
        return base64.b64decode(value, validate=True)

    async def _encrypt(
        self,
        value: Mapping[str, Any],
        *,
        collection: str | None,
        key: str,
    ) -> dict[str, Any]:
        plaintext = json.dumps(dict(value), separators=(",", ":")).encode()
        context = self._encryption_context(collection, key)
        async with self._client() as client:
            response = await client.generate_data_key(
                KeyId=self.kms_key_id,
                KeySpec="AES_256",
                EncryptionContext=context,
            )

        data_key = bytes(response["Plaintext"])
        encrypted_data_key = bytes(response["CiphertextBlob"])
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(
            nonce,
            plaintext,
            self._additional_data(context),
        )
        return {
            _VERSION_KEY: ENCRYPTION_VERSION,
            _DATA_KEY_KEY: self._encode(encrypted_data_key),
            _NONCE_KEY: self._encode(nonce),
            _CIPHERTEXT_KEY: self._encode(ciphertext),
        }

    async def _decrypt(
        self,
        value: dict[str, Any] | None,
        *,
        collection: str | None,
        key: str,
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        if _CIPHERTEXT_KEY not in value:
            return value
        if value.get(_VERSION_KEY) != ENCRYPTION_VERSION:
            raise ValueError("Unsupported OAuth storage encryption version")

        context = self._encryption_context(collection, key)
        encrypted_data_key = self._decode(value.get(_DATA_KEY_KEY), "data key")
        async with self._client() as client:
            response = await client.decrypt(
                CiphertextBlob=encrypted_data_key,
                EncryptionContext=context,
                KeyId=self.kms_key_id,
            )

        data_key = bytes(response["Plaintext"])
        nonce = self._decode(value.get(_NONCE_KEY), "nonce")
        ciphertext = self._decode(value.get(_CIPHERTEXT_KEY), "ciphertext")
        plaintext = AESGCM(data_key).decrypt(
            nonce,
            ciphertext,
            self._additional_data(context),
        )
        decoded = json.loads(plaintext)
        if not isinstance(decoded, dict):
            raise ValueError("Decrypted OAuth storage value must be an object")
        return decoded

    async def get(
        self,
        key: str,
        *,
        collection: str | None = None,
    ) -> dict[str, Any] | None:
        value = await self.key_value.get(key=key, collection=collection)
        return await self._decrypt(value, collection=collection, key=key)

    async def get_many(
        self,
        keys: Sequence[str],
        *,
        collection: str | None = None,
    ) -> list[dict[str, Any] | None]:
        values = await self.key_value.get_many(keys=keys, collection=collection)
        return [
            await self._decrypt(value, collection=collection, key=key)
            for key, value in zip(keys, values, strict=True)
        ]

    async def ttl(
        self,
        key: str,
        *,
        collection: str | None = None,
    ) -> tuple[dict[str, Any] | None, float | None]:
        value, ttl = await self.key_value.ttl(key=key, collection=collection)
        return await self._decrypt(value, collection=collection, key=key), ttl

    async def ttl_many(
        self,
        keys: Sequence[str],
        *,
        collection: str | None = None,
    ) -> list[tuple[dict[str, Any] | None, float | None]]:
        values = await self.key_value.ttl_many(keys=keys, collection=collection)
        return [
            (await self._decrypt(value, collection=collection, key=key), ttl)
            for key, (value, ttl) in zip(keys, values, strict=True)
        ]

    async def put(
        self,
        key: str,
        value: Mapping[str, Any],
        *,
        collection: str | None = None,
        ttl: SupportsFloat | None = None,
    ) -> None:
        encrypted = await self._encrypt(value, collection=collection, key=key)
        await self.key_value.put(
            key=key,
            value=encrypted,
            collection=collection,
            ttl=ttl,
        )

    async def put_many(
        self,
        keys: Sequence[str],
        values: Sequence[Mapping[str, Any]],
        *,
        collection: str | None = None,
        ttl: SupportsFloat | None = None,
    ) -> None:
        if len(keys) != len(values):
            raise ValueError("keys and values must contain the same number of items")
        encrypted = [
            await self._encrypt(value, collection=collection, key=key)
            for key, value in zip(keys, values, strict=True)
        ]
        await self.key_value.put_many(
            keys=keys,
            values=encrypted,
            collection=collection,
            ttl=ttl,
        )


__all__ = ["KmsEnvelopeEncryptionWrapper"]
