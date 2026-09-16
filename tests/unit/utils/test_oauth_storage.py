"""Tests for AWS-backed browser OAuth storage."""

from __future__ import annotations

import json
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from key_value.aio.stores.memory import MemoryStore

from mcp_atlassian.utils.oauth_storage import KmsEnvelopeEncryptionWrapper


class FakeKmsClient:
    """Small asynchronous KMS fake that records encryption contexts."""

    def __init__(self) -> None:
        self.data_key = b"k" * 32
        self.generate_contexts: list[dict[str, str]] = []
        self.decrypt_contexts: list[dict[str, str]] = []

    async def generate_data_key(self, **kwargs: object) -> dict[str, Any]:
        context = kwargs["EncryptionContext"]
        assert isinstance(context, dict)
        self.generate_contexts.append(context)
        return {
            "Plaintext": self.data_key,
            "CiphertextBlob": b"kms-wrapped-data-key",
        }

    async def decrypt(self, **kwargs: object) -> dict[str, Any]:
        context = kwargs["EncryptionContext"]
        assert isinstance(context, dict)
        self.decrypt_contexts.append(context)
        return {"Plaintext": self.data_key}


class FakeKmsContext:
    def __init__(self, client: FakeKmsClient) -> None:
        self.client = client

    async def __aenter__(self) -> FakeKmsClient:
        return self.client

    async def __aexit__(self, *args: object) -> None:
        return None


def _build_storage(
    store: MemoryStore,
    kms: FakeKmsClient,
) -> KmsEnvelopeEncryptionWrapper:
    return KmsEnvelopeEncryptionWrapper(
        store,
        kms_key_id="alias/mcp-oauth",
        product="jira",
        kms_client_factory=lambda: FakeKmsContext(kms),
    )


@pytest.mark.asyncio
async def test_kms_storage_encrypts_token_record_and_preserves_ttl():
    store = MemoryStore()
    kms = FakeKmsClient()
    storage = _build_storage(store, kms)
    record = {
        "access_token": "access-secret",
        "refresh_token": "refresh-secret",
        "expires_at": 1_800_000_000,
        "user_info": {"name": "test-user", "displayName": "Test User"},
    }

    await storage.put(
        "token-id",
        record,
        collection="mcp-upstream-tokens",
        ttl=300,
    )

    raw = await store.get("token-id", collection="mcp-upstream-tokens")
    assert raw is not None
    assert "access-secret" not in json.dumps(raw)
    assert "refresh-secret" not in json.dumps(raw)

    restored, ttl = await storage.ttl(
        "token-id",
        collection="mcp-upstream-tokens",
    )
    assert restored == record
    assert ttl is not None
    assert 0 < ttl <= 300
    expected_context = {
        "application": "mcp-atlassian",
        "product": "jira",
        "collection": "mcp-upstream-tokens",
        "record_key": "token-id",
    }
    assert kms.generate_contexts == [expected_context]
    assert kms.decrypt_contexts == [expected_context]


@pytest.mark.asyncio
async def test_kms_storage_rejects_ciphertext_moved_to_another_key():
    store = MemoryStore()
    kms = FakeKmsClient()
    storage = _build_storage(store, kms)
    await storage.put(
        "original",
        {"access_token": "secret"},
        collection="mcp-upstream-tokens",
    )
    raw = await store.get("original", collection="mcp-upstream-tokens")
    assert raw is not None
    await store.put("replayed", raw, collection="mcp-upstream-tokens")

    with pytest.raises(InvalidTag):
        await storage.get("replayed", collection="mcp-upstream-tokens")
