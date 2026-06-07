"""
Mock-based unit tests — no Passbolt instance required.

Focus: the two fixed bugs (#10 updatepassword, #8 share-with-user) plus
create/get basics. The HTTP layer is mocked; encryption is real.
"""
import json

import pytest

from conftest import (
    BASE, PASSPHRASE, OWNER_ID, RECIPIENT_ID, RESOURCE_ID,
    TYPE_PAD_ID, TYPE_STRING_ID, make_resource,
)

RESOURCE_TYPES = [
    {"slug": "password-and-description", "id": TYPE_PAD_ID},
    {"slug": "password-string", "id": TYPE_STRING_ID},
]


def aro(gpg_env, who, user_id, username):
    key = gpg_env[who]
    return {
        "id": user_id,
        "username": username,
        "gpgkey": {
            "user_id": user_id,
            "armored_key": key["pub"],
            "fingerprint": key["fingerprint"],
        },
    }


def last_request(requests_mock, method):
    for req in reversed(requests_mock.request_history):
        if req.method == method:
            return req
    raise AssertionError(f"no {method} request was made")


def test_createpassword_sets_type_and_json_secret(client, gpg_env, requests_mock):
    requests_mock.get(f"{BASE}/resource-types.json", json={"body": RESOURCE_TYPES})
    requests_mock.post(
        f"{BASE}/resources.json",
        json={"header": {"message": "The resource has been added successfully."}},
    )

    msg = client.createpassword("example", "pw", "owner", "https://x.com", "desc")
    assert msg == "The resource has been added successfully."

    body = last_request(requests_mock, "POST").json()
    assert body["resource_type_id"] == TYPE_PAD_ID
    secret = gpg_env["gpg"].decrypt(body["secrets"][0]["data"], passphrase=PASSPHRASE)
    assert json.loads(str(secret)) == {"password": "pw", "description": "desc"}


@pytest.mark.parametrize("encrypt_description", [True, False])
def test_updatepassword_always_sends_resource_type_id(
    client, gpg_env, requests_mock, encrypt_description
):
    """Regression for issue #10: resource_type_id must always be present."""
    requests_mock.get(f"{BASE}/resources.json", json={"body": [make_resource()]})
    requests_mock.get(
        f"{BASE}/permissions/resource/{RESOURCE_ID}.json",
        json={"body": [{"aro": "User", "aro_foreign_key": OWNER_ID}]},
    )
    requests_mock.get(
        f"{BASE}/share/search-aros.json",
        json={"body": [aro(gpg_env, "owner", OWNER_ID, "owner@example.com")]},
    )
    requests_mock.get(f"{BASE}/resource-types.json", json={"body": RESOURCE_TYPES})
    requests_mock.put(
        f"{BASE}/resources/{RESOURCE_ID}.json",
        json={"header": {"message": "The resource has been updated successfully."}},
    )

    msg = client.updatepassword(
        "example", "newpw", "owner",
        description="newdesc", encrypt_description=encrypt_description,
    )
    assert msg == "The resource has been updated successfully."

    body = last_request(requests_mock, "PUT").json()
    assert body.get("resource_type_id"), "resource_type_id missing from update payload"


def _setup_share(client, gpg_env, requests_mock, resource_type_id, slug, secret_data):
    requests_mock.get(f"{BASE}/resources.json", json={"body": [make_resource(resource_type_id)]})
    requests_mock.get(
        f"{BASE}/resource-types/{resource_type_id}.json",
        json={"body": {"slug": slug, "id": resource_type_id}},
    )
    requests_mock.get(
        f"{BASE}/secrets/resource/{RESOURCE_ID}.json",
        json={"body": {"data": secret_data}},
    )
    requests_mock.get(
        f"{BASE}/share/search-aros.json",
        json={"body": [
            aro(gpg_env, "owner", OWNER_ID, "owner@example.com"),
            aro(gpg_env, "recipient", RECIPIENT_ID, "recipient@example.com"),
        ]},
    )
    requests_mock.post(f"{BASE}/share/simulate/resource/{RESOURCE_ID}.json", json={})
    requests_mock.put(
        f"{BASE}/share/resource/{RESOURCE_ID}.json",
        json={"header": {"message": "The operation was successful."}},
    )


def _recipient_secret(requests_mock):
    body = last_request(requests_mock, "PUT").json()
    for secret in body["secrets"]:
        if secret["user_id"] == RECIPIENT_ID:
            return secret["data"]
    raise AssertionError("no secret was encrypted for the recipient")


def test_sharepassword_user_gets_json_secret(client, gpg_env, requests_mock):
    """Regression for issue #8: encrypted-description resources must share the JSON blob."""
    enc = str(gpg_env["gpg"].encrypt(
        json.dumps({"password": "pw", "description": "desc"}),
        gpg_env["owner"]["fingerprint"], always_trust=True,
    ))
    _setup_share(client, gpg_env, requests_mock, TYPE_PAD_ID, "password-and-description", enc)

    msg = client.sharepassword("example", "owner", users=["recipient@example.com"])
    assert msg == "The operation was successful."

    data = _recipient_secret(requests_mock)
    decrypted = str(gpg_env["gpg"].decrypt(data, passphrase=PASSPHRASE))
    # The recipient must receive parseable JSON, not a bare password string.
    assert json.loads(decrypted) == {"password": "pw", "description": "desc"}


def test_sharepassword_user_plaintext_type_gets_raw_secret(client, gpg_env, requests_mock):
    """The other branch: a password-string resource shares the raw password."""
    enc = str(gpg_env["gpg"].encrypt(
        "pw", gpg_env["owner"]["fingerprint"], always_trust=True,
    ))
    _setup_share(client, gpg_env, requests_mock, TYPE_STRING_ID, "password-string", enc)

    client.sharepassword("example", "owner", users=["recipient@example.com"])

    data = _recipient_secret(requests_mock)
    decrypted = str(gpg_env["gpg"].decrypt(data, passphrase=PASSPHRASE))
    assert decrypted == "pw"


def test_sharepassword_requires_user_or_group(client):
    with pytest.raises(ValueError):
        client.sharepassword("example", "owner", users=[], groups=[])
