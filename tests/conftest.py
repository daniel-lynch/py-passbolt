"""
Shared fixtures for the mock-based unit tests.

These tests need no Passbolt instance: the HTTP layer is mocked with
requests-mock and a throwaway GPG keypair (in an isolated GNUPGHOME) is used
for the real encrypt/decrypt that the client performs.
"""
import os
from urllib.parse import quote

import gnupg
import pytest
import requests

import passbolt.passbolt as passbolt_mod
from passbolt.passbolt import passbolt

PASSPHRASE = "testpass"
BASE = "https://passbolt.test"

OWNER_ID = "11111111-1111-4111-8111-111111111111"
RECIPIENT_ID = "22222222-2222-4222-8222-222222222222"
RESOURCE_ID = "33333333-3333-4333-8333-333333333333"
TYPE_PAD_ID = "669f8c64-242a-59fb-92fc-81f660975fd3"  # password-and-description
TYPE_STRING_ID = "a28a04cd-6f53-518a-967c-9963bf9ccab2"  # password-string


@pytest.fixture(scope="session")
def gpg_env(tmp_path_factory):
    """Isolated GNUPGHOME with an 'owner' and a 'recipient' keypair."""
    home = tmp_path_factory.mktemp("gnupg")
    os.chmod(home, 0o700)
    os.environ["GNUPGHOME"] = str(home)
    gpg = gnupg.GPG(gnupghome=str(home))

    def mkkey(email):
        params = gpg.gen_key_input(
            name_real=email, name_email=email, passphrase=PASSPHRASE,
            key_type="RSA", key_length=2048,
        )
        key = gpg.gen_key(params)
        fp = str(key)
        return {
            "fingerprint": fp,
            "pub": gpg.export_keys(fp),
            "priv": gpg.export_keys(fp, True, passphrase=PASSPHRASE),
        }

    return {
        "gpg": gpg,
        "owner": mkkey("owner@example.com"),
        "recipient": mkkey("recipient@example.com"),
    }


@pytest.fixture
def client(gpg_env, requests_mock, monkeypatch):
    """A logged-in passbolt client wired to the mocked API."""
    owner = gpg_env["owner"]

    # requests-mock populates response.cookies but not the session jar, while
    # the login flow reads session.cookies["csrfToken"]. Give the client a
    # session that already carries the CSRF cookie; requests-mock still
    # intercepts its HTTP calls.
    seeded = requests.Session()
    seeded.cookies.set("csrfToken", "testcsrf")
    monkeypatch.setattr(passbolt_mod.requests, "session", lambda: seeded)

    # The login flow reads an encrypted token from a response header and
    # decrypts it with our key, so encrypt a token to the owner's key.
    enc = gpg_env["gpg"].encrypt(
        "gpgauthv1.3.0|36|token|gpgauthv1.3.0",
        owner["fingerprint"], always_trust=True,
    )
    requests_mock.post(
        f"{BASE}/auth/login.json",
        headers={"X-GPGAuth-User-Auth-Token": quote(str(enc))},
        json={
            "header": {"message": "You are successfully logged in."},
            "body": {
                "profile": {"user_id": OWNER_ID},
                "gpgkey": {"fingerprint": owner["fingerprint"]},
            },
        },
    )
    # CSRF bootstrap GET (default; tests re-register /resources.json as needed).
    requests_mock.get(
        f"{BASE}/resources.json",
        headers={"Set-Cookie": "csrfToken=testcsrf"},
        json={"header": {}, "body": []},
    )

    return passbolt(owner["priv"], PASSPHRASE, BASE)


def make_resource(resource_type_id=TYPE_PAD_ID):
    """A minimal resource dict as returned by GET /resources.json."""
    return {
        "id": RESOURCE_ID,
        "name": "example",
        "username": "owner",
        "uri": "https://example.com",
        "description": "a description",
        "resource_type_id": resource_type_id,
        "created": "2020-01-01T00:00:00+00:00",
        "created_by": OWNER_ID,
        "modified": "2020-01-01T00:00:00+00:00",
        "modified_by": OWNER_ID,
        "deleted": None,
    }
