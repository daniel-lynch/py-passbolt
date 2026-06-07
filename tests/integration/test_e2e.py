"""
Self-contained end-to-end tests against an ephemeral Passbolt instance.

Unlike test_password/users/groups.py (which assume a pre-populated instance),
these bootstrap their own users via tests/integration/bootstrap.py and exercise
the real API — including regressions for issues #8 and #10.

Skipped unless an accounts manifest exists (PASSBOLT_E2E_ACCOUNTS, or the
default .artifacts/accounts.json produced by bootstrap.py).
"""
import json
import os
import uuid

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.environ.get(
    "PASSBOLT_E2E_ACCOUNTS", os.path.join(HERE, ".artifacts", "accounts.json")
)

if not os.path.exists(MANIFEST):
    pytest.skip(
        f"no accounts manifest at {MANIFEST}; run bootstrap.py against an "
        "ephemeral instance first",
        allow_module_level=True,
    )

# Isolate the keyring before the library builds its GPG object.
os.environ.setdefault("GNUPGHOME", os.path.join(HERE, ".artifacts", "gnupg-test"))
os.makedirs(os.environ["GNUPGHOME"], mode=0o700, exist_ok=True)

from passbolt.passbolt import passbolt  # noqa: E402

ACCT = json.load(open(MANIFEST))


def _client(email):
    key = open(ACCT["users"][email]["priv"]).read()
    return passbolt(key, ACCT["passphrase"], ACCT["base_url"])


@pytest.fixture(scope="module")
def ada():
    return _client("ada@example.com")


@pytest.fixture(scope="module")
def bob():
    return _client("bob@example.com")


@pytest.fixture
def resource_name(ada):
    name = f"e2e-{uuid.uuid4().hex[:8]}"
    yield name
    try:
        ada.deletepassword(name)
    except Exception:
        pass


def test_password_lifecycle(ada, resource_name):
    assert ada.createpassword(
        resource_name, "s3cret", "ada", "https://x.com", "desc"
    ) == "The resource has been added successfully."

    pw = ada.getpassword(resource_name, "ada")[0]
    assert pw.password == "s3cret"
    assert pw.description == "desc"

    assert ada.updatepassword(
        resource_name, "new", "ada", description="newdesc"
    ) == "The resource has been updated successfully."

    assert ada.getpassword(resource_name, "ada")[0].password == "new"


def test_update_cleartext_description(ada, resource_name):
    """Regression for #10: update must succeed for non-encrypted descriptions."""
    ada.createpassword(
        resource_name, "s3cret", "ada", "https://x.com", "clear",
        encrypt_description=False,
    )
    assert ada.updatepassword(
        resource_name, "new", "ada", description="newclear",
        encrypt_description=False,
    ) == "The resource has been updated successfully."


@pytest.mark.parametrize("encrypt_description", [True, False])
def test_share_with_user(ada, bob, resource_name, encrypt_description):
    """Regression for #8: a user shared with directly can read the secret."""
    ada.createpassword(
        resource_name, "shared-pw", "ada", "https://x.com", "shared-desc",
        encrypt_description=encrypt_description,
    )
    assert ada.sharepassword(
        resource_name, "ada", ["bob@example.com"], []
    ) == "The operation was successful."

    pw = bob.getpassword(resource_name, "ada")[0]
    assert pw.password == "shared-pw"
    assert pw.description == "shared-desc"
