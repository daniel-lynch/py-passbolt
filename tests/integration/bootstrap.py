#!/usr/bin/env python3
"""
Bootstrap an ephemeral Passbolt instance for integration testing.

Registers two users and completes their account setup programmatically (the
step the browser extension normally performs): generate a GPG keypair, then
POST the armored public key to /setup/complete/{user_id}.json.

Writes private keys + an accounts.json manifest to the artifacts dir, which the
e2e test (tests/integration/test_e2e.py) consumes.

Env:
  PASSBOLT_BASE_URL   default http://localhost:8080
  PASSBOLT_ARTIFACTS  default <this dir>/.artifacts
  PASSBOLT_COMPOSE    default <this dir>/compose.yml
"""
import json
import os
import re
import subprocess
import sys

import gnupg
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
BASE_URL = os.environ.get("PASSBOLT_BASE_URL", "http://localhost:8080")
ARTIFACTS = os.environ.get("PASSBOLT_ARTIFACTS", os.path.join(HERE, ".artifacts"))
COMPOSE = os.environ.get("PASSBOLT_COMPOSE", os.path.join(HERE, "compose.yml"))
PASSPHRASE = "testpassphrase"

# (email, first, last, role)
USERS = [
    ("ada@example.com", "Ada", "Lovelace", "admin"),
    ("bob@example.com", "Bob", "Tester", "user"),
]


def register_user(email, first, last, role):
    """Run register_user in the container; return (user_id, token)."""
    cmd = (
        "/usr/share/php/passbolt/bin/cake passbolt register_user "
        f"-u {email} -f {first} -l {last} -r {role}"
    )
    out = subprocess.run(
        ["docker", "compose", "-f", COMPOSE, "exec", "-T", "passbolt",
         "su", "-m", "-c", cmd, "-s", "/bin/sh", "www-data"],
        capture_output=True, text=True,
    )
    blob = out.stdout + out.stderr
    m = re.search(r"/setup/(?:install|start)/([0-9a-f-]{36})/([0-9a-f-]{36})", blob)
    if not m:
        raise RuntimeError(f"could not parse setup URL for {email}:\n{blob}")
    return m.group(1), m.group(2)


def make_key(gpg, email, first, last):
    params = gpg.gen_key_input(
        name_real=f"{first} {last}", name_email=email, passphrase=PASSPHRASE,
        key_type="RSA", key_length=3072,
    )
    key = gpg.gen_key(params)
    pub = gpg.export_keys(str(key))
    priv = gpg.export_keys(str(key), True, passphrase=PASSPHRASE)
    return pub, priv


def complete_setup(user_id, token, armored_pub):
    body = {
        "authenticationtoken": {"token": token},
        "gpgkey": {"armored_key": armored_pub},
    }
    r = requests.post(
        f"{BASE_URL}/setup/complete/{user_id}.json?api-version=v2",
        json=body, headers={"Content-Type": "application/json"},
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"setup complete failed ({r.status_code}): {r.text}")


def main():
    os.makedirs(ARTIFACTS, exist_ok=True)
    gpg_home = os.path.join(ARTIFACTS, "gnupg")
    os.makedirs(gpg_home, exist_ok=True)
    os.chmod(gpg_home, 0o700)
    gpg = gnupg.GPG(gnupghome=gpg_home)

    users = {}
    for email, first, last, role in USERS:
        print(f"==> registering {email} ({role})")
        user_id, token = register_user(email, first, last, role)
        pub, priv = make_key(gpg, email, first, last)
        complete_setup(user_id, token, pub)
        priv_path = os.path.join(ARTIFACTS, f"{email}.priv.asc")
        with open(priv_path, "w") as fh:
            fh.write(priv)
        users[email] = {"user_id": user_id, "priv": priv_path, "role": role}
        print(f"    setup complete -> {priv_path}")

    manifest = os.path.join(ARTIFACTS, "accounts.json")
    with open(manifest, "w") as fh:
        json.dump(
            {"base_url": BASE_URL, "passphrase": PASSPHRASE, "users": users},
            fh, indent=2,
        )
    print(f"\nWrote manifest: {manifest}")


if __name__ == "__main__":
    sys.exit(main())
