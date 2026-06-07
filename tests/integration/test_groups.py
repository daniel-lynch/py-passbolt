import unittest
import os
import pytest
from passbolt.passbolt import passbolt

if not os.environ.get('keypath'):
    pytest.skip(
        "integration tests require a live Passbolt instance "
        "(set keypath, passphrase and uri env vars)",
        allow_module_level=True,
    )

key = open(os.environ.get('keypath'), "r").read()
passphrase = os.environ.get('passphrase')
uri = os.environ.get('uri')

Passbolt = passbolt(key, passphrase, uri)

class TestPasswordMethods(unittest.TestCase):

    def test_0_creategroup(self):
        group = Passbolt.creategroup("pytest", ["daniel.lynch2016@gmail.com"], ["doghouse475@gmail.com"])
        self.assertEqual(group, "The group has been added successfully.")

    def test_1_getgroup(self):
        group = Passbolt.getgroup("pytest")
        self.assertEqual(group.name, "pytest")

    def test_2_updategroup(self):
        group = Passbolt.updategroup("pytest", ["s1@a.com"], ["s2@a.com"])
        self.assertEqual(group, "The operation was successful.")

    def test_3_deletegroup(self):
        group = Passbolt.deletegroup("pytest")
        self.assertEqual(group, "The group was deleted successfully.")


if __name__ == '__main__':
    unittest.main()