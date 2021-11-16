import unittest
import os
from passbolt.passbolt import passbolt

key = open(os.environ.get('keypath'), "r").read()
passphrase = os.environ.get('passphrase')
uri = os.environ.get('uri')

Passbolt = passbolt(key, passphrase, uri)

class TestPasswordMethods(unittest.TestCase):

    def test_0_createpassword(self):
        password = Passbolt.createpassword("pytesting", "asdf", "pytesting", "testing.com", "pytesting")
        self.assertEqual(password, "The resource has been added successfully.")

    def test_1_getpassword(self):
        password = Passbolt.getpassword("pytesting", "pytesting")
        self.assertEqual(password[0].name, "pytesting")

    def test_2_sharepassword(self):
        password = Passbolt.sharepassword("pytesting", "pytesting", ["s1@a.com"], ["Users"])
        self.assertEqual(password, "The operation was successful.")

    def test_3_updatepassword(self):
        password = Passbolt.updatepassword("pytesting", "asdf1", "pytesting", "pytesting1", "pytesting1", "testing2.com", "pytesting1")
        self.assertEqual(password, "The resource has been updated successfully.")

    def test_4_deletepassword(self):
        password = Passbolt.deletepassword("pytesting1", "pytesting1")
        self.assertEqual(password, "The resource has been deleted successfully.")

if __name__ == '__main__':
    unittest.main()