import unittest
from passbolt.passbolt import passbolt

key = open("key.asc", "r").read()
passphrase = open("passphrase", "r").read().replace('\n', '')
Passbolt = passbolt(key, passphrase, "https://passbolt.djlynch.us")

class TestPasswordMethods(unittest.TestCase):

    def test_0createpassword(self):
        password = Passbolt.createpassword("pytesting", "asdf", "pytesting", "testing.com", "pytesting")
        self.assertEqual(password, "The resource has been added successfully.")

    def test_1getpassword(self):
        password = Passbolt.getpassword("pytesting", "pytesting")
        self.assertEqual(password[0].name, "pytesting")

    def test_2sharepassword(self):
        password = Passbolt.sharepassword("pytesting", "pytesting", ["s1@a.com"], ["users"])
        self.assertEqual(password, "The operation was successful.")

    def test_3updatepassword(self):
        password = Passbolt.updatepassword("pytesting", "asdf1", "pytesting", "pytesting1", "pytesting1", "testing2.com", "pytesting1")
        self.assertEqual(password, "The resource has been updated successfully.")

    def test_4deletepassword(self):
        password = Passbolt.deletepassword("pytesting1", "pytesting1")
        self.assertEqual(password, "The resource has been deleted successfully.")

if __name__ == '__main__':
    unittest.main()