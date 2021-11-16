import unittest
import os
from passbolt.passbolt import passbolt

key = open(os.environ.get('keypath'), "r").read()
passphrase = os.environ.get('passphrase')
uri = os.environ.get('uri')

Passbolt = passbolt(key, passphrase, uri)

class TestPasswordMethods(unittest.TestCase):

    def test_0_createuser(self):
        user = Passbolt.createuser("test@example.com", "Test", "Ing")
        self.assertEqual(user, "The user was successfully added. This user now need to complete the setup.")
        user2 = Passbolt.createuser("test2@example.com", "Test", "Ing")
        self.assertEqual(user2, "The user was successfully added. This user now need to complete the setup.")

    def test_1_getuser(self):
        user = Passbolt.getuser("daniel.lynch2016@gmail.com")
        self.assertEqual(user.username, "daniel.lynch2016@gmail.com")

    def test_2_updateuser(self):
        user = Passbolt.updateuser("doghouse475@gmail.com", "DJ", "Lynch", True)
        self.assertEqual(user, "The user has been updated successfully.")
        user = Passbolt.updateuser("doghouse475@gmail.com", "DJ", "Lynch", False)
        self.assertEqual(user, "The user has been updated successfully.")

    def test_3_deleteuser(self):
        user = Passbolt.deleteuser("test@example.com")
        self.assertEqual(user, "The user has been deleted successfully.")
        user2 = Passbolt.deleteuser("test2@example.com")
        self.assertEqual(user2, "The user has been deleted successfully.")

if __name__ == '__main__':
    unittest.main()