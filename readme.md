# Readme

Based on Passbolt's web api https://help.passbolt.com/api

## Install:

```
pip3 install passbolt
```

### From source
```
git clone https://github.com/daniel-lynch/passbolt.git
cd passbolt
pip3 install -r requirements.txt
python3 setup.py install
```

## Examples:

  - Login:

      To login you will need a private key and the associated passphrase.
      Then just call the passbolt class with those variables.

      ```
      from passbolt.passbolt import passbolt

      key = open("passbolt_private.asc", "r").read()
      passphrase = open("passphrase", "r").read().replace('\n', '')
      Passbolt = passbolt(key, passphrase)
      ```

  - Create a password:

      To create a password you will need the following:

        - Resource name
        - Password
        - Username (optional)
        - Uri (optional)
        - Description (optional)
        - Encrypt Description (optional, defaults True)

      ```
      print(
          Passbolt.createpassword(
              "Resource name",
              "Password",
              "Username",
              "Uri",
              "Description"
              )
          )

      print(
          Passbolt.createpassword(
              "testlib",
              "FakePasswordHere",
              "dlynch",
              "ssh://",
              "This is a description"
              )
          )
      ```

  - Get a password:

    Get password accepts:

        Name:
          Accepted inputs:
           - String
           - List
           - Dict

        Username(optional)
          - To be used when Name is a string or list
          Accepted inputs:
           - String

        Dict format:
          {"Resource name": "Username"}
          Ex. {"tunes01.lynch.local": "dlynch"}

      Returns a list of password objects with the following attributes:

        name
        username
        password
        uri
        resourceid
        created
        created_by
        creator
        deleted
        description
        favorite
        modified
        modified_by
        modifier
        permission
        resource_type_id
        folder_parent_id

      ```
      passwords = Passbolt.getpassword("tunes01.datayard.local", "datayard")
      passwords = Passbolt.getpassword(["tunes01.datayard.local"], "datayard)
      passwords = Passbolt.getpassword({"tunes01.datayard.local": "datayard"})

      passwords = Passbolt.getpassword("Resource name", "Username")
      passwords = Passbolt.getpassword(["Resource name"], "Username)
      passwords = Passbolt.getpassword({"Resource name": "Username"})
      ```

  - Share a password:

    Share password accepts:

      - Resource name
      - Username
      - List of Users to share with (Optional if Groups list is defined)
      - List of Groups to share with (Optional if Users list is defined)

    ```
    print(
        Passbolt.sharepassword(
            "Resource name",
            "Username",
            ["List of Users"],
            ["List of Groups"])
        )

    print(
        Passbolt.sharepassword(
            "testing",
            "test",
            ["testing@gmail.com"],
            ["test_group"])
        )
    ```

  - Update a password:

    Update password accepts:
      - Resource name
      - New password
      - Username (Optional)
      - New Resource name (Optional)
      - New Username (Optional)
      - Uri (Optional)
      - Description (Optional)
      - Encrypt Description (Optional, defaults True)

    ```
    print(
        Passbolt.updatepassword(
            "Resource name",
            "New password"
            )
        )
    print(
        Passbolt.updatepassword(
            "Testing",
            "Hunter2",
            "Test",
            newname="Testing2",
            newusername="Test2",
            uri="testing.com",
            description="asdf"
            )
        )
    ```

  - Delete a password:

    Delete password accepts:
      - Resource name
      - Username (Optional)

    ```
    print(
        Passbolt.deletepassword(
            "Resource name", "Username"
            )
        )

    print(
        Passbolt.deletepassword(
            "testlib", "dlynch"
            )
        )
    ```

  - Create User:

    Create user accepts:
      - Email Address (Username)
      - First name
      - Last name

    ```
    print(
        Passbolt.createuser("email", "First name", "Last name")
    )

    print(
        Passbolt.createuser("testing@testing.com", "John", "Doe")
    )
    ```

  - Get User:

    Get user accepts:
      - Email Address (Username)

    ```
      User = Passbolt.getuser("testing@testing.com")
    ```

    Returns a user object with the following attributes:

        userid (string)
        username (string)
        gpgkey (Dict)
        created (string)
        active (string)
        deleted (string)
        modified (string)
        role_id (string)
        profile (Dict)
        role (string)
        last_logged_in (string)

  - Update User:

    Update user accepts:
      - Email Address (Username)
      - Firstname
      - Lastname
      - Admin status (Optional, defaults False)

    ```
    print(
        Passbolt.updateuser("email", "First name", "Last name")
    )

    print(
        Passbolt.updateuser("testing2@testing.com", "Jane", "Doe")
    )
    ```

  - Delete User:

    Delete user accepts:
      - Email Address (Username)

    ```
      print(Passbolt.deleteuser("testing@testing.com"))
    ```

  - Get Groups:

    Get groups accepts:
      - members (Optional, defaults True)

    ```
      print(Passbolt.getgroups())
    ```

    Returns a list of group objects:

  - Get Group:

    Accepts:
      - Group name

    ```
      print(Passbolt.getgroup("Users"))
    ```

    Returns a group object with the following attributes:

        groupid (string)
        name (string)
        users (List of partial User objects)
        admins (List of User objects)
        created (string)
        created_by (string, User ID)
        deleted (string)
        modified (string)
        modified_by (string, User ID)

  - Update Group:

    Accepts:
      - Group name
      - New Users (Optional)
      - New Admins (Optional)

    ```
      Passbolt.updategroup("Users", ["testing@gmail.com"], ["admin@gmail.com"])
    ```

    Currently only supports adding Users and Admins due to API limitations.

  - Delete Group:

    Accepts:
      - Group name

    ```
      Passbolt.deletegroup("Users")
    ```
