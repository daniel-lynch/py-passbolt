#!/bin/env python3
import requests
import gnupg
import fnmatch
import json
from urllib.parse import unquote


class passbolt:

    def __init__(self,privatekey=None, passphrase=None, apiurl=None, fingerprint=None, verify=True):
        if keyfingerprint:
            self.keyfingerprint = fingerprint
            self.gpg = gnupg.GPG(use_agent=True)
            self.passphrase = None
        else:
            self.privatekey = privatekey
            self.passphrase = passphrase
            self.gpg = gnupg.GPG()
            # Importing our private key
            self.imported_keys = self.gpg.import_keys(privatekey)
            # Getting the fingerprint of our first privatekey
            self.keyfingerprint = self.imported_keys.fingerprints[0]

        self.apiurl = apiurl
        self.session = requests.session()
        self.session.verify = verify
        self.apiversion = "?api-version=v3"
        self.loginurl = f"/auth/login.json{self.apiversion}"

        # Giving our key Ultimate trust so that we can encrypt secrets with it.
        self.gpg.trust_keys(self.keyfingerprint, "TRUST_ULTIMATE")

        self.__login()

    def __login(self):

        """
        Login process can be found here
        https://help.passbolt.com/api/authentication 
        """

        loginbody = {
            "gpg_auth": {
                "keyid": self.keyfingerprint
            }
        }

        login = self.session.post(
            self.apiurl + self.loginurl,
            headers={"Content-Type": "application/json"},
            json=loginbody
            )

        server_verify_token = unquote(
            login.headers["X-GPGAuth-User-Auth-Token"]).replace("\\+", " ")

        user_token_result = self.__decrypt(server_verify_token)

        loginbody["gpg_auth"]["user_token_result"] = user_token_result

        login = self.session.post(
            self.apiurl + self.loginurl,
            headers={"Content-Type": "application/json"},
            json=loginbody
            )

        logindata = login.json()

        #print(logindata['header']['message'])

        if logindata['header']['message'] == "You are successfully logged in.":
            # Once we're logged in grab some info and X-CSRF-Token
            self.userid = logindata['body']['profile']['user_id']
            self.fingerprint = logindata['body']['gpgkey']['fingerprint']
            self.session.get('%s/resources.json?api-version=v3' % self.apiurl)
            self.csrfToken = self.session.cookies.get_dict()["csrfToken"]
            self.headers = {"Content-Type": "application/json",
                            "X-CSRF-Token": self.csrfToken}
        else:
            raise ValueError(logindata['header']['message'])

    # Wrapper around a wrapper for my wrapper
    def __req(self, reqtype, location, data=None, parameters=None):
        if reqtype == "get":
            return(
                self.session.get(
                    f"{self.apiurl}{location}{self.apiversion}{parameters}"
                    ).json()['body']
                )
        if reqtype == "put":
            return(
                self.session.put(
                    f"{self.apiurl}{location}{self.apiversion}",
                    headers=self.headers,
                    json=data
                ).json()['header']['message']
            )
        if reqtype == "post":
            return(
                self.session.post(
                    f"{self.apiurl}{location}{self.apiversion}",
                    headers=self.headers,
                    json=data
                ).json()['header']['message']
            )
        if reqtype == "delete":
            return(
                self.session.delete(
                    f"{self.apiurl}{location}{self.apiversion}",
                    headers=self.headers
                ).json()["header"]["message"]
            )

    def __decrypt(self, encpass):
        return(
            self.gpg.decrypt(
                encpass, passphrase=self.passphrase
                ).data.decode("utf-8")
            )

    def __encrypt(self, password, recipients):
        return(
            self.gpg.encrypt(password, recipients).data.decode('utf-8')
        )

    def __getresources(self, parameters=None):
        resources = self.__req("get", "/resources.json", parameters=parameters)
        return(resources)

    def __getresourceid(self, name, username=None, parameters=None):
        resourceid = None
        resources = self.__getresources(parameters)
        for resource in resources:
            if name == resource['name']:
                if username and not username == resource['username']:
                    continue
                resourceid = resource["id"]
                return resourceid
        if not resourceid:
            raise NameError(f"Resource {name} not found")

    def __getroleid(self, admin):
        role_id = None
        users = self.__req("get", "/share/search-aros.json")
        for user in users:
            if "role" in user:
                if admin == True and user["role"]["name"] == "admin":
                    role_id = user["role"]["id"]
                    break
                if admin == False and user["role"]["name"] == "user":
                    role_id = user["role"]["id"]
                    break
        return role_id

    def __creategroup(self, group):
        admins = []
        users = []
        if "users" in group:
            for user in group["users"]:
                if user["_joinData"]["is_admin"] == True:
                    admins.append(User(user["id"],
                            user["username"],
                            user["created"],
                            user["active"],
                            user["deleted"],
                            user["modified"],
                            user["role_id"],
                            None,
                            None,
                            None,
                            user["last_logged_in"]))
                else:
                    users.append(User(user["id"],
                            user["username"],
                            user["created"],
                            user["active"],
                            user["deleted"],
                            user["modified"],
                            user["role_id"],
                            None,
                            None,
                            None,
                            user["last_logged_in"]))
        return(Group(group["id"],
            group["name"],
            users,
            admins,
            group["created"],
            group["created_by"],
            group["deleted"],
            group["modified"],
            group["modified_by"]))

    def getpassword(self, name, username=None): 

        resources = self.__req("get", "/resources.json")
        passwords = []

        for resource in resources:
            if isinstance(name, (list)):
                if not resource["name"] in name:
                    continue
            elif isinstance(name, (dict)):
                if not resource["name"] in name:
                    continue
                username = name[resource["name"]]
            elif not fnmatch.fnmatch(resource["name"], name):
                continue

            if username and resource["username"] != username:
                continue

            resourceid = resource["id"]
            encpw = self.__req("get", f"/secrets/resource/{resourceid}.json")["data"]
            pw = self.__decrypt(encpw)
            resourcetype = self.__req("get", f"/resource-types/{resource['resource_type_id']}.json")["slug"]
            if resourcetype == "password-and-description":
                pw = json.loads(pw)
                description = pw["description"]
                password = pw["password"]
            else:
                description = resource["description"]
                password = pw

            password = Password(resourceid,
                resource["name"],
                password,
                resource["created"],
                resource["created_by"],
                resource["created_by"],
                resource["deleted"],
                description,
                None,
                resource["modified"],
                resource["modified_by"],
                None,
                None,
                resource["uri"],
                resource["username"],
                resource['resource_type_id'],
                None)
            passwords.append(password)

        return passwords

    def createpassword(
        self,
        name,
        password,
        username=None,
        uri=None,
        description=None,
        encrypt_description=True
    ):

        data = {
            "name": name,
            "username": username,
            "resource_type_id": None,
            "secrets": [{}],
            "uri": uri,
            "description": description,
        }

        if encrypt_description:
            resource_types = self.__req("get", "/resource-types.json")
            for type in resource_types:
                if type["slug"] == "password-and-description":
                    data["resource_type_id"] = type["id"]
            secretsobj = json.dumps({"password": password, "description": description})
            secrets = self.__encrypt(secretsobj, self.fingerprint)
            data["secrets"][0]["data"] = secrets
            del(data["description"])
        else:
            password = self.__encrypt(password, self.fingerprint)
            data["secrets"][0]["data"] = password

        return self.__req("post", "/resources.json", data)

    def updatepassword(self, name, password, username=None, newname=None, newusername=None, uri=None, description=None, encrypt_description=True):
        groups = []
        users = []
        data = {
            "name": newname or name,
            "username": newusername or username,
            "secrets": []
            }

        if not encrypt_description and not description == None:
            data["description"] = description

        if not uri == None:
            data["uri"] = uri

        resourceid = self.__getresourceid(name, username)

        permdata = self.__req("get", f"/permissions/resource/{resourceid}.json")

        for resource in permdata:
            if not resource['aro'] == "Group":
                users.append(resource['aro_foreign_key'])
            else:
                groups.append(resource['aro_foreign_key'])

        req = self.__req("get", "/share/search-aros.json")

        if encrypt_description:
            resource_types = self.__req("get", "/resource-types.json")
            for type in resource_types:
                if type["slug"] == "password-and-description":
                    data["resource_type_id"] = type["id"]
            password = json.dumps({"password": password, "description": description})

        for group in groups:
            for reqobj in req:
                if "groups_users" in reqobj:
                    member = reqobj
                    if member["gpgkey"]["user_id"] in users:
                        continue
                    for membership in reqobj["groups_users"]:
                        if group == membership["group_id"]:
                            self.gpg.import_keys(member["gpgkey"]["armored_key"])
                            self.gpg.trust_keys(
                                member["gpgkey"]["fingerprint"],
                                "TRUST_ULTIMATE")

                            data["secrets"].append({
                                "user_id": member["gpgkey"]["user_id"],
                                "data": self.__encrypt(password, member["username"])
                                })

        for user in users:
            for reqobj in req:
                member = reqobj
                if user == reqobj["id"]:
                    self.gpg.import_keys(member["gpgkey"]["armored_key"])
                    self.gpg.trust_keys(
                        member["gpgkey"]["fingerprint"],
                        "TRUST_ULTIMATE")

                    data["secrets"].append({
                        "user_id": member["gpgkey"]["user_id"],
                        "data": self.__encrypt(password, member["username"])
                        })
    
        return self.__req("put", f"/resources/{resourceid}.json", data)

    def deletepassword(self, name, username=None):
        resourceid = self.__getresourceid(name, username)
        return self.__req("delete", f"/resources/{resourceid}.json")

    def sharepassword(self, name, username=None, users=[], groups=[], permission="Read"):
        if not users and not groups:
            raise ValueError("Atleast one user or group is required")
        if not type(groups) == list:
            raise ValueError("groups must be a list")
        if not type(users) == list:
            raise ValueError("users must be a list")

        if permission == "Read":
            permission = 1
        if permission == "Update":
            permission = 7
        if permission == "Owner":
            permission = 15
        if permission not in [1,7,15]:
            permission = 1

        groupids = []
        secrets = []
        permissions = []

        resourceid = self.__getresourceid(name, username)

        password = self.getpassword(name, username)[0].password

        for group in groups:
            groupobj = self.getgroup(group)
            if groupobj:
                groupids.append(groupobj.groupid)
                permissions.append({
                    "is_new": True,
                    "aro": "Group",
                    "aro_foreign_key": groupobj.groupid,
                    "aco": "Resource",
                    "aco_foreign_key": resourceid,
                    "type": permission
                    })

        req = self.__req("get", "/share/search-aros.json")

        for reqobj in req:
            if "groups_users" in reqobj:
                member = reqobj
                for membership in reqobj["groups_users"]:
                    if membership["group_id"] in groupids:
                        # Don't add our own userid and secret because its already there
                        if member["gpgkey"]["user_id"] == self.userid:
                            continue
                        self.gpg.import_keys(member["gpgkey"]["armored_key"])
                        self.gpg.trust_keys(
                            member["gpgkey"]["fingerprint"],
                            "TRUST_ULTIMATE")

                        secrets.append({
                            "user_id": member["gpgkey"]["user_id"],
                            "data": self.__encrypt(password, member["username"])
                            })

        for user in users:
            if user in secrets:
                continue
            for reqobj in req:
                member = reqobj
                if "username" not in reqobj:
                    continue
                if user == reqobj["username"]:
                    self.gpg.import_keys(member["gpgkey"]["armored_key"])
                    self.gpg.trust_keys(
                        member["gpgkey"]["fingerprint"],
                        "TRUST_ULTIMATE")

                    secrets.append({
                        "user_id": member["gpgkey"]["user_id"],
                        "data": self.__encrypt(password, member["username"])
                        })

                    permissions.append({
                        "is_new": True,
                        "aro": "User",
                        "aro_foreign_key": member["gpgkey"]["user_id"],
                        "aco": "Resource",
                        "aco_foreign_key": resourceid,
                        "type": permission
                        })

        data = {"permissions": permissions, "secrets": secrets}
        return(self.__req("put", f"/share/resource/{resourceid}.json", data))

    def createuser(self, email, firstname, lastname, admin=False):
        role_id = self.__getroleid(admin)
        data = {
            "username": email,
            "profile": {
                "first_name": firstname,
                "last_name": lastname
            },
            "role_id": role_id
        }
        return self.__req("post", "/users.json", data)

    def updateuser(self, email, firstname, lastname, admin=False):
        role_id = self.__getroleid(admin)
        userobj = self.getuser(email)
        data = {
            "username": email,
            "profile": {
                "first_name": firstname,
                "last_name": lastname
            },
            "role_id": role_id
        }
        return self.__req("put", f"/users/{userobj.userid}.json", data)

    def getuser(self, email):
        users = self.__req("get", "/users.json")

        for user in users:
            if user["username"] == email:
                return User(user["id"],
                        user["username"],
                        user["created"],
                        user["active"],
                        user["deleted"],
                        user["modified"],
                        user["role_id"],
                        user["profile"],
                        user["role"]["name"],
                        user["gpgkey"],
                        user["last_logged_in"])

        return None

    def deleteuser(self, email):
        user = self.getuser(email)

        if not user:
            return f"{email} not found, no user deleted."

        return self.__req("delete", f"/users/{user.userid}.json")

    def getgroups(self, members=True):
        groups = []
        parameters = None
        if members:
            parameters = "&contain[user]=1"
        groupsreq = self.__req("get", "/groups.json", parameters=parameters)
        for group in groupsreq:
            groups.append(self.__creategroup(group))
        return groups

    def getgroup(self, name):
        groups = self.getgroups(members=False)
        for groupobj in groups:
            if groupobj.name == name:
                group = self.__req("get", f"/groups/{groupobj.groupid}.json", parameters="&contain[user]=1")
                return(self.__creategroup(group))


    def creategroup(self, name, admins, users=[]):
        if not type(admins) == list:
            raise ValueError("admins must be a list")
        if not type(users) == list:
            raise ValueError("users must be a list")

        groups_users = []
        for admin in admins:
            user = self.getuser(admin)
            if user:
                groups_users.append({"user_id": user.userid, "is_admin": True})
        for user in users:
            userobj = self.getuser(user)
            if userobj:
                groups_users.append({"user_id": userobj.userid, "is_admin": False})

        data = {
            "name": name,
            "groups_users": groups_users
        }

        return(self.__req("post", "/groups.json", data))

    def updategroup(self, groupname, newusers=[], newadmins=[]):
        groups_users = []
        newuserobjs = []
        group = self.getgroup(groupname)

        for user in newusers:
            userobj = self.getuser(user)
            groups_users.append({"user_id": userobj.userid, "is_admin": False})
            newuserobjs.append(userobj)
        for admin in newadmins:
            userobj = self.getuser(admin)
            groups_users.append({"user_id": userobj.userid, "is_admin": True})
            newuserobjs.append(userobj)

        data = {
            "name": group.name,
            "groups_users": groups_users,
            "secrets": []
        }

        req = self.__req("get", "/share/search-aros.json")
        for reqobj in req:
            if "gpgkey" in reqobj:
                member = reqobj
                if member["id"] in groups_users:
                    self.gpg.import_keys(member["gpgkey"]["armored_key"])
                    self.gpg.trust_keys(
                        member["gpgkey"]["fingerprint"],
                        "TRUST_ULTIMATE")

        resources = self.__getresources(f"&filter[is-shared-with-group]={group.groupid}")

        for resource in resources:
            resourceid = resource["id"]
            encpw = self.__req("get", f"/secrets/resource/{resourceid}.json")["data"]
            pw = self.__decrypt(encpw)
            for user in newuserobjs:
                secret = self.__encrypt(pw, user.username)
                data["secrets"].append({"resource_id": resource["id"], "user_id": user.userid, "data": secret})
        return(self.__req("put", f"/groups/{group.groupid}.json", data=data))

    def deletegroup(self, name):
        group = self.getgroup(name)
        if group:
            return(self.__req("delete", f"/groups/{group.groupid}.json"))

class Password():
    
        def __init__(self,
            resourceid,
            name,
            password,
            created = None,
            created_by = None,
            creator = None,
            deleted = None,
            description = None,
            favorite = None,
            modified = None,
            modified_by = None,
            modifier = None,
            permission = None,
            uri = None,
            username = None,
            resource_type_id = None,
            folder_parent_id = None):

            self.resourceid = resourceid
            self.created = created
            self.created_by = created_by
            self.creator = creator
            self.deleted = deleted
            self.description = description
            self.favorite = favorite
            self.modified = modified
            self.modified_by = modified_by
            self.modifier = modifier
            self.name = name
            self.permission = permission
            self.uri = uri
            self.username = username
            self.resource_type_id = resource_type_id
            self.folder_parent_id = folder_parent_id
            self.password = password

class User:

    def __init__(self,
        userid,
        username,
        created = None,
        active = None,
        deleted = None,
        modified = None,
        role_id = None,
        profile = None,
        role = None,
        gpgkey = None,
        last_logged_in = None
        ):

        self.userid = userid
        self.created = created
        self.active = active
        self.deleted = deleted
        self.modified = modified
        self.username = username
        self.role_id = role_id
        self.profile = profile
        self.role = role
        self.gpgkey = gpgkey
        self.last_logged_in = last_logged_in

class Group:

    def __init__(self,
        groupid,
        name,
        users = None,
        admins = None,
        created = None,
        created_by = None,
        deleted = None,
        modified = None,
        modified_by = None):

        self.groupid = groupid
        self.name = name
        self.users = users
        self.admins = admins
        self.created = created
        self.created_by = created_by
        self.deleted = deleted
        self.modified = modified
        self.modified_by = modified_by
