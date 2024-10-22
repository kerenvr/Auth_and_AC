import json
import os
from CryptoProject import CryptoProject
from cryptography.fernet import Fernet

# questions do we generate new keys for each file or keep one key only for all user files?


# Initialize CryptoProject class
crypto = CryptoProject()

# File to store user accounts
# You can implement the backing store using a database or other methods as you like
USER_FILE = "./data/users.json"  # user and pass
ACL_FILE = "./data/acl.json"  # files they have access to


class Authentication():
    def __init__(self):
        return

    def load_users(self):
        """Load users from persistent storage."""
        try:
            with open(USER_FILE, 'r') as file:
                return json.load(file)
        except FileNotFoundError:  # https://chatgpt.com/share/6717402c-aff4-8007-bfa8-c9131493ce8b
            default_data = []
            # ik it would be better to do the same way as acl, but I wanted to append to a list
            with open(USER_FILE, 'w') as file:
                json.dump(default_data, file, indent=4)
            return default_data

    def save_users(self, users):
        # TODO: Save users to persistent storage.
        with open(USER_FILE, 'w') as json_file:
            json.dump(users, json_file,
                      indent=4,
                      separators=(',', ': '))  # https://howtodoinjava.com/python-json/append-json-to-file/
        return

    def create_account(self, users):
        # TODO: Implement account creation
        username = input("Create a username: ")
        password = input("Create a password: ")
        # TODO: Check if username already exists

        if users != None:
            for user in users:
                if username == user["firstName"]:
                    return (print("Username already exists!"))

        # TODO: Store password securely

        users.append({
            "firstName": username,
            "password": crypto.hash_string(password),
        })

        # TODO: Save updated user list

        self.save_users(users)

        return

    def login(self, users):
        username = input("Enter username: ")
        password = input("Enter password: ")
        # TODO: Implement login method including secure password check

        for user in users:
            if username == user["firstName"]:  # username is in the db
                # get the hashed password from db
                hashed_password = user["password"]
                unhashed_password = crypto.verify_integrity(  # verify hash and unhashed pswd
                    password, hashed_password)
                # if true (meaning they match), grant access
                if unhashed_password:
                    print("Access Granted.")
                    return username  # session token
                else:
                    print("Incorrect username or password.")
                    return


class AccessControl():
    def __init__(self):
        return

    # https://stackoverflow.com/questions/1274405/how-to-create-new-folder
    def create_folder(self, new_path):
        if not os.path.exists(new_path):
            os.makedirs(new_path)

    def load_acl(self):
        # TODO: Load ACL (Access Control List) from persistent storage.
        try:
            with open(ACL_FILE, 'r') as file:
                return json.load(file)
        except Exception as e:
            print(e)
            return {}

    def save_acl(self, acl):
        # TODO: Save ACL to persistent storage.

        with open(ACL_FILE, 'w') as json_file:
            json.dump(acl, json_file,
                      indent=4,
                      )
        # store dictionary test[] = {listName: List}
        return

    def create_file(self, username, acl):
        filename = input('Enter the name of the file you want to create: ')
        filepath = f"./files/{filename}.txt"
        content = input("Enter content for the file: ")

        # TODO: Add file access entry in ACL
        # https://chatgpt.com/share/67159fb3-cd1c-8007-b822-53757afbb44a
        try:
            if filename not in acl:  # file is not stored
                # add file with empty array for users
                acl[f"{filename}.txt"] = []

            acl[f"{filename}.txt"].extend([username])  # add the user

            self.save_acl(acl)  # save to the file

        except Exception as e:
            print(e)

        # TODO: Create the file and write content. EXTRA CREDIT: encrypt the file/content.

        # create folder for user
        self.create_folder(f"./keys/private/{username}")
        self.create_folder(f"./keys/public/{username}")

        # path with username and filename
        private_key_path = f"./keys/private/{username}/{username}_{filename}.private_key.pem"
        public_key_path = f"./keys/public/{username}/{username}_{filename}.public_key.pem"

        # generate the keys and put them in a file
        crypto.generate_rsa_keys(private_key_path, public_key_path)

        encrypted_content = crypto.rsa_encrypt(
            content, public_key_path)  # encrypt

        file = open(filepath, "w")  # create file
        file.write(encrypted_content)  # write to that file
        file.close()  # close

        return

    def read_file(self, username, acl):
        filename = input('Enter the name of the file you want to read: ')

        # TODO: Check if the user has access. EXTRA CREDIT: If file was encrypted, decrypt the file/content
        if f"{filename}.txt" not in acl:  # if the file doesn't exit, print error
            # give same error msg so users don't know if a file exists or not
            return print("\nError, you do not have access to this file.")

        # if the user has access, read the file
        if username in acl[f"{filename}.txt"]:
            # file path to put all files into a folder
            filepath = f"./files/{filename}.txt"
            file = open(filepath, "r")
            ciphertext = file.read()

            # TODO: Optionally decrypt the file content
            private_key_path = f"./keys/private/{username}/{username}_{filename}.private_key.pem"

            return print(crypto.rsa_decrypt(ciphertext, private_key_path))
        else:
            return print("\nError, you do not have access to this file.")


def main():
    auth = Authentication()
    ac = AccessControl()

    users = auth.load_users()
    acl = ac.load_acl()

    # folders for organization
    ac.create_folder('./data')
    ac.create_folder('./files')
    ac.create_folder('./keys/private')
    ac.create_folder('./keys/public')

    while True:
        print("\n--- Authentication & Access Control ---")
        print("1. Create an account")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            auth.create_account(users)
        elif choice == '2':
            user = auth.login(users)
            if user:
                # If login is successful, show file options
                while True:
                    print("\n1. Create a file")
                    print("2. Read a file")
                    print("3. Logout")

                    file_choice = input("Enter your choice: ")

                    if file_choice == '1':
                        ac.create_file(user, acl)
                    elif file_choice == '2':
                        ac.read_file(user, acl)
                    elif file_choice == '3':
                        print(f"Logging out {user}.")
                        break
                    else:
                        print("Invalid choice.")
        elif choice == '3':
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
