'''
You need to install the following libraries for this program to work correctly.  The rest of the libraries should already come pre-installed with python.
pip3 install cryptography
pip3 install pyperclip
'''

import base64, json, logging, os, pyperclip, random, string, sys
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

'''
Removing the csv and tkinter libraries since I disabled a function that I didn't want to risk for the final project.
import csv
import tkinter as tk
from tkinter import messagebox, filedialog
'''

logging.basicConfig(filename='Final Project - Logging.txt', level=logging.DEBUG, format='%(asctime)s -  %(levelname)s -  %(message)s')

# This function is used to copy the title, username, or password from a password entry.
def copy_password(cipher_suite, vault_string):
    logging.debug("Copy Password function started.")
    # Decrypt the vault and pass the data to the vault_passwords dictionary variable.
    vault_passwords = decrypt_vault(cipher_suite, vault_string)
    # Check to make sure that the vault is not empty.  If the vault is empty then we need to exit the function and let the user know that the vault is empty.
    empty_vault = is_vault_empty(vault_passwords)
    if empty_vault:
        return
    # Create a temporary dictionary (temp_dict) to hold the user's selection and create an incrementing variable, i, to number the keys for user selection.
    i = 1
    temp_dict = {}
    # Put the user selection process in a try catch if the vault is empty.  This was created before the empty_vault function above, but it can still be used if the vault is modified externally while the program is running.
    try:
        # This loop lists the titles(nested dictionary keys) from the vault_passwords dictionary and lets the user select a password entry.
        while True:
            # Ordered Dict Keys is a list of the keys from vault_passwords sorted alphabetically.
            ordered_dict_keys = sorted(vault_passwords.keys(), key=str.lower)
            print("Please select an entry to copy:")
            # Loop through the entries in Ordered Dict Keys and print them to the screen for the user.
            for keys in ordered_dict_keys:
                print(str(i) + ". " + keys)
                temp_dict[str(i)] = keys
                i += 1
            print("0. Cancel Copy")
            select_entry = input("> ")
            print("")
            # If the user's selection is 0 then quit the copy password function.
            if select_entry == "0":
                logging.info("User cancelled the Copy Password function.")
                return
            # If the user's selection is not 0 then set the vault_passwords_dict_key string equal to the password entry title so we can reference the password entry.
            try:
                vault_passwords_dict_key = temp_dict[select_entry]
                logging.info("User entered a value of '" + str(select_entry) + "' for their copy password entry.")
                break
            # If the user's selection does not exist in the dictionary then we need to have the user try again with a valid value.
            except KeyError:
                print("Please enter a valid value.")
                print("")
                logging.warning("User entered an invalid value of '" + str(select_entry) + "' for their copy password entry.")
                i = 1
    # If the password_vault is still somehow empty after the empty_vault function then the AttributeError will catch it and print out an empty vault error.
    except AttributeError:
        empty_vault_alert()
        return
    # Let the user copy either the title, username, or password to the clipboard.  This is in a loop in case the user needs to copy the username and then the password.
    while True:
        print(banner)
        print("You have selected the following entry: " + vault_passwords_dict_key)
        print("Username: " + vault_passwords[vault_passwords_dict_key]['username'])
        print("Password: "+ vault_passwords[vault_passwords_dict_key]['password'])
        try:
            if vault_passwords[vault_passwords_dict_key]['url'] != None:
                print("     URL: " + vault_passwords[vault_passwords_dict_key]['url'])
        except KeyError:
            pass
        print(banner)
        print("")
        print("What would you like to copy?")
        print("1. Title")
        print("2. Username")
        print("3. Password")
        if 'url' in vault_passwords[vault_passwords_dict_key]:
            print("4. URL")
        print("0. Cancel Copy")
        entry_modification_selection = input("> ")
        logging.info("User entered a Copy Password option of '" + str(entry_modification_selection) + "'.")
        print("")

        # Copy the title to the clipboard.
        if entry_modification_selection == "1":
            pyperclip.copy(vault_passwords_dict_key)
            print("The title for " + str(vault_passwords_dict_key) + " has been copied to your clipboard.")
            logging.info("The user copied the title for '" + str(vault_passwords_dict_key) + "' to the keyboard.")
        # Copy the username to the clipboard.
        elif entry_modification_selection == "2":
            pyperclip.copy(vault_passwords[vault_passwords_dict_key]['username'])
            print("The username for " + str(vault_passwords_dict_key) + " has been copied to your clipboard.")
            logging.info("The user copied the username for '" + str(vault_passwords_dict_key) + "' to the keyboard.")
        # Copy the password to the clipboard.
        elif entry_modification_selection == "3":
            pyperclip.copy(vault_passwords[vault_passwords_dict_key]['password'])
            print("The password for " + str(vault_passwords_dict_key) + " has been copied to your clipboard.")
            logging.info("The user copied the password for '" + str(vault_passwords_dict_key) + "' to the keyboard.")
        elif entry_modification_selection == "4" and 'url' in vault_passwords[vault_passwords_dict_key]:
            pyperclip.copy(vault_passwords[vault_passwords_dict_key]['url'])
            print("The URL for " + str(vault_passwords_dict_key) + " has been copied to your clipboard.")
            logging.info("The user copied the URL for '" + str(vault_passwords_dict_key) + "' to the keyboard.")
        # Exit the copy_password function
        elif entry_modification_selection == "0":
            logging.info("User cancelled the Copy Password function.")
            break
        # If anything is entered besides the values listed above, ask the user to enter a valid value.
        else:
            print("Please enter a valid value.")
            logging.warning("User entered an invalid value of '" + str(entry_modification_selection) + "' at the Copy Password options menu.")
    logging.debug("Copy Password function completed successfully.")
    return

# This function is used to create a password entry.
def create_password(cipher_suite, vault_string):
    logging.debug("Create Password function started.")
    # This variable, vault_dict, is used to see if an entry already exists in the password vault.  We don't want to overwrite an existing entry.
    vault_dict = ""
    # This if statement decrypts the vault if it's not empty and saves the binary data to the file_binary_plain_text string.  That string is then decoded from binary and saved to the file_plain_text string, which is then converted into a dictionary variable and saved as vault_dict.
    if vault_string != b"":
        file_binary_plain_text = (cipher_suite.decrypt(vault_string))
        file_plain_text = bytes(file_binary_plain_text).decode('utf-8')
        # Convert the string to a dictionary
        vault_dict = json.loads(file_plain_text)
    # This while loop ensures that the user enters a valid title for their password entry.
    while True:
        # Enter a title for the password entry.  This could be a website, computer name, bike lock, phone pin, etc.
        title = input('Please enter a title for your password entry: ')
        # Make sure the title isn't too long.  This isn't really important, but will speed up encryption time.
        if len(title) >= 1 and len(title) <= 100:
            # This ensures that we don't overwrite an existing password entry.
            if title in vault_dict:
                print("This title already exists in your vault.  Please enter a different title.")
                print("")
                logging.warning("User entered a title that already exists: '" + str(title) + "'.")
                continue
            break
        else:
            print("Please enter a valid title between 1 and 100 characters.")
            print("")
            logging.warning("User entered an invalid title of '" + str(title) + "'.")
            continue
    # This while loop ensures that the user enters a username less than 100 characters.  Since a username isn't required for a bike lock or a phone pin, we don't need to make this field mandatory.
    while True:
        # Make sure the username isn't too long.  This will speed up encryption time and ensure that encryption time doesn't take too long.
        username = input('Please enter a username for your password entry: ')
        if len(username) <= 100:
            break
        else:
            print("Please enter a valid username less than 100 characters.")
            print("")
            logging.warning("User entered an invalid username of '" + str(username) + "'.")
            continue
    # Passes the user to the password_generator function to either automate password creation or manually create a password and saves it to the mypassword string.
    mypassword = password_generator()
    while True:
        # Make sure the URL isn't too long.  This will speed up encryption time and ensure that encryption time doesn't take too long.
        url = input('Please enter a url for your password entry: ')
        if len(url) <= 500:
            break
        else:
            print("Please enter a valid URL less than 500 characters.")
            print("")
            logging.warning("User entered an invalid url of '" + str(url) + "'.")
            continue
    # Create a dictionary for the current password entry and then add the existing vault dictionary to it.
    new_password_entry = {}
    new_password_entry[title] = {}
    new_password_entry[title]['username'] = username
    new_password_entry[title]['password'] = mypassword
    new_password_entry[title]['url'] = url
    new_password_entry.update(vault_dict)
    logging.info("The new password entry for '" + str(title) + "' has been added to the Password Vault.")
    # Encrypt the vault after adding the existing vault to the new_password_entry vault.
    encrypt_vault(cipher_suite, new_password_entry)
    print(banner)
    print("Your password entry has been added to the vault.")
    print(banner)
    logging.debug("Create Password function completed successfully.")
    return

# This function is used to create a password vault.
def create_vault():
    logging.debug("Create Vault function started.")
    while True:
        # Ask the user for a master password, which will unlock their password vault.
        password = input('Create a Master Password: ').encode("utf-8")
        password_confirm = input('Confirm your Master Password: ').encode("utf-8")
        # Confirm that the master password matches
        if password != password_confirm:
            print("Your Master Password did not match. Please try again.")
            logging.warning("The Master Passwords did not match.  Please try again.")
            continue
        else:
            # Create a random 32 character salt, which is saved in vault.bin for later to recreate the symmetric encryption key with the master password.
            salt = os.urandom(32)
            # Create a default, empty dictionary that is also used to verify the password is correct when opening the vault.
            default_vault_dict = {}
            # Convert the dictionary into a string with json.dumps and then encode it.
            default_vault = json.dumps(default_vault_dict).encode("utf-8")
            # Create a key derivation function using PBKDF2HMAC, which uses a SHA256 hashing algorithm, the 32 character salt from above, and 100,100 iterations.  The 100,100 iterations are unnecessary for this simple program, but were kept to make the program more realistic.  LastPass uses 100,100 iterations (https://support.logmeininc.com/lastpass/help/about-password-iterations-lp030027)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100100
            )
            # The symmetric key is derived using the master password and the key derivation function.
            mykey = base64.urlsafe_b64encode(kdf.derive(password))
            # The Fernet library is used in conjunction with the symmetric key to create a Fernet object, which is used to encrypt/decrypt the vault.
            cipher_suite = Fernet(mykey)
            # The default, empty dictionary string that we created above is encrypted and then assigned to the default_vault_encrypted_data variable.
            default_vault_encrypted_data = cipher_suite.encrypt(default_vault)
            # Create a vault.bin file with the salt and an encrypted, empty vault.
            save_vault(salt, default_vault_encrypted_data)
            # Let the user know that the vault has been created.
            print(banner)
            print("Your new vault has been created. Please open the vault to access your data.")
            print(banner, end="\n\n")
            logging.info("User created a new password vault.")
            break
    logging.debug("Create Vault function completed successfully.")
    return

# This function is used to decrypt the password vault.
def decrypt_vault(cipher_suite, vault_string):
    logging.debug("Decrypt Vault function started.")
    # Create the vault_passwords dictionary.
    vault_passwords = {}
    # If the vault_string data is not empty then decrypt the data and save it to the newly created vault_passwords dictionary and return it.
    if vault_string != b"":
        binary_plain_text = (cipher_suite.decrypt(vault_string))
        plain_text = bytes(binary_plain_text).decode('utf-8')
        # Use json.loads to convert the plain_text string to a dictionary variable and assign that to the vault_passwords dictionary.
        vault_passwords = json.loads(plain_text)
    logging.debug("Decrypt Vault function completed successfully.")
    return vault_passwords

# This function is used to delete a password entry.
def delete_password(cipher_suite, vault_string):
    logging.debug("Delete Password function started.")
    # Set vault_passwords equal to the output of the decrypt_vault function.  This value should either be blank or a plain-text dictionary of the password vault.
    vault_passwords = decrypt_vault(cipher_suite, vault_string)
    # Check to see if the password vault is empty.
    empty_vault = is_vault_empty(vault_passwords)
    # If the password vault is empty then exit the delete passwords function since there are no passwords to delete.
    if empty_vault:
        return
    # The i counter is used to make a numeric list of entries.
    i = 1
    # The temp_dict is used to select a specific password entry.
    temp_dict = {}
    try:
        while True:
            # This variable is an alphabetical list of password entries.  If we did not sort it alphabetically with the vault_passwords.keys() set to lower, then the vault would sort uppercase and lowercase password entries separately and would be confusing to the user.
            ordered_dict_keys = sorted(vault_passwords.keys(), key=str.lower)
            print("Please select an entry to delete:")
            # Loop through the alphabetical list of password entries and print an integer beside each one so the user can use the integer to select a password entry.
            for keys in ordered_dict_keys:
                print(str(i) + ". " + keys)
                # The temp_dict variable stores the key for the integer that the user inputs.
                temp_dict[str(i)] = keys
                i += 1
            print("0. Cancel Deletion")
            # The select_entry variable is the integer that is entered by the user.
            select_entry = input("> ")
            print("")
            # If the user enters 0 then quit the function.
            if select_entry == "0":
                logging.info("User cancelled the Delete Password function.")
                return
            # The try statement ensures that the user enters a valid number.  If the user does not enter a valid number then we ask the user to try again.
            try:
                # The vault_passwords_dict_key string saves the password entry title from above, which will be used as a nested dictionary key later.
                vault_passwords_dict_key = temp_dict[select_entry]
                logging.info("User entered a value of " + str(select_entry) + " for their delete password entry.")
                break
            except KeyError:
                print("Please enter a valid value.")
                logging.warning("User entered an invalid value of " + str(select_entry) + " for their delete password entry.")
                i = 1
    except AttributeError:
        empty_vault_alert()
        return
    while True:
        # Print out the password entry and confirm that the user wants to delete the specified password entry.  The user needs to type "yes" (case insensitive) to delete the entry.  All other entries will cancel the deletion process.
        print(banner)
        print("You have selected the following entry: " + vault_passwords_dict_key)
        print("Username: " + vault_passwords[vault_passwords_dict_key]['username'])
        print("Password: "+ vault_passwords[vault_passwords_dict_key]['password'])
        try:
            if vault_passwords[vault_passwords_dict_key]['url'] != None and vault_passwords[vault_passwords_dict_key]['url'] != "":
                print("URL: "+ vault_passwords[vault_passwords_dict_key]['url'])
        except KeyError:
            logging.debug(str(vault_passwords[vault_passwords_dict_key]) + " does not have a url.")
            pass
        print(banner)
        print("")
        print("Are you sure you want to delete " + str(vault_passwords_dict_key) + "?")
        print("Type 'yes' to confirm deletion or enter anything else to cancel.")
        entry_modification_selection = input("> ")

        # If the user types "yes" then the password entry (nested dictionary) will be popped off of the vault_passwords dictionary and then vault_passwords will be saved and re-encrypted with the user's changes.
        if entry_modification_selection.lower() == "yes":
            logging.info(str(vault_passwords_dict_key) + " has been deleted from your vault.  User entered '" + str(entry_modification_selection) + "'.")
            vault_passwords.pop(vault_passwords_dict_key)
            encrypt_vault(cipher_suite, vault_passwords)
            print("")
            print(banner)
            print(str(vault_passwords_dict_key) + " has been deleted from your vault.")
            print(banner)
            break
        # If the user types anything besides "yes" then the deletion process will be cancelled and will return the user to the open_vault function.
        else:
            print("")
            print(banner)
            print("Deletion of " + str(vault_passwords_dict_key) + " cancelled.")
            print(banner)
            logging.info("Deletion of " + str(vault_passwords_dict_key) + " cancelled.  User entered '" + str(entry_modification_selection) + "'.")
            break
    logging.debug("Delete Password function completed successfully.")
    return

# This function is used to print an error when the vault is empty. It is easier to call this function in an exception instead of writing out the same print statements multiple times.
def empty_vault_alert():
    logging.debug("Empty Vault Alert function started.")
    print(banner)
    print("Your password vault is currently empty.")
    print(banner)
    logging.debug("The password vault is currently empty.")
    logging.debug("Empty Vault Alert function completed successfully.")
    return

# This function is used to encrypt the vault with the symmetric encryption key.
def encrypt_vault(cipher_suite, vault_passwords):
    logging.debug("Encrypt Vault function started.")
    # The vault_string string is a json string of the vault_passwords dictionary.
    vault_string = json.dumps(vault_passwords)
    # The vault_string_bytes literal bytes object is the base64 encoded vault_string.
    vault_string_bytes = vault_string.encode('utf-8')
    # The cipher text is the vault_string_bytes variable encrypted with the symmetric key.
    cipher_text = cipher_suite.encrypt(vault_string_bytes)
    # The original salt used to create the symmetric key via the kdf is returned from the vault_to_strings function. The vault.bin contents are overwritten with the new cipher text so we don't need the vault_string variable and instead we drop it with underscore (_).
    salt_string, _ = vault_to_strings()
    # Update the vault.bin file with the salt and cipher text(vault).
    save_vault(salt_string, cipher_text)
    logging.info("The vault.bin file has been updated.")
    logging.debug("Encrypt Vault function completed successfully.")
    return

# This function is used to print an error when a vault does not exist.  It is easier to call this function in an exception instead of writing out the same print statements multiple times.
def fnf_error():
    logging.debug("File Not Found function started.")
    print(banner)
    print("You do not have an existing password vault.  Please create a vault to get started.")
    print(banner)
    logging.warning("The user attempted to open the password vault, but vault.bin does not exist.")
    logging.debug("File Not Found function completed successfully.")
    return

'''
I originally added this function to add enhancements from the midterm version, but I don't want to risk losing points since my comments for the midterm were to just add logging.

# This function is used to import password entries.
def import_password(cipher_suite, vault_string):
    logging.debug("Import Password function started.")
    # This variable, vault_dict, is used to see if an entry already exists in the password vault.  We don't want to overwrite an existing entry.
    vault_dict = ""
    # This if statement decrypts the vault if it's not empty and saves the binary data to the file_binary_plain_text string.  That string is then decoded from binary and saved to the file_plain_text string, which is then converted into a dictionary variable and saved as vault_dict.
    if vault_string != b"":
        file_binary_plain_text = (cipher_suite.decrypt(vault_string))
        file_plain_text = bytes(file_binary_plain_text).decode('utf-8')
        # Convert the string to a dictionary
        vault_dict = json.loads(file_plain_text)
    # Create a hidden tkinter GUI so we can give the user the option to load a file into the program.  Only allow CSV files.
    root = tk.Tk()
    root.withdraw()
    filetypes = (
        ('CSV files', '*.csv'),
    )
    # Present the File Dialog in the relative path and save the file name to the filename variable.
    filename = filedialog.askopenfilename(
        title='Open a file',
        initialdir='.\\',
        filetypes=filetypes
    )
    # We can use this to confirm that the user selected the correct file, but I didn't want to confirm every time.
    """ if filename != "":
        file_import_answer = messagebox.askquestion(
            title='Selected File',
            message='Is '+ filename + ' the correct file?'
        )
        if file_import_answer != 'yes':
            return False
    elif filename == "":
        print("File Selection was cancelled.")
        return """
    # We replaced the block comment above with this to determine if the file selection was cancelled.
    if filename == "":
        print("File Selection was cancelled.")
        logging.warning("The user select an empty string file to import.")
        return
    # Log the file that is being imported so we can troubleshoot later if needed.
    logging.debug("The user selected the following file to import: " + str(filename))
    accounts_temp = {}
    accounts_dict = {}
    line_count = 1
    if filename[-4:] == ".csv":
        with open(filename) as csvfile:
            reader = csv.DictReader(csvfile, delimiter=',')
            for row in reader:
                key = line_count
                accounts_temp[key] = row
                line_count += 1
        csvfile.close()
        #print(accounts_temp)
        try:
            for account in accounts_temp:
                accounts_dict[accounts_temp[account]['title']] = {}
                #print(accounts_dict[accounts_temp[account]['title']])
                if len(accounts_temp[account]['title']) > 100:
                    print(banner)
                    print("The title '" + str(accounts_temp[account]['title']) + "' is greater than 100 characters.  Please shorten the title to less than 100 characters and try importing again.")
                    print(banner)
                    logging.error("The user attempted to add a title to the vault that was greater than 100 characters.")
                    return
                elif accounts_temp[account]['title'] in vault_dict:
                    print(banner)
                    print("The title '" + str(accounts_temp[account]['title']) + "' already exists in your password vault.  Please delete the existing entry from your password vault or change the title in your import file and try again.")
                    print(banner)
                    logging.error("The user attempted to add a title to the vault that already existed.")
                    return           
                accounts_dict[accounts_temp[account]['title']]['username'] = accounts_temp[account]['username']
                if len(accounts_dict[accounts_temp[account]['title']]['username']) > 100:
                    print(banner)
                    print(str(accounts_temp[account]['title']) + "'s username is greater than 100 characters.  Please shorten the username to less than 100 characters and try importing again.")
                    print(banner)
                    logging.error("The user attempted to add a username to the vault that was greater than 100 characters.")
                    return
                accounts_dict[accounts_temp[account]['title']]['password'] = accounts_temp[account]['password']
                if len(accounts_dict[accounts_temp[account]['title']]['password']) <= 0 or len(accounts_dict[accounts_temp[account]['title']]['password']) > 100:
                    print(banner)
                    print(str(accounts_temp[account]['title']) + "'s password is greater than 100 characters.  Please shorten the password to less than 100 characters and try importing again.")
                    print(banner)
                    logging.error("The user attempted to add a password to the vault that was greater than 100 characters.")
                    return
                accounts_dict[accounts_temp[account]['title']]['url'] = accounts_temp[account]['url']
                if len(accounts_dict[accounts_temp[account]['title']]['url']) > 500:
                    print(banner)
                    print(str(accounts_temp[account]['title']) + "'s URL is greater than 500 characters.  Please shorten the URL to less than 500 characters and try importing again.")
                    print(banner)
                    logging.error("The user attempted to add a URL to the vault that was greater than 500 characters.")
                    return
                #print(accounts_dict[accounts_temp[account]['title']])
        except KeyError:
            print(banner)
            print('Please select a valid CSV file.  The column headings should include "title", "username", "password", and "url".')
            print(banner)
            logging.error("The user attempted to import " + str(filename) + ", but was in an invalid format or it was missing the correct headings.")
            logging.debug("Import Password function completed with errors.")
            return
        #print(accounts_dict)
        accounts_dict.update(vault_dict)
        logging.info(str(len(accounts_temp.keys())) + " entries were added to the password vault.")
        # Encrypt the vault after adding the existing vault to the accounts_dict vault.
        encrypt_vault(cipher_suite, accounts_dict)
        print(banner)
        print("Your password entry has been added to the vault.")
        print(banner)
        logging.debug("Import Password function completed successfully.")
        return
    else:
        print(banner)
        print('Please select a valid CSV file.  The column headings should include "title", "username", "password", and "url".')
        print(banner)
        logging.error("The user attempted to import " + str(filename) + ", but was in an invalid format or it was missing the correct headings.")
        logging.debug("Import Password function completed with errors.")
        return
'''

# This function is used to determine if a password vault has no password entries.
def is_vault_empty(vault_passwords):
    logging.debug("Is Vault Empty function started.")
    # Set the empty_vault variable to False.
    empty_vault = False
    # If the vault_passwords variable is empty then set empty_value to True and print Vault is empty.  If the vault is not empty, then return empty_vault = False.
    if not vault_passwords:
        empty_vault_alert()
        empty_vault = True
        logging.debug("Is Vault Empty function completed successfully.")
        return empty_vault
    else:
        logging.debug("Is Vault Empty function completed successfully.")
        return empty_vault

# This function is used to list all of your password entries.
def list_passwords(cipher_suite, vault_string):
    logging.debug("List Passwords function started.")
    # Set vault_passwords equal to the output of the decrypt_vault function.  This value should either be blank or a plain-text dictionary of the password vault.
    vault_passwords = decrypt_vault(cipher_suite, vault_string)
    # Check to see if the password vault is empty.
    empty_vault = is_vault_empty(vault_passwords)
    # If the password vault is empty then exit the list passwords function since there are no passwords to list.
    if empty_vault:
        logging.warning("The vault is empty so the program cannot list passwords.  Returning user to the Password Vault menu.")
        return
    # The j counter is used to add spacing between the password entries.
    j = 0
    # This variable is an alphabetical list of password entries.  If we did not sort it alphabetically with the vault_passwords.keys() set to lower, then the vault would sort uppercase and lowercase password entries separately and would be confusing to the user.
    order_dict_keys = sorted(vault_passwords.keys(), key=str.lower)
    # Loop through the alphabetical list of password entries and print a space between each password entry to make the vault easier to view.
    print(banner)
    for keys in order_dict_keys:
        if j > 0:
            print("")
        print(keys + ":")
        print("     Username: " + vault_passwords[keys]['username'])
        print("     Password: " + vault_passwords[keys]['password'])
        try:
            if vault_passwords[keys]['url'] != None and vault_passwords[keys]['url'] != "":
                print("     URL: " + vault_passwords[keys]['url'])
        except KeyError:
            logging.debug("There is no url listed for " + keys + ".  Skip printing the url to the user.")
            pass
        j += 1
    print(banner)
    logging.debug("List Passwords function completed successfully.")
    return

# This function is used to modify a password entry.
def modify_password(cipher_suite, vault_string):
    logging.debug("Modify Password function started.")
    # Set vault_passwords equal to the output of the decrypt_vault function.  This value should either be blank or a plain-text dictionary of the password vault.
    vault_passwords = decrypt_vault(cipher_suite, vault_string)
    # Check to see if the password vault is empty.
    empty_vault = is_vault_empty(vault_passwords)
    # If the password vault is empty then exit the modify passwords function since there are no passwords to modify.
    if empty_vault:
        return
    # The i counter is used to make a numeric list of entries.
    i = 1
    # The temp_dict is used to select a specific password entry.
    temp_dict = {}
    try:
        while True:
            # This variable is an alphabetical list of password entries.  If we did not sort it alphabetically with the vault_passwords.keys() set to lower, then the vault would sort uppercase and lowercase password entries separately and would be confusing to the user.
            ordered_dict_keys = sorted(vault_passwords.keys(), key=str.lower)
            print("Please select an entry to modify:")
            # Loop through the alphabetical list of password entries and print an integer beside each one so the user can use the integer to select a password entry.
            for keys in ordered_dict_keys:
                print(str(i) + ". " + keys)
                # The temp_dict variable stores the key for the integer that the user inputs.
                temp_dict[str(i)] = keys
                i += 1
            print("0. Cancel Modification")
            # The select_entry variable is the integer that is entered by the user.
            select_entry = input("> ")
            logging.info("User entered an Modify Password password entry of '" + str(select_entry) + "'.")
            print("")
            # If the user enters 0 then quit the function.
            if select_entry == "0":
                logging.info("User cancelled the Modify Password function.")
                return
            # The try statement ensures that the user enters a valid number.  If the user does not enter a valid number then we ask the user to try again.
            try:
                # The vault_passwords_dict_key string saves the password entry title from above, which will be used as a nested dictionary key later.
                vault_passwords_dict_key = temp_dict[select_entry]
                break
            except KeyError:
                print("Please enter a valid value.")
                logging.warning("User entered an invalid Modify Password password entry of '" + str(select_entry) + "'.")
                i = 1
    except AttributeError:
        empty_vault_alert()
        return
    while True:
        # Print out the password entry and confirm that the user wants to modify the specified password entry.  Since there are three ways to modify a password entry the user is given the option to modify the title, username, or password.
        print(banner)
        print("You have selected the following entry: " + vault_passwords_dict_key)
        print("Username: " + vault_passwords[vault_passwords_dict_key]['username'])
        print("Password: "+ vault_passwords[vault_passwords_dict_key]['password'])
        if "url" in vault_passwords[vault_passwords_dict_key]:
            print("URL: "+ vault_passwords[vault_passwords_dict_key]['url'])
        print(banner)
        print("")
        print("What would you like to modify?")
        print("1. Title")
        print("2. Username")
        print("3. Password")
        print("4. URL")
        print("0. Cancel Modification")
        # The entry_modification_selection variable is the integer that is entered by the user to select whether they want to modify the title, username, or password.
        entry_modification_selection = input("> ")
        logging.info("User entered a Modify Password modification option of '" + str(entry_modification_selection) + "'.")
        # If the user selects 1 then the password entry title is modified.
        if entry_modification_selection == "1":
            print("") 
            while True:
                # The entry_name_modification string contains the user's new title for the password entry.
                entry_name_modification = input("Please enter your new Title: ")
                # The if statement checks to see if the title already exists in the password vault.  If it does then we ask the user if they want to overwrite the existing password entry.
                if entry_name_modification in vault_passwords:
                    print("An entry with the title " + entry_name_modification + " already exists.  Enter 'yes' to overwrite the existing entry or enter anything else to cancel.")
                    title_modification_selection = input("> ")
                    if title_modification_selection.lower() == "yes":
                        # The if statement checks to make sure the title is between 1 and 100 characters.  If the title is not between 1 and 100 characters then we repeat the loop.
                        if len(entry_name_modification) >= 1 and len(entry_name_modification) <= 100:
                            vault_passwords[entry_name_modification] = vault_passwords.pop(vault_passwords_dict_key)
                            vault_passwords_dict_key = entry_name_modification
                            break
                        else:
                            print("Please enter a valid title between 1 and 100 characters.")
                            print("")
                            logging.warning("User entered an invalid title of '" + str(entry_name_modification) + "'.")
                            continue
                    else:
                        break
                # This else statement is used if the title does not exist in the password vault.
                else:
                    # The if statement checks to make sure the title is between 1 and 100 characters.  If the title is not between 1 and 100 characters then we repeat the loop.
                    if len(entry_name_modification) >= 1 and len(entry_name_modification) <= 100:
                        vault_passwords[entry_name_modification] = vault_passwords.pop(vault_passwords_dict_key)
                        vault_passwords_dict_key = entry_name_modification
                        break
                    else:
                        print("Please enter a valid title between 1 and 100 characters.")
                        print("")
                        logging.warning("User entered an invalid title of '" + str(entry_name_modification) + "'.")
                        continue
        # If the user selects 2 then the password entry username is modified.
        elif entry_modification_selection == "2":
            print("")
            # The while loop checks to make sure the username is less than 100 characters.  The username should not be a required field in cases where the password entry is just a PIN so the username can be blank by design.
            while True:
                username_modification = input("Please enter your new Username: ")
                if len(username_modification) <= 100:
                    vault_passwords[vault_passwords_dict_key]['username'] = str(username_modification)
                    break
                else:
                    print("Please enter a valid username less than 100 characters.")
                    logging.warning("User entered an invalid username of '" + str(username_modification) + "'.")
                    continue
        # If the user selects 3 then the password entry password is modified.
        elif entry_modification_selection == "3":
            print("")
            mypassword = password_generator()
            vault_passwords[vault_passwords_dict_key]['password'] = str(mypassword)
        # If the user selects 4 then the password entry url is modified.
        elif entry_modification_selection == "4":
            while True:
                url_modification = input("Please enter your new URL: ")
                if len(url_modification) <= 500:
                    vault_passwords[vault_passwords_dict_key]['url'] = str(url_modification)
                    break
                else:
                    print("Please enter a valid url less than 500 characters.")
                    logging.warning("User entered an invalid URL of '" + str(url_modification) + "'.")
                    continue
        # If the user selects 0 then the user is returned to the open_vault function.
        elif entry_modification_selection == "0":
            logging.info("User cancelled the Password Modification function.")
            break
        # The else statement ensures that the user selects a valid value.
        else:
            print("Please enter a valid value.")
            logging.info("User entered an invalid Modify Password menu choice of '" + str(entry_modification_selection) + "'.")
        i = 1
    # The vault is saved at the end of the modify_password function to save all changes that the user made.
    encrypt_vault(cipher_suite, vault_passwords)
    print(banner)
    logging.debug("Modify Password function completed successfully.")
    return

# This function is used to open an existing password vault.
def open_vault():
    logging.debug("Open Vault function started.")
    # This try catch is only necessary in case someone tries to intentionally mess with the program and delete/rename the vault.bin file while running the program.
    try:
        password_counter = 2
        while True:
            # Ask for the user's master password so the vault.bin file can be decrypted.
            password = input('Please enter your Master Password: ').encode("utf-8")
            # Get the salt and encrypted vault from the vault.bin file.
            salt_string, vault_string = vault_to_strings()
            # Create a key derivation function using PBKDF2HMAC, which uses a SHA256 hashing algorithm and 100,100 iterations.  The 100,100 iterations are unnecessary for this simple program, but were kept to make the program more realistic.  LastPass uses 100,100 iterations (https://support.logmeininc.com/lastpass/help/about-password-iterations-lp030027)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_string,
                iterations=100100
            )
            # The symmetric key is derived using the master password and the key derivation function.
            mykey = base64.urlsafe_b64encode(kdf.derive(password))
            try:
                # The cipher_suite object is used in other functions to encrypt and decrypt the vault with the symmetric key.
                cipher_suite = Fernet(mykey)
            except ValueError:
                vault_tampered()
            # This try except statement will check to make sure that the vault can be decrypted.  If the password is incorrect or the vault has been modified externally then the exception will notify the user.
            try:
                if vault_string != b'':
                    # This function doesn't need to be saved to a variable, it only needs to ensure that a valid symmetric encryption key is used to decrypt the vault.  If the vault cannot be decrypted with the symmetric encryption key then there is an error that is handled by the exception statement.
                    cipher_suite.decrypt(vault_string)
            except InvalidToken:
                if password_counter > 0:
                    print('Your Master Password is incorrect.  Please try entering your password again.  You have ' + str(password_counter) + ' attempt(s) remaining.')
                    print("")
                    if password_counter != 1:
                        logging.warning("The Master Password has been entered incorrectly.  There are "+ str(password_counter) + " attempts remaining.")
                    elif password_counter == 1:
                        logging.warning("The Master Password has been entered incorrectly.  There is "+ str(password_counter) + " attempt remaining.")
                    password_counter -= 1
                    continue
                else:
                    print('You have reached the maximum number of password attempts.  Please make sure your vault.bin file has not been modified and try again later.')
                    logging.critical("The Master Password has been entered incorrectly three times.  Exiting the program.")
                    sys.exit()
            logging.info("The Master Password has been entered correctly.")
            break
        while True:
            # Password Vault Main Menu
            ## The vault_string variable needs to be updated in case changes were made to it from another function (create, modify, and delete).  The vault_string is still encrypted.
            vault_string = vault_to_strings()[1]
            print("")
            print("Welcome to your vault.")
            print("Please select an option to proceed:")
            print("1. Create a new password entry")
            print("2. List password entries")
            print("3. Modify a password entry")
            print("4. Delete a password entry")
            print("5. Copy a password to your clipboard")
            #print("6. Import Password Entries")
            print("6. Log Out")
            print("0. Exit program!")
            # Saves the user's input to the vault_menu_choice string.
            vault_menu_choice = input("> ")
            logging.info("User entered an Open Vault menu choice of '" + str(vault_menu_choice) + "'.")
            print("")
            # If the user's input is 0 then exit the program completely.  Clear the clipboard in case any data was copied and set the following variables to None.
            if vault_menu_choice == '0':
                logging.info("User exited the program.")
                print("Exiting the program.")
                pyperclip.copy("")
                cipher_suite, password, vault_string, salt_string = None, None, None, None
                sys.exit()
            elif vault_menu_choice == '1':
                # The cipher suite is used to decrypt the vault_string variable.  Once we decrypt the vault we can add password entries to it.
                create_password(cipher_suite, vault_string)
            elif vault_menu_choice == '2':
                # The cipher suite is used to decrypt the vault_string variable so we can list the passwords.
                list_passwords(cipher_suite, vault_string)
            elif vault_menu_choice == '3':
                # The cipher suite is used to decrypt the vault_string variable.  Once we decrypt the vault we can modify the password entries.
                modify_password(cipher_suite, vault_string)
            elif vault_menu_choice == '4':
                # The cipher suite is used to decrypt the vault_string variable.  Once we decrypt the vault we can delete the password entries.
                delete_password(cipher_suite, vault_string)
            elif vault_menu_choice == '5':
                # The cipher suite is used to decrypt the vault_string variable so we can copy the passwords.
                copy_password(cipher_suite, vault_string)
            # This function works, but I'm disabling it because I don't want to risk the chance that it doesn't work.
            #elif vault_menu_choice == '6':
                # The cipher suite is used to decrypt the vault_string variable so we can copy the passwords.
                #import_password(cipher_suite, vault_string)
            elif vault_menu_choice == '6':
                # When logging out the clipboard is cleared and the following variables are set to None.
                pyperclip.copy("")
                cipher_suite, password, vault_string, salt_string = None, None, None, None
                logging.info("User logged out of the Password Vault.")
                logging.debug("Open Vault function completed successfully.")
                return
            else:
                print("Please enter a valid value.")
                logging.info("User entered an invalid Open Vault menu choice of '" + str(vault_menu_choice) + "'.")
    # If the vault.bin file is not found, let the user know.
    except FileNotFoundError:
        fnf_error()
        return

# This function is used to generate a password or enter one manually.
def password_generator():
    logging.debug("Password Generator function started.")
    while True:
        # Password Generator Menu
        print('Please make a selection for password creation:')
        print('1. Generate Password Automatically')
        print('2. Enter Password Manually')
        # Save the user's password creation selection to the password_generator_choice string.
        password_generator_choice = input("> ")
        logging.info("User entered a password generator choice of '" + str(password_generator_choice) + "'.")
        print("")
        # Generate the Password Automatically
        if password_generator_choice == '1':
            """
            I tried creating an insanely large password and my desktop computer, which has 64GB of RAM, was using upwards of 50GB of RAM for python to encrypt the password before I cancelled it.  Needless to say, any title, username, or password creation should be within acceptable limits, which I've deemed to be 100 characters.
            Example: 1000000000000000000000000000000000000000 character password.
            """
            # The password length should not be less than 0 or more than 100 characters.  To ensure that the user is put into the password creation loop, the default length of the password is set to -1, which will put the user in the following while loop.
            mypassword_length = -1
            while mypassword_length <= 0 or mypassword_length > 100:
                try:
                    # Update the mypassword_length integer with the desired length of the password.
                    mypassword_length = int(input("Enter the desired length of your password: "))
                    # When creating the password we should use lowercase, uppercase, numbers, and symbols so all of those characters are added to the all_chars string.
                    all_chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
                    # Double check that the password length is correct in case there's any tomfoolery.
                    if mypassword_length < 101 and mypassword_length > 0:
                        # Randomly select a character from the all_chars string and append it to mypassword.  Repeat this loop for the range/length of mypassword_length.
                        mypassword = ''.join(random.choice(all_chars) for i in range(mypassword_length))
                        logging.warning("User entered a password length of '" + str(mypassword_length) + "'.")
                    else:
                        print("Please enter a value between 1 and 100")
                        logging.warning("User entered an invalid password length of '" + str(mypassword_length) + "'.")
                        continue
                except ValueError:
                    # Reset the value of mypassword_length if the length is not within acceptable limits and let the user know to enter a valid number between 1 and 100.
                    print("Please enter a value between 1 and 100")
                    logging.warning("User generated an invalid password length of '" + str(len(mypassword_length)) + "'.")
                    # Reset the password length.
                    mypassword_length = -1
            # Break the user out of the password generator loop.
            break
        # Enter the Password Manually
        elif password_generator_choice == '2':
            mypassword = str(input('Please enter your password: '))
            # Make sure that the user does not try to bypass the 100 character limit.
            while len(mypassword) <= 0 or len(mypassword) > 100:
                print("Please enter a password between 1 and 100 characters.")
                print("")
                mypassword = str(input('Please enter your password: '))
                if len(mypassword) <= 0 or len(mypassword) > 100:
                    logging.warning("User manually entered an invalid password length of '" + str(len(mypassword)) + "'.")
            # Break the user out of the password generator loop.
            break
        else:
            print("Please enter a valid value.")
            logging.info("User entered an invalid password generator option of '" + str(password_generator_choice) + "'.")
    logging.debug("Password Generator function completed successfully.")
    return mypassword

# This function is used to save the vault.bin file.
def save_vault(salt, vault):
    logging.debug("Save Vault function started.")
    # Create an vault.bin file by concatenating the salt and the encrypted vault contents.
    with open("vault.bin", "wb") as vault_file:
        vault_file.write(salt + vault)
    vault_file.close()
    logging.debug("Save Vault function completed successfully.")
    return

# This function is used to print an error when a vault has been tampered with or is currently open and therefore cannot be edited.  It is easier to call this function in an exception instead of writing out the same print statements multiple times.
def vault_tampered():
    logging.debug("Vault Tampered function started.")
    print("\nPlease check and make sure that your vault.bin file has not been tampered with or that you do not have it currently open.  If you've run into an issue, please recreate your vault and try again.", end="\n\n")
    logging.debug("Vault Tampered function completed with errors.  Please check and make sure that the vault.bin file has not been tampered with or that it is not currently open.  If there is a recurring issue, please recreate the vault and try again.  Exiting the program.")
    sys.exit()

# This function is used to save the contents of the vault.bin into strings.
def vault_to_strings():
    logging.debug("Vault To Strings function started.")
    # Read the vault.bin file and save the first 32 bytes as the salt_string.  Save the rest of the bytes as the vault_string.
    try:
        with open("vault.bin", "rb") as vault_file:
            salt_string = vault_file.read(32)
            vault_string = vault_file.read()
        vault_file.close()
        logging.debug("Vault To Strings function completed successfully.")
        return salt_string, vault_string
    # If someone tries to be sneaky and replaces the vault.bin file with a blank file, a different bin file, or deletes data from the bin file, then catch the exception here.
    except (KeyError):
        logging.critical("Vault To Strings function completed with errors.  The vault.bin file has been tampered with.")
        vault_tampered()


# Create a separator that will be used globally
banner = '*' * 82

# Password Manager Main Menu
logging.info("User started the program.")
while True:
    try:
        # Creates the vault_exists boolean flag to determine whether or not the vault exists.
        vault_exists = False
        print("Welcome To Your New Password Manager!")
        print("Please select an option to proceed:")
        print("1. Create a new password vault")
        # Only print the open vault option if a password vault has already been created.  If the vault.bin file is found then set the vault_exists flag to True.
        if os.path.exists('vault.bin'):
            print("2. Open an existing password vault")
            vault_exists = True
        print("0. Exit program!")
        main_menu_choice = input("> ")
        logging.info("User entered a value of '" + str(main_menu_choice + "' at the main menu."))
        print("")
        # If the user's input is 0 then exit the program completely.  We do not need to clear the clipboard or change any variables since that is already done in the open_vault function (if the vault is opened).
        if main_menu_choice == '0':
            logging.info("User exited the program.")
            print("Exiting the program.")
            sys.exit()
        # Send the user to the create vault function.
        elif main_menu_choice == '1':
            create_vault()
        # Send the user to the open vault function if the vault exists.
        elif main_menu_choice == '2' and vault_exists:
            open_vault()
        # Ensure that the user selects a valid menu option.
        else:
            print("Please enter a valid value.")
            print("")
            logging.warning("User entered an invalid value of '" + str(main_menu_choice) + "' at the main menu.")
            continue
    except KeyboardInterrupt:
        logging.critical("User pressed Ctrl+C to exit the program.")
        sys.exit()
