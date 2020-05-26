import sys
import argparse
import sqlite3
from sqlite3 import Error
from getpass import getpass
from passencrypter import PasswordEncrypter


class PasswordsDb:

    def __init__(self, dbfile):
        self.__dbfile = dbfile
        self.__conn = sqlite3.connect(dbfile)
        self.__cursor = self.__conn.cursor()
        self.__createtable()


    def __createtable(self):
        self.__cursor.execute(
            '''CREATE TABLE IF NOT EXISTS passwords(
                    service_name TEXT,
                    password TEXT
                )'''
        )
        self.__conn.commit()


    def add(self, service_name, password):
        self.__cursor.execute(
            '''INSERT INTO passwords (service_name, password)
             VALUES(?,?)''',
            (service_name, password)
        )
        self.__conn.commit()


    def delete(self, service_name):
        self.__cursor.execute(
            '''DELETE FROM passwords
            WHERE service_name=?''', (service_name,)
        )
        self.__conn.commit()


    def getpass(self, service_name):
        self.__cursor.execute(
            '''SELECT password FROM passwords
            WHERE service_name=?''', (service_name,)
        )
        passtuple = self.__cursor.fetchone()

        if passtuple is not None:
            return passtuple[0]
        else:
            return None


    def close_conn(self):
        if self.__conn:
            self.__conn.close()


class PasswordManager:

    def __init__(self, action, service_name, dbfile, mastersalt, salt):
        self.__action = action
        self.__service_name = service_name
        self.__dbfile = dbfile
        self.__mastersalt = mastersalt
        self.__salt = salt
        self.__encrypter = PasswordEncrypter()
        self.__passdb = None


    def __authenticate(self):
        masterpass = None

        if self.__passdb.getpass('masterpassword') is None:
            print('This is your first time running password buddy')
            print('Please enter your master password:')
            masterpass = getpass()
            print('Renter your password:')
            masterpass2 = getpass()

            if masterpass == masterpass2:
                masterpass = self.__encrypter.hashpass(
                    masterpass, self.__mastersalt)
                self.__passdb.add('masterpassword', masterpass)
                print('Masterpassword is set')
            else:
                print('Passwords are not equal')
                sys.exit()
        else:
            print('Please enter your master password:')
            masterpass = getpass()
            masterpass = self.__encrypter.hashpass(
                masterpass, self.__mastersalt)
            dbpass = self.__passdb.getpass('masterpassword')
            if masterpass != dbpass:
                print('Authentication failed')
                sys.exit()


    def __exec_action(self):
        if self.__action == 'add':
            password = self.__passdb.getpass(self.__service_name)
            if password is not None:
                print('Password for given service already exists')
                sys.exit()

            password = self.__encrypter.genpass() # option to change pass length and chars
            encrypted = self.__encrypter.encrypt(
                'masterpassword', password, self.__salt)

            self.__passdb.add(self.__service_name, encrypted)
            print('Your password for ' +
                self.__service_name + ' is ' + password)

        elif self.__action == 'del':
            password = self.__passdb.getpass(self.__service_name)

            if password is not None and self.__service_name != 'masterpassword':
                self.__passdb.delete(self.__service_name)
                print('Password for ' + self.__service_name + ' deleted')
            else:
                print('No password for given service')

        elif self.__action == 'get':
            password = self.__passdb.getpass(self.__service_name)

            if password is not None and self.__service_name != 'masterpassword':
                decrypted = self.__encrypter.decrypt(
                    'masterpassword', password, self.__salt)
                print(decrypted)
            else:
                print('No password for given service')


    def start(self):
        try:
            self.__passdb = PasswordsDb(self.__dbfile)
            self.__authenticate()
            self.__exec_action()
        except Error as e:
            print('Error during connection with db')
            print(e)
        finally:
            self.__passdb.close_conn()


def parse_args():
        parser = argparse.ArgumentParser()
        parser.add_argument(
            'action',
            choices=['add', 'del', 'get'],
            help='Action to perform on passwords database'
        )
        parser.add_argument(
            'service_name',
            help='Name of the service that password is stored for'
        )
        return parser.parse_args()


def main():
    args = parse_args()
    passmanager = PasswordManager(
        args.action, args.service_name,
        'passwords.sqlite3', 'mastersalt', 'salt')

    passmanager.start()


if __name__ == '__main__':
    main()
