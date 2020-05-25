import sys
import argparse
import sqlite3
from sqlite3 import Error

from passwordencryptor import PasswordEncryptor


class PasswordsDb:

    def __init__(self, db_name):
        self.db_name = db_name
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.__create_table()


    def __create_table(self):
        self.cursor.execute(
            '''CREATE TABLE IF NOT EXISTS passwords(
                    service_name TEXT,
                    password TEXT
                )'''
        )
        self.conn.commit()


    def add_password(self, service_name, password):
        self.cursor.execute(
            '''INSERT INTO passwords (service_name, password)
             VALUES(?,?)''',
            (service_name, password)
        )
        self.conn.commit()


    def delete_password(self, service_name):
        self.cursor.execute(
            '''DELETE FROM passwords
            WHERE service_name=?''', (service_name,)
        )
        self.conn.commit()


    def get_password(self, service_name):
        self.cursor.execute(
            '''SELECT password FROM passwords
            WHERE service_name=?''', (service_name,)
        )
        return self.cursor.fetchone()


    def get_services(self):
        self.cursor.execute(
        'SELECT service_name FROM passwords'
        )
        return self.cursor.fetchall()


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
    parser.add_argument(
        '-ls',
        '--listservices',
        help = 'Lists all saved services',
        action='store_true'
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        passdb = PasswordsDb('passwords.sqlite3')
        pe = PasswordEncryptor()
        masterpass = None

        if passdb.get_password('masterpassword') is None:
            print('This is your first time running password buddy')
            print('Please enter your master password:')
            masterpass = input()
            print('Renter your password:')
            masterpass2 = input()

            if masterpass == masterpass2:
                masterpass = pe.hashpass(masterpass)
                passdb.add_password('masterpassword', masterpass)
                print('Your master password is: ' + masterpass)
                print('Please remember it :)')
            else:
                print('Passwords are not equal')
                sys.exit()
            
        else:
            print('Please enter your master password:')
            masterpass = input()
            masterpass = pe.hashpass(masterpass)
            dbpassword = passdb.get_password('masterpassword')[0]
            if masterpass != dbpassword:
                print('Authentication failed')
                sys.exit()

        if args.action == 'add':
            if passdb.get_password(args.service_name) is not None:
                print('Password for given service already exists')
                sys.exit()    
            password = pe.generate_password()
            encrypted = pe.encrypt('masterpassword', password)
            passdb.add_password(args.service_name, encrypted)
            print('Your password for ' + args.service_name + ' is ' + password)

        elif args.action == 'del':
            passdb.delete_password(args.service_name)
            print('Password for ' + args.service_name + ' deleted')
        
        elif args.action == 'get':
            password = passdb.get_password(args.service_name)
            
            if password is not None and args.service_name != 'masterpassword':
                decrypted = pe.decrypt('masterpassword', password[0])
                print(decrypted)
            else:
                print('No password for given service')

    except Error as e:
        print('Error during connection with db')
        print(e)
    finally:
        if passdb.conn:
            passdb.conn.close()


if __name__ == '__main__':
    main()
