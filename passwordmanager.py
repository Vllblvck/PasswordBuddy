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
    authenticate_user()
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


def authenticate_user():
    pass


def main():
    args = parse_args()
    try:
        passdb = PasswordsDb('passwords.sqlite3')
        authenticate_user()
        pe = PasswordEncryptor()

        if args.action == 'add':
            password = pe.generate_password()
            encrypted = pe.encrypt('masterpassword', password)
            passdb.add_password(args.service_name, encrypted)
        elif args.action == 'del':
            passdb.delete_password(args.service_name)
        elif args.action == 'get':
            password = passdb.get_password(args.service_name)
            if password is not None:
                decrypted = pe.decrypt('masterpassword', password[0])
                print(decrypted)
            else:
                print("No password for given service name")

    except Error as e:
        print('Error during connection with db')
        print(e)
    finally:
        if passdb.conn:
            passdb.conn.close()


if __name__ == '__main__':
    main()
