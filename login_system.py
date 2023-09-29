import logging
import re
from bcrypt import checkpw, hashpw, gensalt
from dotenv import dotenv_values
from getpass import getpass
from os import path, system, name as operating_system
from psycopg2 import connect, DatabaseError
from psycopg2.errors import UndefinedTable


def connect_to_database():
    connection = None

    try:
        if path.exists('.env'):
            config = dotenv_values('.env', encoding='utf-8')
            connection = connect(
                database=config['database'],
                user=config['user'],
                password=config['password'],
                host=config['host']
            )

    except Exception:
        print('Error connecting to PostgreSQL...')

    return connection


def encrypt_password(password):
    salt = gensalt()
    hashed_password = hashpw(password.encode('utf-8'), salt)
    return hashed_password


def create_table():
    try:
        connection = connect_to_database()
        cursor = connection.cursor()

        query = """CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(75) NOT NULL,
            email VARCHAR(75) NOT NULL,
            password VARCHAR(128) NOT NULL
        )"""

    except Exception as error:
        logging.error(error)

    finally:
        if connection:
            cursor.execute(query)
            connection.commit()

            cursor.close()
            connection.close()


def email_validation(email):
    domains = ['gmail', 'hotmail', 'icloud', 'outlook', 'protonmail', 'yahoo']

    for domain in domains:
        pattern = rf'(?:^[a-z]+[-_.]{{0,1}}[a-z]{{1,}}[0-9]{{0,}}\@{domain}\.com$)'
        match = bool(re.findall(pattern, email, re.IGNORECASE))

        if match:
            return True

    return False


def access_system():
    while True:
        email = input('E-mail address: ').lower()        
        if email_validation(email):
            break
        else:
            print('Invalid e-mail address. Try again.')

    while True:
        password = getpass('Password: ')
        if len(password):
            break

    connection = connect_to_database()
    cursor = connection.cursor()

    try:
        print()
        query = f"SELECT email, password FROM users WHERE email = LOWER('{email}')"
        cursor.execute(query)
        rows = cursor.fetchall()

        for email_db, password_db in rows:
            if email_db == email:
                if checkpw(password.encode('utf-8'), password_db.encode('utf-8')):
                    print('Accessing...')
                else:
                    print('Incorrect password')

                print()
                break
        else:
            print('The provided e-mail address is not registered.')

    except Exception:
        print('Unable to connect to the database.')

    finally:
        cursor.close()
        connection.close()


def check_table_existence():
    result = None

    try:
        connection = connect_to_database()
        cursor = connection.cursor()

        query = "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users')"
        cursor.execute(query)
        result = cursor.fetchone()[0]

    except UndefinedTable as undefined:
        print(undefined)

    finally:
        if connection:
            cursor.close()
            connection.close()

    return result


def check_user_existence(email):
    result = None

    try:
        connection = connect_to_database()
        cursor = connection.cursor()

        query = f"SELECT COUNT(*) FROM users WHERE email = LOWER('{email}')"
        cursor.execute(query)
        result = cursor.fetchone()[0]

    except Exception as error:
        logging.error(error)

    return result


def insert_into_table(name, email, password):
    try:
        connection = connect_to_database()
        cursor = connection.cursor()

        if check_table_existence():
            query = f"INSERT INTO users (name, email, password) VALUES ('{name}', '{email}', '{password.decode('utf-8')}')"
            cursor.execute(query)
            connection.commit()
            print('Successfully registered.')

    except DatabaseError as db_error:
        logging.error(db_error)
        connection.rollback()

    except Exception as error:
        logging.error(error) 

    finally:
        if connection:
            cursor.close()
            connection.close()


def create_user_account():
    name = input('Name: ')

    while True:
        email = input('E-mail address: ').lower()
        if email_validation(email):
            break
        else:
            print('Invalid e-mail address. Try again.')

    while True:
        password = getpass('Password: ')
        if len(password) >= 8:
            password = encrypt_password(password)
            break
        else:
            print('Your password must be at least 8 characters long.')

    try:
        create_table()

        if check_user_existence(email):
            print('User already registered.')
        else:
            insert_into_table(name, email, password)

    except UndefinedTable:
        print('Registration failed.')


def main():
    functions = {1: access_system, 2: create_user_account}
    options = {1: 'Sign in to your account', 2: 'Create a new account'}

    try:
        [print(f'{key} - {value}') for key, value in options.items()] and print()

        entry = int(input('Please, enter your desired option: '))
        functions[entry]()

    except (KeyError, ValueError):
        print('Invalid option')


if __name__ == '__main__':
    match operating_system:
        case 'nt':
            system('cls')
        case default:
            system('clear')

    main()
