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
            connection = connect(database = config['database'],
                                  host = config['host'],
                                  user = config['user'],
                                  password = config['password']
                        )
    except:
        print('Error connecting to PostgreSQL...')

    return connection


def encrypt_password(password):
    return hashpw(password.encode('utf-8'), gensalt())


def create_table():
    connection = connect_to_database()
    cursor = connection.cursor()

    query = """CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) NOT NULL,
        email VARCHAR(50) NOT NULL,
        password VARCHAR(128) NOT NULL
    )"""

    cursor.execute(query)
    connection.commit()

    cursor.close()
    connection.close()


def access_system():
    email = input('E-mail address: ').lower()
    password = getpass('Password: ')

    connection = connect_to_database()
    cursor = connection.cursor()

    try:
        print()
        query = f"SELECT email, password FROM users WHERE email = LOWER('{email}')"
        cursor.execute(query)
        rows = cursor.fetchall()

        for email_, password_ in rows:
            if email_ == email:
                password_match = checkpw(password.encode('utf-8'), password_.encode('utf-8'))

                if password_match:
                    print('Accessing...')
                else:
                    print('Incorrect password')

                print()
                break
        else:
            print('The e-mail address entered is not registered')

    except:
        print('Could not connect to the database')

    finally:
        cursor.close()
        connection.close()


def table_exists():
    result = None

    connection = connect_to_database()
    cursor = connection.cursor()

    try:
        query = "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users')"
        cursor.execute(query)
        result = cursor.fetchone()[0]

    except UndefinedTable as undefined:
        print(undefined)

    finally:
        cursor.close()
        connection.close()

    return result


def user_exists(email):
    result = None

    connection = connect_to_database()
    cursor = connection.cursor()

    query = f"SELECT COUNT(*) FROM users WHERE email = LOWER('{email}')"
    cursor.execute(query)
    result = cursor.fetchone()[0]

    return result


def insert_into_table(name, email, password):
    connection = connect_to_database()
    cursor = connection.cursor()

    try:
        if table_exists():
            query = f"INSERT INTO users (name, email, password) VALUES ('{name}', '{email}', '{password.decode('utf-8')}')"
            cursor.execute(query)
            connection.commit()
            print('Successfully registered ')

    except (Exception, DatabaseError) as error:
        print(error)
        connection.rollback()

    finally:
        cursor.close()
        connection.close()


def register_new_user():
    name = input('Name: ')
    email = input('E-mail address: ').lower()
    password = encrypt_password(getpass('Password: '))

    try:
        create_table()

        if user_exists(email):
            print('The user is already registered')
        else:
            insert_into_table(name, email, password)

    except UndefinedTable:
        print('An error occurred in the registration')


def menu():
    functions = {1: access_system, 2: register_new_user}
    options = {1: 'Access the system', 2: 'Register a new user'}

    try:
        [print(f'{key} - {value}') for key, value in options.items()] and print()

        entry = int(input('Enter the desired option: '))
        functions[entry]()

    except (KeyError, ValueError):
        print('Invalid option')


if __name__ == '__main__':

    if operating_system == 'nt': system('cls')
    else: system('clear')

    menu()
