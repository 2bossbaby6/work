import sqlite3
import datetime
import pickle
import secrets
import hashlib


peper = "hvvc273h2j12c7zm31mudn9larbd9l46"

class Customer(object):
    def __init__(self, customer_name, customer_password, email, customer_id, address, phone, children):
        self.is_manager = None
        self.customer_name = customer_name
        self.customer_password = customer_password
        self.address = address
        self.email = email
        self.phone = phone
        self.customer_id = customer_id
        self.children = children

    def new_pass(self, newpassword):
        self.customer_password = newpassword

    def get_customer_id(self):
        return self.customer_id

    def __str__(self):
        return "user:" + self.customer_name + ":" + self.customer_password + ":" + \
               ":" + self.address + ":" + self.phone + ":" + self.email + ":" + \
               str(self.customer_id)


class Child(object):
    def __init__(self, child_name, child_id, parent_name, parent_id, birthday_date):
        self.child_name = child_name
        self.child_id = child_id
        self.parent_name = parent_name
        self.parent_id = parent_id
        self.birthday_date = birthday_date


class CustomerChildORM:
    def __init__(self):
        self.current = None
        self.conn = None  # will store the DB connection
        self.cursor = None  # will store the DB connection cursor

    def open_DB(self):
        """
        will open DB file and put value in:
        self.conn (need DB file name)
        and self.cursor
        """
        self.conn = sqlite3.connect('CustomerChild.db')
        self.current = self.conn.cursor()

    def create_table(self):
        self.open_DB()
        self.current.execute(""" CREATE TABLE customers ( 
        customer_name TEXT,
        customer_password TEXT,
        email TEXT,
        customer_id INT,
        address TEXT,
        phone TEXT,
        salt TEXT,
        children TEXT)""")

        self.current.execute("""CREATE TABLE children (
        child_name TEXT,
        child_id INT,
        parent_name TEXT,
        parent_id INT,
        birthday_date TEXT)""")

        self.close_DB()

    def close_DB(self):
        self.conn.close()

    def commit(self):
        self.conn.commit()

    # All read SQL
    def change_column_type(self):
        self.open_DB()
        sql = """ALTER TABLE children 
        ALTER COLUMN birthday_date TEXT;"""
        self.current.execute(sql)
        self.commit()
        self.close_DB()

    def GetCustomerID(self, customer_name):
        self.open_DB()

        sql = """SELECT customer_id 
        FROM customer
        WHERE customer_name = '""" + str(customer_name) + "'"
        customer_id = self.current.execute(sql)

        self.commit()
        self.close_DB()
        return customer_id

    def GetOrders(self):
        pass

    def get_customers(self):
        self.open_DB()
        sql = """SELECT customer_name FROM customers"""
        self.current.execute(sql)
        results = self.current.fetchall()
        # Convert the results to a list of strings
        customers = [result[0] for result in results]

        self.commit()
        self.close_DB()

        return customers

    def get_customers_who_have_children(self):
        self.open_DB()

        sql = """SELECT DISTINCT customers.customer_name
        FROM customers
        INNER JOIN children
        ON customers.customer_id = children.parent_id"""
        self.current.execute(sql)
        res = self.current.fetchall()
        # Fetch the customer names
        customer_names = [row[0] for row in res]

        self.commit()
        self.close_DB()

        return customer_names

    def get_children(self, user_id):
        self.open_DB()
        sql = """SELECT children
        FROM customers WHERE customer_id = """ + str(user_id)
        self.current.execute(sql)
        res = self.current.fetchall()
        children_names = [row[0] for row in res]
        #children_names = children_names[0].split(",")
        self.commit()
        self.close_DB()
        return children_names

    def parent_login(self, user_name, user_password, user_id):
        self.open_DB()
        query = """SELECT salt FROM customers WHERE customer_name = '""" + str(user_name) + "' ;"
        self.current.execute(query)
        salt = self.current.fetchall()
        salt = salt[0][0]
        user_password = self.hash_password(user_password, salt, peper)
        sql = """SELECT * 
        FROM customers
        WHERE customer_name ='""" + str(user_name) + "' AND customer_password = '" + str(user_password) + "' AND customer_id = '" + str(user_id) + "'"

        self.current.execute(sql)
        res = self.current.fetchall()
        res = list(res[0])
        if len(res) != 0:
            return "yes"
        return "no"

    def child_login(self, child_name, child_id):
        self.open_DB()
        # query = """SELECT salt FROM customers WHERE customer_name = '""" + str(user_name) + "' ;"
        # self.current.execute(query)
        # salt = self.current.fetchall()
        # salt = salt[0][0]
        # user_password = self.hash_pasasword(user_password, salt, peper)
        sql = """SELECT * 
        FROM children
        WHERE child_name = '""" + str(child_name) + "' AND child_id = '" + str(child_id) + "' ;"

        self.current.execute(sql)
        res = self.current.fetchall()
        res = list(res[0])
        if len(res) != 0:
            return "yes"
        return "no"

    # __________________________________________________________________________________________________________________
    # __________________________________________________________________________________________________________________
    # ______end of read start write ____________________________________________________________________________________
    # __________________________________________________________________________________________________________________
    # __________________________________________________________________________________________________________________
    # __________________________________________________________________________________________________________________
    # All write SQL

    def withdraw_by_username(self, amount, username):
        """
        return true for success and false if failed
        """
        pass

    def order_product(self, customer_id, product_name):
        self.open_DB()
        sql = "SELECT MAX(order_id) FROM orders"
        self.current.execute(sql)
        res = self.current.fetchall()
        max_order_id = res[0]
        if max_order_id[0] == None:
            order_id = 1
        else:
            order_id = max_order_id[0] + 1

        sql = """INSERT INTO orders VALUES( """ + str(order_id) + ", " + str(customer_id) + ", '" \
              + str(datetime.date.today()) + "', '" + product_name + "')"
        self.current.execute(sql)

        self.commit()
        self.close_DB()
        return "order id is: " + str(order_id)


    def delete_customer(self, customer_id):
        self.open_DB()
        sql = """DELETE FROM customers
        WHERE customer_id = """ + str(customer_id)
        self.current.execute(sql)
        self.commit()
        self.close_DB()
        return "customer deleted"

    def insert_new_customer(self, customer_name, customer_password, email, address, phone):
        self.open_DB()

        sql = "SELECT MAX(customer_id) FROM customers"
        self.current.execute(sql)
        res = self.current.fetchall()
        max_customer_id = res[0]
        if max_customer_id[0] != None:
            customer_id = str(max_customer_id[0] + 1)
        else:
            customer_id = "1"

        salt = self.generate_salt()
        hashed_password = self.hash_password(str(customer_password), salt, peper)

        sql = "INSERT INTO customers VALUES ('" + customer_name + "', '" + hashed_password + "', '" + email + "', " + str(customer_id) + ", '" + address + "', " + str(phone) + ", '" + str(salt) + "', '')"
        self.current.execute(sql)
        self.commit()
        self.close_DB()
        return customer_id

    def generate_salt(self):
        """Generate a random salt."""
        length = 32
        return secrets.token_hex(length // 2)

    def hash_password(self, password, salt, pepper):
        """Hash a password with salt and pepper."""
        combined_data = password + salt + pepper

        hashed_data = hashlib.sha256(combined_data.encode()).hexdigest()

        return hashed_data

    # def insert_new_account(self,username,password,firstname,lastname,address,phone,email):
    def insert_new_child(self, child_name, parent_name, parent_id, birthday_date):
        self.open_DB()
        child_id = 0
        sql = "SELECT MAX(child_id) FROM children"
        self.current.execute(sql)
        res = self.current.fetchall()
        max_child_id = res[0]
        if max_child_id[0] != None:
            child_id = str(max_child_id[0] + 1)
        else:
            child_id = "1"
        ids = str(child_id) + str(child_name) + ","
        sql = """UPDATE customers 
                SET children = children || '""" + ids + """' WHERE customer_id = """ + str(parent_id) + ";"
        self.current.execute(sql)

        sql = """INSERT INTO children
        VALUES ('""" + str(child_name) + "', " + str(child_id) + ", '" + str(parent_name) + "', " + str(parent_id) +\
              ", '" + str(birthday_date) + """')"""
        self.current.execute(sql)

        self.commit()
        self.close_DB()
        print(res)
        return str(child_id)

    def update_customer(self, customer_id, customer_name, customer_password, email, address, phone):
        self.open_DB()
        sql = """Update customers
        SET customer_name = '""" + customer_name + """'
        WHERE customer_id = """ + str(customer_id)
        self.current.execute(sql)

        sql = """Update customers
                SET customer_password = '""" + customer_password + """'
                WHERE customer_id = """ + str(customer_id)
        self.current.execute(sql)

        sql = """Update customers
                SET email = '""" + email + """'
                WHERE customer_id = """ + str(customer_id)
        self.current.execute(sql)

        sql = """Update customers
                SET address = '""" + address + """'
                WHERE customer_id = """ + str(customer_id)
        self.current.execute(sql)

        sql = """Update customers
                SET phone = '""" + str(phone) + """'
                WHERE customer_id = """ + str(customer_id)
        self.current.execute(sql)

        self.commit()
        self.close_DB()
        return True

    def update_order(self, order_id, new_product_name):
        self.open_DB()
        sql = """UPDATE orders
        SET product_ordered = '""" + str(new_product_name) \
              + """' WHERE order_id = """ + str(order_id)
        self.current.execute(sql)
        self.commit()
        self.close_DB()
        return "order updated"


def main_test():
    user1 = Customer("Yos", "12345", "yossi", "zahav", "kefar saba", "123123123", "1111", 1)

    db = CustomerChildORM()
    db.delete_user(user1.customer_name)
    users = db.get_users()
    for u in users:
        print(u)


if __name__ == "__main__":
    main_test()
    #instance = CustomerChildORM()
    #CustomerChildORM.create_table(instance)