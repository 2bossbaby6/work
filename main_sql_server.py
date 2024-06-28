import socket
import SQL_ORM
import os
import queue, threading, time, random
from tcp_by_size import send_with_size, recv_by_size
from socket import socket as socki
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from hashlib import sha256

DEBUG = True
exit_all = False

parents_list = {}
children_list = {}

users_keys = {}
IV = b'abndfgg76r4lt2m0'   # 16-byte IV for AES

def handel_client(client_socket, tid, db):
    global exit_all

    print("New Client num " + str(tid))

    while not exit_all:
        #try:
            data = decrypt_message(recv_by_size(client_socket),users_keys[client_socket], IV)
            important_data = data[5:]
            data = data[:5].decode()
            if data == "":
                print("Error: Seens Client DC")
                break
            print(data)

            if data[0:5] == "PAREN":
                to_send = parent_action(important_data, db, client_socket)  # send to the parent part
                send_with_size(client_socket, encrypt_message(to_send, users_keys[client_socket], IV))

            elif data[0:5] == "CHILD":
                to_send = child_action(important_data, db, client_socket)  # send to the child part
                send_with_size(client_socket, encrypt_message(to_send, users_keys[client_socket], IV))

        #except socket.error as err:
        #    if err.errno == 10054:
        #        # 'Connection reset by peer'
        #        print("Error %d Client is Gone. %s reset by peer." % (err.errno, str(client_socket)))
        #        break
        #    else:
        #        print("%d General Sock Error Client %s disconnected" % (err.errno, str(client_socket)))
        #        break

       # except Exception as err:
       #     print("General Error:" + str(err))
       #     break
    client_socket.close()


def child_action(data, db, client_socket):
    """
       check what client ask and fill to send with the answer
    """
    to_send = "Not Set Yet"
    action = data[:6].decode()
    if action == "TMNAGE":
        data = data[6:]
    else:
        data = data[7:]
    fields = ""
    if action != "TMNAGE":
        fields = data.decode().split('|')
    instance = SQL_ORM.CustomerChildORM()

    if DEBUG:
        print("Got client request " + action + " -- " + str(fields))

    if action == "UPDUSR":
        usr = SQL_ORM.CustomerChildORM.update_customer(instance, fields[0], fields[1], fields[2],
                                                       fields[3], fields[4], fields[5])
        if usr:
            to_send = "UPDUSRR|" + "Success"
        else:
            to_send = "UPDUSRR|" + "Error"

    elif action == "INSKID":  # Insert new child to db
        customer = SQL_ORM.CustomerChildORM.insert_new_child(instance, fields[0], fields[1], fields[2], fields[3])
        to_send = "INSKID|your id is: " + customer
    elif action == "TMNAGE":
        # Get the directory of the current script
        script_dir = os.path.dirname(os.path.abspath(__file__))

        decrypted_data = data
        with open('screen_time_S.db', 'wb') as f:
            f.write(decrypted_data)

        to_send = "GOTITT|"

    elif action == "LOGINN":
        child_name, child_id = fields[0], fields[1]
        children_list[child_id] = client_socket
        login = SQL_ORM.CustomerChildORM.child_login(instance, child_name, child_id)
        to_send = "LOGGINN|" + login

    else:
        print("Got unknown action from client " + action)
        to_send = "ERR___R|001|" + "unknown action"

    return to_send



# Function to perform actions based on client requests
def parent_action(data, db, client_socket):
    """
    check what client ask and fill to send with the answer
    """
    to_send = "Not Set Yet"
    data = data.decode()
    action = data[:6]
    child_id = ""
    if action == "LOGINN" or action == "INSPAR" or action == "GETKID" or action == "INSKID":
        data = data[7:]
    else:
        child_id = data[6]
        data = data[8:]
    fields = data.split('|')
    instance = SQL_ORM.CustomerChildORM()

    if DEBUG:
        print("Got client request " + action + " -- " + str(fields))

    if action == "UPDUSR":
        usr = SQL_ORM.CustomerChildORM.update_customer(instance, fields[0], fields[1], fields[2],
                                                       fields[3], fields[4], fields[5])
        if usr:
            to_send = "UPDUSRR|" + "Success"
        else:
            to_send = "UPDUSRR|" + "Error"

    elif action == "INSPAR":  # Insert new parent to data base
        customer = SQL_ORM.CustomerChildORM.insert_new_customer(instance, fields[0], fields[1], fields[2],
                                                                fields[3], fields[4])
        to_send = "INSPAR|your id is: " + customer

    elif action == "INSKID":  # Insert new child to db
        customer = SQL_ORM.CustomerChildORM.insert_new_child(instance, fields[0], fields[1], fields[2], fields[3])
        to_send = "INSKID|your id is: " + customer

    elif action == "ABREAK":  # create a break for the child

        section_time, break_time = fields[0], fields[1]

        to_send = "ABREAK|" + "A break was set"
        send_to_kid = "ABREAK|" + str(section_time) + "|" + str(break_time)
        send_with_size(children_list[child_id], encrypt_message(send_to_kid, users_keys[children_list[child_id]], IV))

    elif action == "MESSAG":  # get message
        message = fields[0]
        to_send = "MESSAG|" + str(message)
        send_with_size(children_list[child_id], encrypt_message(to_send, users_keys[children_list[child_id]], IV))

    elif action == "TMNAGE":  # screen time
        to_send = "TMNAGE"
        with open("screen_time_S.db", 'rb') as f:
            data2 = f.read()
            encrypted_data_db = encrypt_db(data2, users_keys[client_socket], IV)
            send_with_size(client_socket, encrypted_data_db)

    elif action == "BLOCKW":  # block website
        url = fields[0]
        to_send = str(url)
        if is_legal_url(url):
            sock = socki()
            sock.connect(("127.0.0.1", 5000))
            send_with_size(sock, to_send)
            sock.close()
            to_send = "BLOCKW|" + "website is now on the blocking list"
        else:
            to_send = "BLOCKW|" + "website's url was incorrect, try again"

    elif action == "GETKID":
        parent_id = fields[0]
        names_of_children = SQL_ORM.CustomerChildORM.get_children(instance, parent_id)
        to_send = str(names_of_children)

    elif action == "RULIVE":
        to_send = "RULIVER|" + "yes i am a live server"
    elif action == "LOGINN":
        user_name, user_password, user_id = fields[0], fields[1], fields[2]
        parents_list[user_id] = client_socket
        login = SQL_ORM.CustomerChildORM.parent_login(instance, user_name, user_password, user_id)
        to_send = "LOGGINN|" + login

    else:
        print("Got unknown action from client " + action)
        to_send = "ERR___R|001|" + "unknown action"

    return to_send


def find_file(self, file_name, search_dir='.'):
    for root, dirs, files in os.walk(search_dir):
        if file_name in files:
            return os.path.join(root, file_name)
    return None


def is_legal_url(url):
    # Regular expression pattern for basic URL format
    url_pattern = re.compile(r'^(http|https)://[a-zA-Z0-9\-\\.]+\.[a-zA-Z]{2,}(\S*)?$')

    # Check if the URL matches the pattern
    if re.match(url_pattern, url):
        return True
    else:
        return False


# Function to manage the queue
def q_manager(q, tid):
    global exit_all

    print("manager start:" + str(tid))
    while not exit_all:
        item = q.get()
        print("manager got somthing:" + str(item))
        # do some work with it(item)
        q.task_done()
        time.sleep(0.3)
    print("Manager say Bye")


def diffie_hellman(client_socket):
    # Diffie-Hellman parameters
    p = 23 # A prime number
    g = 5  # A primitive root modulo p

    # Server's private key
    a = random.randint(1, p - 1)

    # Calculate server's public key
    A = pow(g, a, p)

    # Send the public parameters and server's public key to the client
    send_with_size(client_socket, f"{p},{g},{A}".encode())

    # Receive client's public key
    B = int(recv_by_size(client_socket).decode())

    # Compute the shared secret
    shared_secret = pow(B, a, p)
    shared_secret_16_bits = shared_secret  # Truncate to 16 bits
    print(str(shared_secret).encode().zfill(16))
    users_keys[client_socket] = sha256(str(shared_secret).encode()).digest()
    print(f"Shared secret: {shared_secret}")
    print(users_keys[client_socket])


def encrypt_db(message, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_message

def encrypt_message(message, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_message


def decrypt_message(encrypted_message, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message

def main():
    global exit_all

    exit_all = False
    db = SQL_ORM.CustomerChildORM()

    s = socket.socket()

    q = queue.Queue()

    q.put("Hi for start")

    manager = threading.Thread(target=q_manager, args=(q, 0))

    s.bind(("0.0.0.0", 33445))

    s.listen(4)
    print("after listen")

    threads = []
    i = 1
    while True:
        client_socket, addr = s.accept()
        diffie_hellman(client_socket)
        t = threading.Thread(target=handel_client, args=(client_socket, i, db))
        t.start()
        i += 1
        threads.append(t)

    exit_all = True
    for t in threads:
        t.join()
    manager.join()

    s.close()


if __name__ == "__main__":
    main()
