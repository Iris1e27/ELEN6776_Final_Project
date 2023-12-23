import socket
import threading
import sqlite3
import hashlib
import struct
import json

# database
def create_connection(db_file):
    """ 创建一个数据库连接到SQLite数据库 """
    conn = None
    try:
        conn = sqlite3.connect(db_file, check_same_thread=False)
        return conn
    except sqlite3.Error as e:
        print(e)
    return conn

def create_tables(conn):
    """ 创建表格 """
    create_users_table = """
    CREATE TABLE IF NOT EXISTS users (
        username text PRIMARY KEY,
        hashed_password text NOT NULL
    );
    """
    create_supernodes_table = """
    CREATE TABLE IF NOT EXISTS supernodes (
        ip text PRIMARY KEY,
        port integer PRIMARY KEY
    );
    """
    try:
        c = conn.cursor()
        c.execute(create_users_table)
        c.execute(create_supernodes_table)
    except sqlite3.Error as e:
        print(e)

def add_user(conn, username, password):
    """ 添加新用户 """
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    sql = ''' INSERT INTO users(username, hashed_password) VALUES(?,?) '''
    cur = conn.cursor()
    cur.execute(sql, (username, hashed_password))
    conn.commit()
    
def delete_user(conn, username):
    """ 删除用户 """
    sql = ''' DELETE FROM users WHERE username = ? '''
    cur = conn.cursor()
    cur.execute(sql, (username,))
    conn.commit()

def register_user(conn, username, hashed_password):
    sql = ''' INSERT INTO users(username, hashed_password) VALUES(?,?) ON CONFLICT(username) DO NOTHING '''
    cur = conn.cursor()
    cur.execute(sql, (username, hashed_password))
    conn.commit()

def authenticate_user(conn, username, hashed_password):
    sql = 'SELECT hashed_password FROM users WHERE username = ?'
    cur = conn.cursor()
    cur.execute(sql, (username,))
    result = cur.fetchone()
    return result and result[0] == hashed_password


def add_supernode(conn, ip, port):
    """ 添加超级节点 """
    sql = ''' INSERT INTO supernodes(ip, port) VALUES(?,?) '''
    cur = conn.cursor()
    cur.execute(sql, (ip, port))
    conn.commit()

def remove_supernode(conn, ip):
    """ 移除超级节点 """
    sql = 'DELETE FROM supernodes WHERE ip = ?'
    cur = conn.cursor()
    cur.execute(sql, (ip,))
    conn.commit()

def query_all_supernodes(conn):
    """ 查询所有超级节点 """
    sql = 'SELECT ip, port FROM supernodes'
    cur = conn.cursor()
    cur.execute(sql)
    supernodes = cur.fetchall()
    return [{'ip': ip, 'port': port} for ip, port in supernodes]


# server parse request and make response
def parse_request(data):
    """解析请求数据"""
    if len(data) < 4:
        return None, None
    type_field, length_field = struct.unpack('>HH', data[:4])
    if len(data) < 4 + length_field:
        return None, None  # 数据长度不足，无法解析完整的JSON数据
    json_data = data[4:4 + length_field].decode('utf-8')
    try:
        data_field = json.loads(json_data)
    except json.JSONDecodeError:
        return None, None
    return type_field, data_field

def handle_client_connection(client_socket, conn):
    request = client_socket.recv(1024)
    type_field, data_field = parse_request(request)
    client_address = client_socket.getpeername()  # 获取客户端的IP地址和端口号

    if type_field is not None and data_field is not None:
        if type_field == 1:  
            response = handle_register_delete_SN_message(conn, data_field, client_address)
        elif type_field == 3:  
            response = handle_register_delete_user_message(conn, data_field)
        elif type_field == 4: 
            response = handle_authentication_message(conn, data_field)
        elif type_field == 7: 
            response = handle_query_SN_message(conn, data_field)
        else:
            response = create_response(type_field, 400, "Unknown request type", None)

        client_socket.send(response)
    else:
        print("Invalid request")
    client_socket.close()

def create_response(request_type, message_code, message_body, timestamp):
    response_data = {
        'request_type': request_type,
        'message_code': message_code,
        'message_body': message_body,
        'timestamp': timestamp
    }
    response_json = json.dumps(response_data)
    response = struct.pack('>HH', 0, len(response_json)) + response_json.encode('utf-8')
    return response


def handle_register_delete_SN_message(conn, data, client_address):
    operation = data['operation']  # 'register' 或 'delete'
    timestamp = data['timestamp']
    client_ip, client_port = client_address

    if operation == 'register':
        add_supernode(conn, client_ip, client_port)
        return create_response(1, 200, "SuperNode registered successfully", timestamp)
    elif operation == 'delete':
        remove_supernode(conn, client_ip)
        return create_response(1, 200, "SuperNode deleted successfully", timestamp)
    else:
        return create_response(1, 400, "Invalid operation", timestamp)

def handle_register_delete_user_message(conn, data):
    username = data['username']
    password = data['password']
    operation = data['operation']
    timestamp = data['timestamp']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if operation == 'register':
        register_user(conn, username, hashed_password)
        return create_response(3, 200, "User registered successfully", timestamp)
    elif operation == 'delete':
        delete_user(conn, username)
        return create_response(3, 200, "User deleted successfully", timestamp)

def handle_authentication_message(conn, data):
    username = data['username']
    password = data['password']
    timestamp = data['timestamp']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if authenticate_user(conn, username, hashed_password):
        return create_response(4, 200, "Authentication successful", timestamp)
    else:
        return create_response(4, 400, "Authentication failed", timestamp)


def handle_query_SN_message(conn, data):
    timestamp = data['timestamp']
    supernodes = query_all_supernodes(conn)
    message_body = {
        'supernodes': supernodes
    }
    return create_response(7, 200, message_body, timestamp)


# server connection
def start_tcp_server(address, port, conn):
    """ 启动TCP服务器监听指定端口 """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((address, port))
    server.listen(5)  # 最大挂起连接数
    print(f"Listening on {address}:{port}")

    while True:
        client_sock, address = server.accept()
        print(f"Accepted connection from {address[0]}:{address[1]}")
        client_handler = threading.Thread(
            target=handle_client_connection,
            args=(client_sock, conn)
        )
        client_handler.start()


# main
def main():
    db_file = 'loginserver.db'
    conn = create_connection(db_file)

    if conn is not None:
        create_tables(conn)
        # 启动TCP服务器
        start_tcp_server('0.0.0.0', 9999, conn)
    else:
        print("Error! 无法创建数据库连接。")

if __name__ == '__main__':
    main()
