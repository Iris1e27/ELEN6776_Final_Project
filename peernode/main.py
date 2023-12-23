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
    """ 创建超级节点、对等节点和在线对等节点表 """
    sql_create_friends_table = """
    CREATE TABLE IF NOT EXISTS friends (
        username TEXT PRIMARY KEY,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL
    );
    """
    sql_create_supernodes_table = """
    CREATE TABLE IF NOT EXISTS supernodes (
        ip TEXT,
        port INTEGER,
        PRIMARY KEY (ip, port)
    );
    """
    sql_create_peernodes_table = """
    CREATE TABLE IF NOT EXISTS peernodes (
        ip TEXT,
        port INTEGER,
        PRIMARY KEY (ip, port)
    );
    """
    sql_create_chat_history_table = """
    CREATE TABLE IF NOT EXISTS chat_history (
        sender_username TEXT NOT NULL,
        receiver_username TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp DATETIME NOT NULL PRIMARY KEY
    );
    """
    try:
        c = conn.cursor()
        c.execute(sql_create_friends_table)
        c.execute(sql_create_supernodes_table)
        c.execute(sql_create_peernodes_table)
        c.execute(sql_create_chat_history_table)
    except sqlite3.Error as e:
        print(e)
        
def add_friend(conn, username, ip, port):
    """ 添加好友 """
    sql = ''' INSERT INTO friends(username, ip, port) VALUES(?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, (username, ip, port))
    conn.commit()

def delete_friend(conn, username):
    """ 删除好友 """
    sql = ''' DELETE FROM friends WHERE username = ? '''
    cur = conn.cursor()
    cur.execute(sql, (username,))
    conn.commit()

def add_chat_message(conn, sender, receiver, content, timestamp):
    """ 添加聊天记录 """
    sql = ''' INSERT INTO chat_history(sender_username, receiver_username, content, timestamp) 
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, (sender, receiver, content, timestamp))
    conn.commit()

def add_supernode(conn, ip, port):
    """ 添加超级节点 """
    sql = ''' INSERT INTO supernodes(ip, port) VALUES(?,?) ON CONFLICT(ip) DO NOTHING '''
    cur = conn.cursor()
    cur.execute(sql, (ip, port))
    conn.commit()

def remove_supernode(conn, ip):
    """ 移除超级节点 """
    sql = ''' DELETE FROM supernodes WHERE ip = ? '''
    cur = conn.cursor()
    cur.execute(sql, (ip,))
    conn.commit()

def add_peernode(conn, ip, port):
    """ 添加对等节点 """
    sql = ''' INSERT INTO peernodes(ip, port) VALUES(?,?) ON CONFLICT(ip) DO NOTHING '''
    cur = conn.cursor()
    cur.execute(sql, (ip, port))
    conn.commit()

def remove_peernode(conn, ip):
    """ 移除对等节点 """
    sql = ''' DELETE FROM peernodes WHERE ip = ? '''
    cur = conn.cursor()
    cur.execute(sql, (ip,))
    conn.commit()

# peernode is client make request and parse response, also is server parse request and make response
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

    if type_field is not None and data_field is not None:
        if type_field == 8:
            response = handle_add_delete_buddy_message(conn, data_field)
        elif type_field == 9:
            response = handle_chat_message(conn, data_field)
        # ... 添加其他类型请求的处理
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

def handle_add_delete_buddy_message(conn, data):
    username = data['username']
    ip = data.get('ip', '')  # 对于删除操作，IP可能不是必需的
    port = data.get('port', 0)  # 对于删除操作，端口可能不是必需的
    operation = data['operation']
    timestamp = data['timestamp']

    if operation == 'add':
        add_friend(conn, username, ip, port)
        message = "Buddy added successfully"
    elif operation == 'delete':
        delete_friend(conn, username)
        message = "Buddy deleted successfully"
    else:
        return create_response(8, 400, "Invalid operation", timestamp)

    return create_response(8, 200, message, timestamp)

def handle_chat_message(conn, data):
    sender_username = data['sender_username']
    receiver_username = data['receiver_username']
    content = data['content']
    timestamp = data['timestamp']

    add_chat_message(conn, sender_username, receiver_username, content, timestamp)
    return create_response(9, 200, "Message sent successfully", timestamp)


def send_add_delete_buddy_request(host, port, username, operation, timestamp):
    data = {
        'username': username,
        'operation': operation,
        'timestamp': timestamp
    }
    send_request(host, port, 8, data)

def send_chat_message_request(host, port, sender_username, receiver_username, content, timestamp):
    data = {
        'sender_username': sender_username,
        'receiver_username': receiver_username,
        'content': content,
        'timestamp': timestamp
    }
    send_request(host, port, 9, data)

def send_request(host, port, request_type, data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        request_json = json.dumps(data)
        request = struct.pack('>HH', request_type, len(request_json)) + request_json.encode('utf-8')
        s.sendall(request)
        response = s.recv(1024)

        if len(response) < 4:
            print("Invalid response")
            return None

        response_type, length = struct.unpack('>HH', response[:4])
        if len(response) != 4 + length:
            print("Incomplete response")
            return None

        response_data = response[4:].decode('utf-8')
        return response_type, response_data


    
# server connection
def start_tcp_server(address, port, conn):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((address, port))
    server.listen(5)
    print(f"Listening on {address}:{port}")

    while True:
        client_sock, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(
            target=handle_client_connection,
            args=(client_sock, conn)
        )
        client_handler.start()

# main
def main():
    db_file = 'peernode.db'
    conn = create_connection(db_file)

    if conn is not None:
        create_tables(conn)
        # 启动TCP服务器
        start_tcp_server('0.0.0.0', 7777, conn)
    else:
        print("Error! 无法创建数据库连接。")

if __name__ == '__main__':
    main()
