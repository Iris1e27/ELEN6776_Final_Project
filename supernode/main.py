import socket
import sys
import threading
import sqlite3
import hashlib
import struct
import json
import logging
import functools

# 配置日志
logging.basicConfig(filename='app.log', filemode='w', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

def log_decorator(func):
    """日志装饰器"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            logging.info(f"Function {func.__name__} started with args: {args} and kwargs: {kwargs}")
            result = func(*args, **kwargs)
            logging.info(f"Function {func.__name__} ended successfully")
            return result
        except Exception as e:
            logging.exception(f"Function {func.__name__} raised an exception: {e}")
            # 可以选择在这里重新抛出异常，或者返回某种错误表示
            raise 
    return wrapper

# database
@log_decorator
def create_connection(db_file):
    """ 创建一个数据库连接到SQLite数据库 """
    conn = None
    try:
        conn = sqlite3.connect(db_file, check_same_thread=False)
        return conn
    except sqlite3.Error as e:
        print(e)
    return conn

@log_decorator
def create_tables(conn):
    """ 创建超级节点、对等节点和在线对等节点表 """
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
    sql_create_online_peernodes_table = """
    CREATE TABLE IF NOT EXISTS online_peernodes (
        username TEXT PRIMARY KEY,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        last_keepalive TIMESTAMP NOT NULL
    );
    """
    try:
        c = conn.cursor()
        c.execute(sql_create_supernodes_table)
        c.execute(sql_create_peernodes_table)
        c.execute(sql_create_online_peernodes_table)
    except sqlite3.Error as e:
        print(e)

@log_decorator
def add_supernode(conn, ip, port):
    """ 添加超级节点 """
    sql = ''' INSERT INTO supernodes(ip, port) VALUES(?,?) ON CONFLICT(ip) DO NOTHING '''
    cur = conn.cursor()
    cur.execute(sql, (ip, port))
    conn.commit()

@log_decorator
def delete_supernode(conn, ip):
    """ 删除超级节点 """
    sql = ''' DELETE FROM supernodes WHERE ip = ? '''
    cur = conn.cursor()
    cur.execute(sql, (ip,))
    conn.commit()

@log_decorator
def add_peernode(conn, ip, port):
    """ 添加对等节点 """
    sql = ''' INSERT INTO peernodes(ip, port) VALUES(?,?) ON CONFLICT(ip) DO NOTHING '''
    cur = conn.cursor()
    cur.execute(sql, (ip, port))
    conn.commit()

@log_decorator
def delete_peernode(conn, ip):
    """ 删除对等节点 """
    sql = ''' DELETE FROM peernodes WHERE ip = ? '''
    cur = conn.cursor()
    cur.execute(sql, (ip,))
    conn.commit()

@log_decorator
def update_keepalive_peernodes(conn, username, ip, port):
    """ 更新对等节点的保活时间戳 """
    sql = ''' REPLACE INTO online_peernodes(username, ip, port, last_keepalive)
              VALUES(?, ?, ?, CURRENT_TIMESTAMP) '''
    cur = conn.cursor()
    cur.execute(sql, (username, ip, port))
    conn.commit()

@log_decorator
def remove_inactive_peernodes(conn, timeout_seconds=120):
    """ 删除超过特定时间未发送保活的对等节点 """
    sql = ''' DELETE FROM online_peernodes WHERE (strftime('%s', 'now') - strftime('%s', last_keepalive)) > ? '''
    cur = conn.cursor()
    cur.execute(sql, (timeout_seconds,))
    conn.commit()


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

@log_decorator
def handle_client_connection(client_socket, conn):
    request = client_socket.recv(1024)
    type_field, data_field = parse_request(request)
    client_address = client_socket.getpeername()

    if type_field is not None and data_field is not None:
        if type_field == 2:  
            response = handle_login_server_address_request(conn, data_field)
        elif type_field == 5:  
            response = handle_keep_alive_message(conn, data_field, client_address)
        elif type_field == 6: 
            response = handle_user_search_message(conn, data_field)
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

def handle_login_server_address_request(conn, data):
    timestamp = data['timestamp']
    # 假设登录服务器地址已知，可以从配置文件或环境变量中获取
    login_server_address = "127.0.0.1"  # 示例IP
    login_server_port = 9999  # 示例端口
    message_body = {
        'login_server_ip': login_server_address,
        'login_server_port': login_server_port
    }
    return create_response(2, 200, message_body, timestamp)

def handle_keep_alive_message(conn, data, client_address):
    username = data['username']
    timestamp = data['timestamp']
    ip, port = client_address
    update_keepalive_peernodes(conn, username, ip, port)
    remove_inactive_peernodes(conn, timeout_seconds=120)
    return create_response(5, 200, "Keepalive updated", timestamp)

def handle_user_search_message(conn, data):
    search_username = data['username']
    timestamp = data['timestamp']
    user_info = find_online_user(conn, search_username)
    if user_info:
        message_body = {
            'found_user_ip': user_info['ip'],
            'found_user_port': user_info['port']
        }
        return create_response(6, 200, message_body, timestamp)
    else:
        return create_response(6, 404, "User not found", timestamp)

def find_online_user(conn, username):
    """ 在在线用户表中搜索指定用户名的用户 """
    sql = ''' SELECT ip, port FROM online_peernodes WHERE username = ? '''
    cur = conn.cursor()
    cur.execute(sql, (username,))
    result = cur.fetchone()
    if result:
        return {'ip': result[0], 'port': result[1]}
    return None


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
def main(config_path):
    # 加载配置文件
    with open(config_path) as f:
        config = json.load(f)

    db_file = config['database_file']
    port = config['port']

    # 创建数据库连接
    conn = create_connection(db_file)
    if conn is not None:
        create_tables(conn)
        # 启动 TCP 服务器
        start_tcp_server('0.0.0.0', port, conn)
    else:
        print("Error! 无法创建数据库连接。")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python main.py <config_path>")
        sys.exit(1)
    
    config_path = sys.argv[1]
    main(config_path)