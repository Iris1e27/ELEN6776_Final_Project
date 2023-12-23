import socket
import struct
import json
import time

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

        # 解析响应类型和数据长度
        response_type, length = struct.unpack('>HH', response[:4])
        if len(response) != 4 + length:
            print("Incomplete response")
            return None

        # 解析响应数据
        response_data = response[4:].decode('utf-8')
        return response_type, response_data


def test_register_user(host, port, username, password):
    data = {
        'username': username,
        'password': password,
        'operation': 'register',
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    response_type, response_data = send_request(host, port, 3, data)
    print('Register User Response:', response_type, response_data)

def test_login(host, port, username, password):
    data = {
        'username': username,
        'password': password,
        'IP': '127.0.0.1',
        'Port': 12345,
        'operation': 'login',
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    response_type, response_data = send_request(host, port, 4, data)
    print('Login Response:', response_type, response_data)

def test_register_supernode(host, port, operation):
    data = {
        'operation': operation,
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    response_type, response_data = send_request(host, port, 1, data)
    print('Register SuperNode Response:', response_type, response_data)

def test_query_supernode(host, port):
    data = {'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    response_type, response_data = send_request(host, port, 7, data)
    print('Query SuperNode Response:', response_type, response_data)

# 测试用例
server_host = 'localhost'
server_port = 9999

test_register_user(server_host, server_port, 'testuser', 'testpass')
test_login(server_host, server_port, 'testuser', 'testpass')
test_register_supernode(server_host, server_port, 'register')
test_query_supernode(server_host, server_port)