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

        response_type, length = struct.unpack('>HH', response[:4])
        if len(response) != 4 + length:
            print("Incomplete response")
            return None

        response_data = response[4:].decode('utf-8')
        return response_type, response_data

# 测试获取登录服务器地址
def test_login_server_address_request(host, port):
    data = {'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    response_type, response_data = send_request(host, port, 2, data)
    print(f'Login Server Address Response (Type {response_type}):', response_data)

# 测试发送保活消息
def test_keep_alive_message(host, port):
    data = {
        'username': 'testuser',
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    response_type, response_data = send_request(host, port, 5, data)
    print(f'Keep Alive Response (Type {response_type}):', response_data)

# 测试用户搜索
def test_user_search_message(host, port, username):
    data = {
        'username': username,
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    response_type, response_data = send_request(host, port, 6, data)
    print(f'User Search Response (Type {response_type}):', response_data)

# 运行测试
supernode_host = '127.0.0.1'  # 替换为您的超级节点服务器地址
supernode_port = 9001         # 替换为您的超级节点服务器端口

test_login_server_address_request(supernode_host, supernode_port)
test_keep_alive_message(supernode_host, supernode_port)
test_user_search_message(supernode_host, supernode_port, 'targetuser')
test_user_search_message(supernode_host, supernode_port, 'testuser')
