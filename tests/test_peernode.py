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

# 测试添加/删除好友
def test_add_delete_buddy(host, port, username, operation):
    data = {
        'username': username,
        'operation': operation,
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    response_type, response_data = send_request(host, port, 8, data)
    print(f'Add/Delete Buddy Response (Type {response_type}):', response_data)

# 测试发送聊天消息
def test_send_chat_message(host, port, sender_username, receiver_username, content):
    data = {
        'sender_username': sender_username,
        'receiver_username': receiver_username,
        'content': content,
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    response_type, response_data = send_request(host, port, 9, data)
    print(f'Send Chat Message Response (Type {response_type}):', response_data)

# 运行测试
peernode_host = '127.0.0.1'  # 替换为您的对等节点服务器地址
peernode_port = 8002         # 替换为您的对等节点服务器端口

test_add_delete_buddy(peernode_host, peernode_port, 'buddyuser', 'add')
test_add_delete_buddy(peernode_host, peernode_port, 'buddyuser', 'delete')
test_send_chat_message(peernode_host, peernode_port, 'senderuser', 'receiveruser', 'Hello, this is a test message')
