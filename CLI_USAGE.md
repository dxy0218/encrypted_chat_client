# 命令提示符使用手册

该手册介绍如何在命令提示符（CLI）下运行加密聊天客户端以及常用命令。

## 启动
1. 启动服务器：`python encrypted_chat/encrypted_chat_server.py`
2. 在另一终端运行客户端：`python encrypted_chat/encrypted_chat_client.py`

## 常用命令
- 直接输入文本并回车即可向对方发送消息。
- `/file <路径>`：发送指定文件，双方都会看到进度条。
- `/recall <消息ID>`：撤回之前发送的消息，消息 ID 会在发送时显示。
- `/exit`：退出客户端。

客户端界面使用颜色区分双方消息，并在对方读取消息后显示提示。
