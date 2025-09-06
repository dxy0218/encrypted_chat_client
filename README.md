# Encrypted Chat Client

## 项目简介
该项目展示了如何使用 Python 的 `socket` 与 `cryptography` 库构建一个简易的端到端加密聊天工具。服务器启动后会生成对称密钥并负责转发消息，客户端通过密钥对消息进行加解密，实现安全通信。

## 应用场景
- 局域网或内网中的临时安全聊天
- 学习对称加密与网络编程的示例
- 快速演示加密通信流程

## 项目优势
- **安全性**：使用 `Fernet` 算法，对消息内容进行可靠加密
- **易上手**：服务器与客户端脚本简单，适合学习与定制
- **可扩展**：提供 Windows 打包脚本，支持一键构建安装程序
- **实时性**：自动显示连接延迟并支持大文件传输进度
- **消息回执与撤回**：提供已读提示并支持发送方撤回消息，命令行界面以颜色区分双方消息

## 系统兼容性
- 支持 Windows 7、8、10、11
- 兼容 Python 3.8 至 3.12，`setup_env.ps1` 可通过 `-PythonVersion` 参数指定所需版本

## 界面优化
图形化客户端现在提供滚动聊天记录与 Enter 快捷发送消息，更便于使用

## 快速开始
### 运行源代码
1. 安装依赖：`pip install -r requirements.txt`
2. 启动服务器：`python encrypted_chat/encrypted_chat_server.py`
3. 在另一终端启动客户端：`python encrypted_chat/encrypted_chat_client.py`
4. 输入消息即可通信；使用 `/file <路径>` 发送文件，终端会显示发送与接收进度
5. 需要撤回消息时使用 `/recall <消息ID>`，消息 ID 会在发送时显示
6. 客户端每隔数秒会显示与服务器之间的实时延迟，使用 `/exit` 退出
7. 更多命令详见 [CLI_USAGE.md](CLI_USAGE.md)

### 构建 Windows 安装包
项目提供 `build_windows_installer.py` 与 `setup_env.ps1` 用于自动构建 Windows 安装程序，详细步骤见 [WINDOWS_INSTALLER.md](WINDOWS_INSTALLER.md)。
安装完成后，可在开始菜单找到两种启动方式：
- **Encrypted Chat Client (CLI)**：命令提示符模式
- **Encrypted Chat Client (GUI)**：窗口界面模式

