#!/usr/bin/env python3
"""VNC Basic Auth 反向代理。

位于 websockify 之前，对每个 TCP 连接的首个 HTTP 请求检查 Basic Auth，
通过后把原始字节双向透传到上游。静态页 vnc.html 和 WebSocket 握手都带
Authorization 头，因此这一层能同时保护两者。

环境变量：
  VNC_AUTH_PORT          对外监听端口，默认 6080
  VNC_AUTH_UPSTREAM_HOST 上游主机，默认 127.0.0.1
  VNC_AUTH_UPSTREAM_PORT 上游端口，默认 6081
  XHS_VNC_USER           Basic Auth 用户名，默认 vnc
  XHS_VNC_PASSWORD       Basic Auth 密码；留空则生成随机密码并写到数据目录
  VNC_AUTH_REALM         Basic Auth realm，默认 XHS VNC
"""
import base64
import hmac
import os
import secrets
import socket
import socketserver
import string
import sys
import threading
from urllib.parse import urlparse

LISTEN_PORT = int(os.environ.get("VNC_AUTH_PORT", "6080"))
UPSTREAM_HOST = os.environ.get("VNC_AUTH_UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.environ.get("VNC_AUTH_UPSTREAM_PORT", "6081"))
REALM = os.environ.get("VNC_AUTH_REALM", "XHS VNC")
USER = os.environ.get("XHS_VNC_USER") or "vnc"

# 密码文件跟 cookies 同目录（已挂载卷），容器重启后仍可复用同一随机密码。
cookies_path = os.environ.get("COOKIES_PATH", "/app/data/cookies.json")
PASSWORD_FILE = os.path.join(os.path.dirname(cookies_path), "vnc_password.txt")


def load_password():
    env_password = os.environ.get("XHS_VNC_PASSWORD", "")
    if env_password:
        return env_password
    try:
        with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
            saved = f.read().strip()
            if saved:
                return saved
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"[vnc-auth] 读取密码文件失败: {exc}", file=sys.stderr, flush=True)

    alphabet = string.ascii_letters + string.digits
    generated = "".join(secrets.choice(alphabet) for _ in range(16))
    try:
        os.makedirs(os.path.dirname(PASSWORD_FILE), exist_ok=True)
        with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
            f.write(generated + "\n")
        os.chmod(PASSWORD_FILE, 0o600)
        print(f"[vnc-auth] 已生成随机密码并保存到 {PASSWORD_FILE}", flush=True)
    except OSError as exc:
        print(f"[vnc-auth] 保存密码文件失败: {exc}", file=sys.stderr, flush=True)
    return generated


PASSWORD = load_password()
print(f"[vnc-auth] 监听 :{LISTEN_PORT} -> {UPSTREAM_HOST}:{UPSTREAM_PORT}", flush=True)
print(f"[vnc-auth] VNC 账号: {USER}", flush=True)
print(f"[vnc-auth] VNC 密码: {PASSWORD}", flush=True)

UNAUTHORIZED = (
    "HTTP/1.1 401 Unauthorized\r\n"
    f'WWW-Authenticate: Basic realm="{REALM}"\r\n'
    "Content-Type: text/plain; charset=utf-8\r\n"
    "Content-Length: 0\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode("latin-1")

FORBIDDEN = (
    "HTTP/1.1 403 Forbidden\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "Content-Length: 0\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode("latin-1")

MAX_HEADER_BYTES = 64 * 1024


def read_headers(sock):
    """读到 HTTP 头结束；返回已读字节和是否完整。数据可能包含头之后的字节，需一并转发。"""
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return bytes(buf), False
        buf.extend(chunk)
        if len(buf) > MAX_HEADER_BYTES:
            return bytes(buf), False
    return bytes(buf), True


def header_value(head, name):
    prefix = name.lower().encode("latin-1") + b":"
    for line in head.split(b"\r\n"):
        if line.lower().startswith(prefix):
            return line.split(b":", 1)[1].strip().decode("latin-1", "ignore")
    return ""


def authorized(head):
    for line in head.split(b"\r\n"):
        if not line.lower().startswith(b"authorization:"):
            continue
        value = line.split(b":", 1)[1].strip()
        if not value.lower().startswith(b"basic "):
            return False
        try:
            decoded = base64.b64decode(value[6:]).decode("utf-8")
        except Exception:
            return False
        user, sep, password = decoded.partition(":")
        if not sep:
            return False
        return hmac.compare_digest(user, USER) and hmac.compare_digest(password, PASSWORD)
    return False


def same_origin(head):
    """WebSocket 握手带 Origin 时，要求与 Host 同源，防止被其他网站跨站操控桌面。

    同时兼容 SSH 转发和公网 IP：不写死来源白名单，只比较请求自身携带的两个头。
    """
    origin = header_value(head, "Origin")
    if not origin:
        return True
    host = header_value(head, "Host")
    if not host:
        return False
    try:
        parsed = urlparse(origin)
    except ValueError:
        return False
    return parsed.netloc.lower() == host.lower()


def pump(src, dst):
    """单向转发原始字节；结束后关闭写方向，让对端能读完剩余数据。"""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class AuthHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        upstream = None
        try:
            client.settimeout(20)
            head, complete = read_headers(client)
            if not complete:
                return
            if not same_origin(head):
                client.sendall(FORBIDDEN)
                return
            if not authorized(head):
                client.sendall(UNAUTHORIZED)
                return
            upstream = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=10)
            upstream.sendall(head)
            client.settimeout(None)
            upstream.settimeout(None)
            to_up = threading.Thread(target=pump, args=(client, upstream), daemon=True)
            to_client = threading.Thread(target=pump, args=(upstream, client), daemon=True)
            to_up.start()
            to_client.start()
            to_up.join()
            to_client.join()
        except OSError as exc:
            print(f"[vnc-auth] 转发失败 {self.client_address[0]}: {exc}", file=sys.stderr, flush=True)
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass


class AuthServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    server = AuthServer(("0.0.0.0", LISTEN_PORT), AuthHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
