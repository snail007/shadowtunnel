# shadowtunnel

## 介绍

shadowtunnel 是一款可以在你本地机器和远程服务之间建立安全的加密隧道，保护你的 tcp 流量，能高效压缩传输，流量无特征.

local machine <----> shadowtunnel <---> service on remote.

## 使用

```text
Usage of ./shadowtunnel:
  -E  outbound connection is encrypted
  -U  outbound connection is udp
  -c  compress traffic (default true)
  -debug
      show debug info
  -e  inbound connection is encrypted
  -f string
      forward address,such as : 127.0.0.1:8080
  -l string
      local listen address, such as : 0.0.0.0:33000 (default ":50000")
  -m string
      method of encrypt/decrypt, these below are supported :
      aes-192-cfb,aes-128-ctr,aes-256-ctr,bf-cfb,rc4-md5-6,chacha20-ietf,
      aes-128-cfb,aes-256-cfb,aes-192-ctr,des-cfb,cast5-cfb,rc4-md5,chacha20
      (default "aes-192-cfb")
  -p string
      password of encrypt/decrypt (default "shadowtunnel")
  -t int
      connection timeout seconds (default 3)
  -u  inbound connection is udp
  -v  show version
```

## 示例

1.http 代理

假设有一个 vps，它的 IP 是 2.2.2.2

首先在 2.2.2.2 启动一个 http 代理
然后下载 http 代理程序，使用 root 权限在 vps 上执行下面的命令：

wget https://github.com/snail007/goproxy/releases/download/v4.9/proxy-linux-amd64.tar.gz && tar zxfv proxy-linux-amd64.tar.gz && rm proxy-linux-amd64.tar.gz && mv proxy /usr/bin/ && proxy http -p 127.0.0.1:38080 &

2.在 vps 启动一个隧道

下载 shadowtunnel 程序，使用 root 权限在 vps 上执行下面的命令：

wget https://github.com/snail007/shadowtunnel/releases/download/v1.0/shadowtunnel-linux-amd64.tar.gz && tar zxfv shadowtunnel-linux-amd64.tar.gz && rm shadowtunnel-linux-amd64.tar.gz && mv shadowtunnel /usr/bin/

在 vps 上监听 :50000 并转发到 127.0.0.1:38080 ：

shadowtunnel -e -f 127.0.0.1:38080 -l :50000

3.在本地机器上启动一个隧道

在本地机器上监听 :50000 并转发到 2.2.2.2:50000 :

shadowtunnel -E -f 2.2.2.2:50000 -l :50000

4.在 chrome 中设置 http 代理配置

设置本地 chrome 的http代理配置如下：

ip: 127.0.0.1
port: 50000

5.完成

## TCP over UDP

1.http 代理

假设有一个 vps，它的 IP 是 2.2.2.2

首先在 2.2.2.2 启动一个 http 代理
然后下载 http 代理程序，使用 root 权限在 vps 上执行下面的命令：

`wget https://github.com/snail007/goproxy/releases/download/v4.9/proxy-linux-amd64.tar.gz && tar zxfv proxy-linux-amd64.tar.gz && rm proxy-linux-amd64.tar.gz && mv proxy /usr/bin/ && proxy http -p 127.0.0.1:38080 &`

2.在 vps 启动一个隧道

下载 shadowtunnel 程序，使用 root 权限在 vps 上执行下面的命令：

`wget https://github.com/snail007/shadowtunnel/releases/download/v1.0/shadowtunnel-linux-amd64.tar.gz && tar zxfv shadowtunnel-linux-amd64.tar.gz && rm shadowtunnel-linux-amd64.tar.gz && mv shadowtunnel /usr/bin/`

在 vps 上监听UDP :50000 并转发到TCP 127.0.0.1:38080 ：

`shadowtunnel -u -e -f 127.0.0.1:38080 -l :50000 -p your-password`

3.在本地机器上启动一个隧道

在本地机器上监听TCP :50000 并转发到UDP 2.2.2.2:50000 :

`shadowtunnel -D -E -f 2.2.2.2:50000 -l :50000 -p your-password`

4.在 chrome 中设置 http 代理配置

设置本地 chrome 的http代理配置如下：

ip: 127.0.0.1
port: 50000

5.完成