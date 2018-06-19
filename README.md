# shadowtunnel

## About

Secure tunnel which help you protecting your tcp traffic between your machine and your service on remote.

local machine <----> shadowtunnel <---> service on remote.

## Usage

```text
Usage of ./shadowtunnel:
  -E    outbound connection is encrypted
  -c    compress traffic (default true)
  -e    inbound connection is encrypted
  -f string
        forward address,such as : 127.0.0.1:8080
  -l string
        local listen address, such as : 0.0.0.0:33000 (default ":50000")
  -m string
        method of encrypt/decrypt, these below are supported :
        aes-192-ctr,aes-256-ctr,cast5-cfb,chacha20,aes-128-cfb,aes-192-cfb,
        rc4-md5,rc4-md5-6,chacha20-ietf,aes-128-ctr,bf-cfb,aes-256-cfb,des-cfb (default "aes-192-cfb")
  -p string
        password of encrypt/decrypt (default "shadowtunnel")
  -t int
        connection timeout seconds (default 3)
  -v    show version
```

## Example

1.http proxy

if we have a vps, IP is 2.2.2.2.

firstly, we start a http proxy on 2.2.2.2.

download http proxy program, execute below on line command on vps with root:

`wget https://github.com/snail007/goproxy/releases/download/v4.9/proxy-linux-amd64.tar.gz && tar zxfv proxy-linux-amd64.tar.gz && rm proxy-linux-amd64.tar.gz && mv proxy /usr/bin/ && proxy http -p 127.0.0.1:38080 &`

2.start a tunnel on vps

download shadowtunnel program, execute below on line command on vps with root:

`wget https://github.com/snail007/shadowtunnel/releases/download/v1.0/shadowtunnel-linux-amd64.tar.gz && tar zxfv shadowtunnel-linux-amd64.tar.gz && rm shadowtunnel-linux-amd64.tar.gz && mv shadowtunnel /usr/bin/`

start a tunnel on vps listening on :50000 and forward to 127.0.0.1:38080 :

`shadowtunnel -e -f 127.0.0.1:38080 -l :50000`

3.start a tunnel on local machine

start a tunnel on local machine listening on :50000 and forward to 2.2.2.2:50000 :

`shadowtunnel -E -f 127.0.0.1:38080 -l :50000`

4.set http proxy configuration in chrome

setting local chrome's http proxy configuration as below :

ip: 127.0.0.1

port: 50000

5.done
