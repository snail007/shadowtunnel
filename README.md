# shadowtunnel

## About

Secure tunnel which help you protecting your tcp traffic between your machine and your service on remote.

local machine <----> shadowtunnel <---> service on remote.

## Usage

```text
Usage of ./shadowtunnel:
  -E	outbound connection is encrypted
  -U	outbound connection is udp
  -c	compress traffic (default true)
  -debug
    	show debug info
  -e	inbound connection is encrypted
  -f string
    	forward address,such as : 127.0.0.1:8080
  -l string
    	local listen address, such as : 0.0.0.0:33000 (default ":50000")
  -m string
    	method of encrypt/decrypt, these below are supported :
    	aes-192-cfb,aes-128-ctr,des-cfb,bf-cfb,chacha20,chacha20-ietf,aes-128-cfb,aes-256-cfb,aes-192-ctr,aes-256-ctr,cast5-cfb,rc4-md5,rc4-md5-6 (default "aes-192-cfb")
  -p string
    	password of encrypt/decrypt (default "shadowtunnel")
  -t int
    	connection timeout seconds (default 3)
  -u	inbound connection is udp
  -v	show version
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

`shadowtunnel -E -f 2.2.2.2:50000 -l :50000`

4.set http proxy configuration in chrome

setting local chrome's http proxy configuration as below :

ip: 127.0.0.1

port: 50000

5.done

## TCP over UDP

1.http proxy

if we have a vps, IP is 2.2.2.2.

firstly, we start a http proxy on 2.2.2.2.

download http proxy program, execute below on line command on vps with root:

`wget https://github.com/snail007/goproxy/releases/download/v4.9/proxy-linux-amd64.tar.gz && tar zxfv proxy-linux-amd64.tar.gz && rm proxy-linux-amd64.tar.gz && mv proxy /usr/bin/ && proxy http -p 127.0.0.1:38080 &`

2.start a tunnel on vps

download shadowtunnel program, execute below on line command on vps with root:

`wget https://github.com/snail007/shadowtunnel/releases/download/v1.0/shadowtunnel-linux-amd64.tar.gz && tar zxfv shadowtunnel-linux-amd64.tar.gz && rm shadowtunnel-linux-amd64.tar.gz && mv shadowtunnel /usr/bin/`

start a tunnel on vps listening on udp :50000 and forward to tcp 127.0.0.1:38080 :

`shadowtunnel -u -e -f 127.0.0.1:38080 -l :50000 -p your-password`

3.start a tunnel on local machine

start a tunnel on local machine listening on tcp :50000 and forward to udp 2.2.2.2:50000 :

`shadowtunnel -D -E -f 2.2.2.2:50000 -l :50000 -p your-password`

4.set http proxy configuration in chrome

setting local chrome's http proxy configuration as below :

ip: 127.0.0.1

port: 50000

5.done

