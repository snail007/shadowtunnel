# shadowtunnel

## Introduce

shadowtunnel is a secure encryption tunnel between your local machine and remote service to protect your TCP flow，

which can efficiently compress transmission, and the flow has no characteristics.

local machine <----> shadowtunnel <----> service on remote.

## Usage

```text
Usage of ./shadowtunnel:
  -E    outbound connection is encrypted
  -U    outbound connection is udp
  -c    compress traffic
  -cache string
        dns query cache file path (default "cache.dat")
  -daemon
        daemon mode
  -debug
        show debug info
  -dns string
        local dns server listen on address
  -dns-hosts string
        path of dns hosts file
  -dns-proxy
        is dns endpoint or not
  -dns-server string
        remote dns server to resolve domain (default "8.8.8.8:53")
  -e    inbound connection is encrypted
  -f weight
        forward address,such as : 127.0.0.1:8080 or with @weight: 127.0.0.1:8080@1
  -forever
        forever mode
  -l string
        local listen address, such as : 0.0.0.0:33000 (default ":50000")
  -lb-activeafter int
        host going actived after this success count (default 1)
  -lb-hashtarget hash
        use target address to choose parent for LB, only worked for LB's hash
        method and using `-redir` (default true)
  -lb-inactiveafter int
        host going inactived after this fail count (default 2)
  -lb-method string
        load balance method when use multiple parent,can be
        <roundrobin|leastconn|leasttime|hash|weight> (default "leasttime")
  -lb-onlyha high availability mode
        use only high availability mode to choose parent for LB
  -lb-retrytime int
        sleep time milliseconds after checking (default 2000)
  -lb-timeout int
        tcp milliseconds timeout of connecting to parent (default 3000)
  -log string
        logging output to file
  -m string
        method of encrypt/decrypt, these below are supported :
        aes-128-cfb,aes-192-cfb,des-cfb,cast5-cfb,rc4-md5,chacha20,aes-256-cfb,
        aes-128-ctr,aes-192-ctr,aes-256-ctr,bf-cfb,rc4-md5-6,chacha20-ietf
        (default "aes-192-cfb")
  -nolog
        turn off logging
  -p string
        password of encrypt/decrypt (default "shadowtunnel")
  -profiling
        profiling mode, in this mode, you should stopping process
        by : Ctrl+C or 'kill -s SIGHUP $PID_OF_shadowtunnel'
  -redir
        read target from socket's redirect opts of iptables
  -t int
        connection timeout seconds (default 3)
  -ttl int
        cache seconds of dns query , if zero , default ttl used. (default 300)
  -u    inbound connection is udp
  -v    show version
```

## 示例

1.http proxy

if we have a vps, IP is 2.2.2.2

firstly, we start a http proxy on 2.2.2.2.    
download http proxy program, execute below on line command on vps with root：

wget https://github.com/snail007/goproxy/releases/download/v4.9/proxy-linux-amd64.tar.gz && tar zxfv proxy-linux-amd64.tar.gz && rm proxy-linux-amd64.tar.gz && mv proxy /usr/bin/ && proxy http -p 127.0.0.1:38080 &

2.Start a tunnel on VPS

download shadowtunnel program, execute below on line command on vps with root：

wget https://github.com/snail007/shadowtunnel/releases/download/v1.1/shadowtunnel-linux-amd64.tar.gz && tar zxfv shadowtunnel-linux-amd64.tar.gz && rm shadowtunnel-linux-amd64.tar.gz && mv shadowtunnel /usr/bin/

start a tunnel on vps listening on :50000 and forward to 127.0.0.1:38080 ：

`shadowtunnel -e -f 127.0.0.1:38080 -l :50000`

3.start a tunnel on local machine

start a tunnel on local machine listening on :50000 and forward to 2.2.2.2:50000 :

`shadowtunnel -E -f 2.2.2.2:50000 -l :50000`

4.set http proxy configuration in chrome

setting local chrome's http proxy configuration as below：

ip: 127.0.0.1
port: 50000

5.done

## TCP over UDP

1.http 代理

if we have a vps, IP is 2.2.2.2.   

firstly, we start a http proxy on 2.2.2.2.    
download http proxy program, execute below on line command on vps with root：

`wget https://github.com/snail007/goproxy/releases/download/v4.9/proxy-linux-amd64.tar.gz && tar zxfv proxy-linux-amd64.tar.gz && rm proxy-linux-amd64.tar.gz && mv proxy /usr/bin/ && proxy http -p 127.0.0.1:38080 &`

2.start a tunnel on vps

download shadowtunnel program, execute below on line command on vps with root：

`wget https://github.com/snail007/shadowtunnel/releases/download/v1.1/shadowtunnel-linux-amd64.tar.gz && tar zxfv shadowtunnel-linux-amd64.tar.gz && rm shadowtunnel-linux-amd64.tar.gz && mv shadowtunnel /usr/bin/`

start a tunnel on vps listening on udp :50000 and forward to tcp 127.0.0.1:38080 ：

`shadowtunnel -u -e -f 127.0.0.1:38080 -l :50000 -p your-password`

3.start a tunnel on local machine

start a tunnel on local machine listening on tcp :50000 and forward to udp 2.2.2.2:50000 :

`shadowtunnel -U -E -f 2.2.2.2:50000 -l :50000 -p your-password`

4.set http proxy configuration in chrome

setting local chrome's http proxy configuration as below：

ip: 127.0.0.1
port: 50000

5.Done

## Deamon & Forever & Log

-daemon:

Using the parameter -daemon allows shadowtunnel to detached from the current command line and run in the background.

-forever:

Using parameter -forever allows shadowtunnel to run in the way of creating and monitoring child processes,

If an abnormal exit occurs, the child process will be restarted to ensure that the service is always online..

-log

Using parameter -log, you can set the log output to the file instead of the command line output.

-nolog

Using parameter -nolog can completely shut off log output and save CPU occupation.

Generally, the three parameters (-daemon -forever -log /tmp/st.log) are used together, so that we can find out the cause of the problem by looking at the log when we have a problem.

for example:

`shadowtunnel -u -e -f 127.0.0.1:38080 -l :50000 -p your-password -daemon -forever -log /tmp/st.log`

## DNS SERVICE

Shadowtunnel can provide local DNS query service, and has caching function to improve resolution speed.

It is necessary to have a superior service to start a DNS service while launching the port forwarding locally.

The -dns parameter sets the IP and port which the local DNS service listen, for example:0.0.0.0:5353

The -dns-server Parameters can be set to DNS servers that are ultimately used to resolve domain names, requiring the server to support TCP-style DNS queries, default:8.8.8.8:53.

for example:

`shadowtunnel -E -f 2.2.2.2:50000 -l :50000  -p your-password -dns :5353 -dns-server 8.8.8.8:53`

superior example:

If the superior is chain-style, then the superior of the DNS proxy in the chain is required to add the -dns-proxy parameter.

`shadowtunnel -e -f 127.0.0.1:38080 -l :50000 -p your-password -dns-proxy`

## DNS CACHE

The -ttl parameter can set the DNS query result cache time. unit is second. if it is 0, and use the TTL of the query result.

The -cache parameter sets DNS cache file location to prevent program restart and cache disappear, which will reduce performance.    

## LOAD BALANCE

Support superior load balancing, repeat -f parameters if exist multiple superiors.

`shadowtunnel -E -f 2.2.2.2:50000 -f 3.3.3.3:50000 -l :50000`

### SET RETRY INTERVAL AND TIMEOUT TIME

`shadowtunnel -E -f 2.2.2.2:50000 -f 3.3.3.3:50000 -l :50000 -lb-method leastconn -lb-retrytime 300 -lb-timeout 300`

### SETTING WEIGHT  

`shadowtunnel -E -f 2.2.2.2:50000@2 -f 3.3.3.3:50000@1 -l :50000 -lb-method weight -lb-retrytime 300 -lb-timeout 300`

### USE TARGET ADDRESS TO SELECT SUPERIOR

`shadowtunnel -E -f 2.2.2.2:50000@2 -f 3.3.3.3:50000@1 -l :50000 -lb-method hash -lb-hashtarget -lb-retrytime 300 -lb-timeout 300`

## DNS HOSTS DOCUMENT

The - DNS - hosts parameter sets the hosts file to be used when DNS is parsed, with the same content format as the system's hosts file.

`shadowtunnel -f 2.2.2.2:50000 -dns :5353 -dns-hosts /etc/hosts`
