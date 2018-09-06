package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	encryptconn "github.com/snail007/goproxy/core/lib/transport/encrypt"
	tou "github.com/snail007/goproxy/core/dst"
	clienttransport "github.com/snail007/goproxy/core/cs/client"
	srvtransport "github.com/snail007/goproxy/core/cs/server"
	utils "github.com/snail007/goproxy/utils"
)

const (
	VERSION = "1.1"
)

var (
	listenAddr      string
	forwardAddr     string
	timeout         int
	compress        bool
	method          string
	password        string
	listen          srvtransport.ServerChannel
	l               = log.New(os.Stderr, "", log.LstdFlags)
	err             error
	inboundEncrypt  bool
	outboundEncrypt bool
	inboundUDP      bool
	outboundUDP     bool
	Debug           bool
	version         bool
)

func main() {

	flag.StringVar(&listenAddr, "l", ":50000", "local listen address, such as : 0.0.0.0:33000")
	flag.StringVar(&method, "m", "aes-192-cfb", "method of encrypt/decrypt, these below are supported :\n"+strings.Join(encryptconn.GetCipherMethods(), ","))
	flag.StringVar(&password, "p", "shadowtunnel", "password of encrypt/decrypt")
	flag.StringVar(&forwardAddr, "f", "", "forward address,such as : 127.0.0.1:8080")
	flag.IntVar(&timeout, "t", 3, "connection timeout seconds")
	flag.BoolVar(&compress, "c", true, "compress traffic")
	flag.BoolVar(&inboundEncrypt, "e", false, "inbound connection is encrypted")
	flag.BoolVar(&outboundEncrypt, "E", false, "outbound connection is encrypted")
	flag.BoolVar(&inboundUDP, "u", false, "inbound connection is udp")
	flag.BoolVar(&outboundUDP, "U", false, "outbound connection is udp")
	flag.BoolVar(&Debug, "debug", false, "show debug info")
	flag.BoolVar(&version, "v", false, "show version")
	flag.Parse()
	if version {
		fmt.Println(VERSION)
		return
	}
	if forwardAddr == "" || listenAddr == "" {
		flag.Usage()
		return
	}
	if outboundUDP && !outboundEncrypt {
		l.Fatal("outbound connection is udp , -E is required")
		return
	}
	if inboundUDP && !inboundEncrypt {
		l.Fatal("inbound connection is udp , -e is required")
		return
	}
	tou.SetLogger(l)
	if Debug {
		l.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	listen = srvtransport.NewServerChannelHost(listenAddr, l)
	if inboundUDP {
		err = listen.ListenTOU(method, password, compress, callback)
	} else {
		if inboundEncrypt {
			err = listen.ListenTCPS(method, password, compress, callback)
		} else {
			err = listen.ListenTCP(callback)
		}
	}

	if err != nil {
		l.Fatal(err)
	}
	l.Printf("shadowtunnel listen on : %s", listen.Addr())
	select {}
}

func callback(conn net.Conn) {
	defer func() {
		if e := recover(); e != nil {
			l.Printf("connection handler crashed :\n%s", err)
		}
	}()
	remoteAddr := conn.RemoteAddr()
	var outconn net.Conn
	if outboundUDP {
		outconn, err = clienttransport.TOUConnectHost(forwardAddr, method, password, compress, timeout*1000)

	} else {
		if outboundEncrypt {
			outconn, err = clienttransport.TCPSConnectHost(forwardAddr, method, password, compress, timeout*1000)
		} else {
			outconn, err = net.DialTimeout("tcp", forwardAddr, time.Duration(timeout)*time.Second)
		}
	}
	if err != nil {
		l.Printf("%s <--> %s, error: %s", remoteAddr, forwardAddr, err)
		conn.Close()
		return
	}
	utils.IoBind(conn, outconn, func(err interface{}) {
		l.Printf("%s <--> %s released", remoteAddr, forwardAddr)
	}, l)
	l.Printf("%s <--> %s connected", remoteAddr, forwardAddr)
}
