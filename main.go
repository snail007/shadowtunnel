package main

import (
	"bufio"
	"flag"
	"fmt"
	logger "log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	clienttransport "github.com/snail007/goproxy/core/cs/client"
	srvtransport "github.com/snail007/goproxy/core/cs/server"
	tou "github.com/snail007/goproxy/core/dst"
	encryptconn "github.com/snail007/goproxy/core/lib/transport/encrypt"
	utils "github.com/snail007/goproxy/utils"
)

const (
	VERSION = "1.2"
)

var (
	listenAddr      string
	forwardAddr     string
	timeout         int
	compress        bool
	method          string
	password        string
	listen          srvtransport.ServerChannel
	err             error
	inboundEncrypt  bool
	outboundEncrypt bool
	inboundUDP      bool
	outboundUDP     bool
	version         bool

	//common
	isDebug   bool
	nolog     bool
	log       = logger.New(os.Stderr, "", logger.Ldate|logger.Ltime)
	logfile   string
	daemon    bool
	forever   bool
	profiling bool
	cmd       *exec.Cmd
	cpuProfilingFile,
	memProfilingFile,
	blockProfilingFile,
	goroutineProfilingFile,
	threadcreateProfilingFile *os.File
)

func main() {

	flag.StringVar(&listenAddr, "l", ":50000", "local listen address, such as : 0.0.0.0:33000")
	flag.StringVar(&method, "m", "aes-192-cfb", "method of encrypt/decrypt, these below are supported :\n"+strings.Join(encryptconn.GetCipherMethods(), ","))
	flag.StringVar(&password, "p", "shadowtunnel", "password of encrypt/decrypt")
	flag.StringVar(&forwardAddr, "f", "", "forward address,such as : 127.0.0.1:8080")
	flag.IntVar(&timeout, "t", 3, "connection timeout seconds")
	flag.BoolVar(&compress, "c", false, "compress traffic")
	flag.BoolVar(&inboundEncrypt, "e", false, "inbound connection is encrypted")
	flag.BoolVar(&outboundEncrypt, "E", false, "outbound connection is encrypted")
	flag.BoolVar(&inboundUDP, "u", false, "inbound connection is udp")
	flag.BoolVar(&outboundUDP, "U", false, "outbound connection is udp")
	flag.BoolVar(&version, "v", false, "show version")

	//common
	flag.BoolVar(&nolog, "nolog", false, "turn off logging")
	flag.BoolVar(&isDebug, "debug", false, "show debug info")
	flag.BoolVar(&daemon, "daemon", false, "daemon mode")
	flag.BoolVar(&forever, "forever", false, "forever mode")
	flag.BoolVar(&profiling, "profiling", false, "profiling mode, in this mode, you should stopping process by : Ctrl+C or 'kill -s SIGHUP $PID_OF_shadowtunnel'")
	flag.StringVar(&logfile, "log", "", "logging output to file")
	flag.Parse()
	if version {
		fmt.Println(VERSION)
		return
	}
	if forwardAddr == "" || listenAddr == "" {
		flag.Usage()
		return
	}
	if daemon {
		daemonF()
		return
	}
	if forever {
		foreverF()
		return
	}
	if profiling {
		startProfiling()
	}
	if outboundUDP && !outboundEncrypt {
		log.Fatal("outbound connection is udp , -E is required")
		return
	}
	if inboundUDP && !inboundEncrypt {
		log.Fatal("inbound connection is udp , -e is required")
		return
	}
	tou.SetLogger(log)
	flags := logger.Ldate
	if isDebug {
		flags |= logger.Lshortfile | logger.Lmicroseconds
		log.SetFlags(flags)
	} else {
		flags |= logger.Ltime
	}
	listen = srvtransport.NewServerChannelHost(listenAddr, log)
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
		log.Fatal(err)
	}
	log.Printf("shadowtunnel listen on : %s", listen.Addr())
	cleanup()
}

func callback(conn net.Conn) {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("connection handler crashed :\n%s", err)
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
		log.Printf("%s <--> %s, error: %s", remoteAddr, forwardAddr, err)
		conn.Close()
		return
	}
	utils.IoBind(conn, outconn, func(err interface{}) {
		log.Printf("%s <--> %s released", remoteAddr, forwardAddr)
	}, log)
	log.Printf("%s <--> %s connected", remoteAddr, forwardAddr)
}
func daemonF() {
	if daemon {
		args := []string{}
		for _, arg := range os.Args[1:] {
			if arg != "-daemon" {
				args = append(args, arg)
			}
		}
		cmd = exec.Command(os.Args[0], args...)
		cmd.Start()
		f := ""
		if forever {
			f = "forever "
		}
		log.Printf("%s%s [PID] %d running...\n", f, os.Args[0], cmd.Process.Pid)
		os.Exit(0)
	}

}
func foreverF() {
	args := []string{}
	for _, arg := range os.Args[1:] {
		if arg != "-forever" {
			args = append(args, arg)
		}
	}
	for {
		if cmd != nil {
			cmd.Process.Kill()
			time.Sleep(time.Second * 5)
		}
		cmd = exec.Command(os.Args[0], args...)
		cmdReaderStderr, err := cmd.StderrPipe()
		if err != nil {
			log.Printf("ERR:%s,restarting...\n", err)
			continue
		}
		cmdReader, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("ERR:%s,restarting...\n", err)
			continue
		}
		scanner := bufio.NewScanner(cmdReader)
		scannerStdErr := bufio.NewScanner(cmdReaderStderr)
		go func() {
			for scanner.Scan() {
				fmt.Println(scanner.Text())
			}
		}()
		go func() {
			for scannerStdErr.Scan() {
				fmt.Println(scannerStdErr.Text())
			}
		}()
		if err := cmd.Start(); err != nil {
			log.Printf("ERR:%s,restarting...\n", err)
			continue
		}
		pid := cmd.Process.Pid
		log.Printf("worker %s [PID] %d running...\n", os.Args[0], pid)
		if err := cmd.Wait(); err != nil {
			log.Printf("ERR:%s,restarting...", err)
			continue
		}
		log.Printf("worker %s [PID] %d unexpected exited, restarting...\n", os.Args[0], pid)
	}
}
func startProfiling() {
	cpuProfilingFile, _ = os.Create("cpu.prof")
	memProfilingFile, _ = os.Create("memory.prof")
	blockProfilingFile, _ = os.Create("block.prof")
	goroutineProfilingFile, _ = os.Create("goroutine.prof")
	threadcreateProfilingFile, _ = os.Create("threadcreate.prof")
	pprof.StartCPUProfile(cpuProfilingFile)
}
func stopProfiling() {
	goroutine := pprof.Lookup("goroutine")
	goroutine.WriteTo(goroutineProfilingFile, 1)
	heap := pprof.Lookup("heap")
	heap.WriteTo(memProfilingFile, 1)
	block := pprof.Lookup("block")
	block.WriteTo(blockProfilingFile, 1)
	threadcreate := pprof.Lookup("threadcreate")
	threadcreate.WriteTo(threadcreateProfilingFile, 1)
	pprof.StopCPUProfile()
}
func cleanup() {
	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan bool)
	signal.Notify(signalChan,
		os.Interrupt,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		defer func() {
			if e := recover(); e != nil {
				log.Printf("clean handler crashed, err : \n%s", string(debug.Stack()))
			}
		}()
		for range signalChan {
			if profiling {
				stopProfiling()
			}
			cleanupDone <- true
		}
	}()
	<-cleanupDone
}
