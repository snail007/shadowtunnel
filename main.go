package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	logger "log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	gocache "github.com/pmylund/go-cache"
	clienttransport "github.com/snail007/goproxy/core/cs/client"
	srvtransport "github.com/snail007/goproxy/core/cs/server"
	tou "github.com/snail007/goproxy/core/dst"
	encryptconn "github.com/snail007/goproxy/core/lib/transport/encrypt"
	utils "github.com/snail007/goproxy/utils"
	jumper "github.com/snail007/goproxy/utils/jumper"
)

const (
	VERSION = "1.2"
)

var (
	listenAddr       string
	forwardAddr      string
	timeout          int
	compress         bool
	method           string
	password         string
	listen           srvtransport.ServerChannel
	err              error
	inboundEncrypt   bool
	outboundEncrypt  bool
	inboundUDP       bool
	outboundUDP      bool
	version          bool
	dnsListen        string
	dnsServerAddress string
	dnsProxy         bool

	dnsTTL    int
	cache     *gocache.Cache
	cacheFile string
	dialer    jumper.Jumper
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
	//local
	flag.StringVar(&dnsListen, "dns", "", "local dns server listen on address")
	flag.StringVar(&dnsServerAddress, "dns-server", "8.8.8.8:53", "remote dns server to resolve domain")
	//server
	flag.BoolVar(&dnsProxy, "dns-proxy", false, "is dns endpoint or not")

	flag.IntVar(&dnsTTL, "ttl", 300, "cache seconds of dns query , if zero , default ttl used.")
	flag.StringVar(&cacheFile, "cache", filepath.Join(path.Dir(os.Args[0]), "cache.dat"), "dns query cache file path")
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
	//setting log
	tou.SetLogger(log)
	flags := logger.Ldate
	if isDebug {
		flags |= logger.Lshortfile | logger.Lmicroseconds
		log.SetFlags(flags)
	} else {
		flags |= logger.Ltime
	}
	if dnsListen != "" {
		//setting cache
		cache = gocache.New(time.Second*time.Duration(dnsTTL), time.Second*60)
		cache.LoadFile(cacheFile)
		go func() {
			timer := time.NewTicker(time.Second * 300)
			for {
				<-timer.C
				cache.DeleteExpired()
				cache.SaveFile(cacheFile)
			}
		}()
		//start dns
		dnsServer()
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
	log.Printf("shadowtunnel listen on tcp : %s", listen.Addr())
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
	var target string
	if dnsProxy {
		utils.ReadPacketData(conn, &target)
		if target == "" {
			debugf("[warn] target is empty")
			conn.Close()
			return
		}
		if target == "_" {
			target = forwardAddr
		}
	} else {
		target = forwardAddr
	}
	if dnsProxy {
		outconn, err = net.DialTimeout("tcp", target, time.Duration(timeout)*time.Second)
	} else {
		addr := ""
		if dnsListen != "" {
			addr = "_"
		}
		outconn, err = getOutconn(addr)
	}
	if err != nil {
		debugf("%s <--> %s, error: %s", remoteAddr, target, err)
		conn.Close()
		return
	}
	utils.IoBind(conn, outconn, func(err interface{}) {
		log.Printf("%s <--> %s released", remoteAddr, target)
	}, log)
	log.Printf("%s <--> %s connected", remoteAddr, target)
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
		debugf("%s%s [PID] %d running...\n", f, os.Args[0], cmd.Process.Pid)
		os.Exit(0)
	}

}
func foreverF() {
	args := []string{}
	for _, arg := range os.Args[1:] {
		if arg != "forever" {
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
			debugf("ERR:%s,restarting...\n", err)
			continue
		}
		cmdReader, err := cmd.StdoutPipe()
		if err != nil {
			debugf("ERR:%s,restarting...\n", err)
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
			debugf("ERR:%s,restarting...\n", err)
			continue
		}
		pid := cmd.Process.Pid
		debugf("worker %s [PID] %d running...\n", os.Args[0], pid)
		if err := cmd.Wait(); err != nil {
			debugf("ERR:%s,restarting...", err)
			continue
		}
		debugf("worker %s [PID] %d unexpected exited, restarting...\n", os.Args[0], pid)
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
				debugf("clean handler crashed, err : \n%s", string(debug.Stack()))
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

func dnsServer() {
	dns.HandleFunc(".", dnsCallback)
	go func() {
		defer func() {
			if e := recover(); e != nil {
				fmt.Printf("crashed:%s", string(debug.Stack()))
			}
		}()
		log.Printf("dns server listen on udp %s", dnsListen)
		err := dns.ListenAndServe(dnsListen, "udp", nil)
		if err != nil {
			debugf("dns listen error: %s", err)
		}
	}()
}
func dnsCallback(w dns.ResponseWriter, req *dns.Msg) {
	defer func() {
		if err := recover(); err != nil {
			debugf("dns handler crashed with err : %s \nstack: %s", err, string(debug.Stack()))
		}
	}()
	var (
		key       string
		m         *dns.Msg
		err       error
		data      []byte
		id        uint16
		query     []string
		questions []dns.Question
	)
	if req.MsgHdr.Response == true {
		return
	}
	query = make([]string, len(req.Question))
	for i, q := range req.Question {
		if q.Qtype != dns.TypeAAAA {
			questions = append(questions, q)
		}
		query[i] = fmt.Sprintf("(%s %s %s)", q.Name, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype])
	}

	if len(questions) == 0 {
		return
	}

	req.Question = questions
	id = req.Id
	req.Id = 0
	key = toMd5(req.String())
	req.Id = id
	if reply, ok := cache.Get(key); ok {
		data, _ = reply.([]byte)
	}
	if data != nil && len(data) > 0 {
		m = &dns.Msg{}
		m.Unpack(data)
		m.Id = id
		err = w.WriteMsg(m)
		debugf("id: %5d cache: HIT %v", id, query)
		return
	}
	debugf("id: %5d resolve: %v %s", id, query, dnsServerAddress)
	outconn, err := getOutconn(dnsServerAddress)
	if err != nil {
		debugf("dns query fail,%s", err)
		return
	}
	defer func() {
		outconn.Close()
	}()
	b, _ := req.Pack()
	outconn.Write(append([]byte{0, byte(len(b))}, b...))
	answer, _ := ioutil.ReadAll(outconn)
	defer func() {
		answer = nil
	}()
	if len(answer) < 3 {
		debugf("dns query fail,%s", err)
		outconn.Close()
		return
	}
	m = &dns.Msg{}
	m.Unpack(answer[2:])
	m.Id = req.Id
	if len(m.Answer) == 0 {
		debugf("dns query fail,%s", err)
		return
	}
	d, err := m.Pack()
	if err != nil {
		debugf("dns query fail,%s", err)
		return
	}
	_, err = w.Write(d)
	if err != nil {
		debugf("dns query fail,%s", err)
		return
	}
	ttl := 0
	if len(m.Answer) > 0 {
		if dnsTTL > 0 {
			ttl = dnsTTL
		} else {
			ttl = int(m.Answer[0].Header().Ttl)
			if ttl < 0 {
				ttl = dnsTTL
			}
		}
	}
	cache.Set(key, answer[2:], time.Second*time.Duration(ttl))
	log.Printf("id: %5d cache: CACHED %v TTL %v", id, query, ttl)
}
func toMd5(data string) string {
	m := md5.New()
	m.Write([]byte(data))
	return hex.EncodeToString(m.Sum(nil))
}
func debugf(v ...interface{}) {
	if nolog {
		return
	}
	str := v[0].(string)
	if isDebug {
		log.Printf(str, v[1:]...)
	}
}
func getOutconn(targetAddr string) (outconn net.Conn, err error) {
	if outboundUDP {
		outconn, err = clienttransport.TOUConnectHost(forwardAddr, method, password, compress, timeout*1000)
	} else {
		if outboundEncrypt {
			outconn, err = clienttransport.TCPSConnectHost(forwardAddr, method, password, compress, timeout*1000)
		} else {
			outconn, err = net.DialTimeout("tcp", forwardAddr, time.Duration(timeout)*time.Second)
		}
	}
	if targetAddr != "" {
		outconn.Write(utils.BuildPacketData(targetAddr))
	}
	return
}
