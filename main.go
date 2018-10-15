package main

import (
	"bufio"
	"bytes"
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"sync"

	"github.com/gobwas/glob"
	"github.com/miekg/dns"
	gocache "github.com/pmylund/go-cache"
	clienttransport "github.com/snail007/goproxy/core/cs/client"
	srvtransport "github.com/snail007/goproxy/core/cs/server"
	tou "github.com/snail007/goproxy/core/dst"
	encryptconn "github.com/snail007/goproxy/core/lib/transport/encrypt"
	utils "github.com/snail007/goproxy/utils"
	jumper "github.com/snail007/goproxy/utils/jumper"
	lbx "github.com/snail007/goproxy/utils/lb"
	redirx "github.com/snail007/shadowtunnel/redir"
)

const (
	VERSION = "1.5"
)

type forwarders []string

func (i *forwarders) String() string {
	return strings.Join(*i, ",")
}

func (i *forwarders) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	listenAddr       string
	forwardsAddr     forwarders
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

	hosts          string
	dnsHosts       = map[string]string{}
	dnsForwardFile string
	dnsForward     = map[string]string{}
	redir          bool

	//LoadBalance
	lb                       lbx.Group
	loadBalanceMethod        string
	loadBalanceTimeout       int
	loadBalanceRetryTime     int
	loadBalanceHashTarget    bool
	loadBalanceOnlyHA        bool
	loadBalanceActiveAfter   int
	loadBalanceInactiveAfter int

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

	dnsGlobCache = sync.Map{}
)

func main() {

	flag.StringVar(&listenAddr, "l", ":50000", "local listen address, such as : 0.0.0.0:33000")
	flag.StringVar(&method, "m", "aes-192-cfb", "method of encrypt/decrypt, these below are supported :\n"+strings.Join(encryptconn.GetCipherMethods(), ","))
	flag.StringVar(&password, "p", "shadowtunnel", "password of encrypt/decrypt")
	flag.Var(&forwardsAddr, "f", "forward address,such as : 127.0.0.1:8080 or with @`weight`: 127.0.0.1:8080@1")
	flag.IntVar(&timeout, "t", 3, "connection timeout seconds")
	flag.BoolVar(&compress, "c", false, "compress traffic")
	flag.BoolVar(&inboundEncrypt, "e", false, "inbound connection is encrypted")
	flag.BoolVar(&outboundEncrypt, "E", false, "outbound connection is encrypted")
	flag.BoolVar(&inboundUDP, "u", false, "inbound connection is udp")
	flag.BoolVar(&outboundUDP, "U", false, "outbound connection is udp")
	flag.StringVar(&hosts, "dns-hosts", "", "path of dns hosts file")
	flag.StringVar(&dnsForwardFile, "dns-forward", "", "rule file of resolving domain")
	flag.BoolVar(&redir, "redir", false, "read target from socket's redirect opts of iptables")
	//local
	flag.StringVar(&dnsListen, "dns", "", "local dns server listen on address")
	flag.StringVar(&dnsServerAddress, "dns-server", "8.8.8.8:53", "remote dns server to resolve domain")
	//server
	flag.BoolVar(&dnsProxy, "dns-proxy", false, "is dns endpoint or not")

	flag.IntVar(&dnsTTL, "ttl", 300, "cache seconds of dns query , if zero , default ttl used.")
	flag.StringVar(&cacheFile, "cache", filepath.Join(path.Dir(os.Args[0]), "cache.dat"), "dns query cache file path")
	flag.BoolVar(&version, "v", false, "show version")
	//lb
	flag.StringVar(&loadBalanceMethod, "lb-method", "leasttime", "load balance method when use multiple parent,can be <roundrobin|leastconn|leasttime|hash|weight>")
	flag.IntVar(&loadBalanceRetryTime, "lb-retrytime", 2000, "sleep time milliseconds after checking")
	flag.IntVar(&loadBalanceTimeout, "lb-timeout", 3000, "tcp milliseconds timeout of connecting to parent")
	flag.BoolVar(&loadBalanceHashTarget, "lb-hashtarget", true, "use target address to choose parent for LB, only worked for LB's `hash` method and using `-redir`")
	flag.BoolVar(&loadBalanceOnlyHA, "lb-onlyha", false, "use only `high availability mode` to choose parent for LB")
	flag.IntVar(&loadBalanceActiveAfter, "lb-activeafter", 1, "host going actived after this success count")
	flag.IntVar(&loadBalanceInactiveAfter, "lb-inactiveafter", 2, "host going inactived after this fail count")

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
	if len(forwardsAddr) == 0 || listenAddr == "" {
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
	if nolog {
		log.SetOutput(ioutil.Discard)
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
	//setting lb
	initLB()
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
		initDnsHosts(hosts, &dnsHosts, ".")
		initDnsHosts(dnsForwardFile, &dnsForward, "")
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
	typ := "tcp"
	if inboundUDP {
		typ = "udp"
	}
	log.Printf("shadowtunnel listen on %s : %s", typ, listen.Addr())
	cleanup()
}

func callback(conn net.Conn) {
	defer func() {
		if e := recover(); e != nil {
			debugf("callback handler crashed, err : %s\nstack:%s", e, string(debug.Stack()))
		}
	}()
	remoteAddr := conn.RemoteAddr()
	var outconn net.Conn
	var target string
	if dnsProxy {
		utils.ReadPacketData(conn, &target)
		if target == "" {
			//debugf("[warn] target is empty")
			conn.Close()
			return
		}
	} else {
		target = lb.Select("", loadBalanceOnlyHA)
	}
	if dnsProxy && target != "_" {
		outconn, err = net.DialTimeout("tcp", target, time.Duration(timeout)*time.Second)
	} else {
		if target == "_" {
			target = lb.Select("", loadBalanceOnlyHA)
		}
		addr := ""
		realAddress := ""
		if dnsListen != "" {
			addr = "_"
		}
		if redir {
			realAddress, err = redirx.RealServerAddress(&conn)
			if err != nil {
				debugf("%s <--> %s, error: %s", remoteAddr, target, err)
				conn.Close()
				return
			}
		}
		outconn, err = getOutconn(lb.Select(realAddress, loadBalanceOnlyHA), addr)
		if err == nil && redir {
			//debugf("real address %s", realAddress)
			pb := new(bytes.Buffer)
			pb.Write([]byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\n", realAddress)))
			pb.WriteString(fmt.Sprintf("Host: %s\r\n", realAddress))
			pb.WriteString(fmt.Sprintf("Proxy-Host: %s\r\n", realAddress))
			pb.WriteString("Proxy-Connection: Keep-Alive\r\n")
			pb.WriteString("Connection: Keep-Alive\r\n")
			pb.Write([]byte("\r\n"))
			_, err = outconn.Write(pb.Bytes())
			pb.Reset()
			pb = nil
			if err != nil {
				outconn.Close()
				conn.Close()
				conn = nil
				outconn = nil
				err = fmt.Errorf("error connecting to proxy: %s", err)
				return
			}
			reply := make([]byte, 1024)
			outconn.SetReadDeadline(time.Now().Add(time.Second * 5))
			n, err := outconn.Read(reply)
			outconn.SetReadDeadline(time.Time{})
			if err != nil {
				err = fmt.Errorf("error read reply from proxy: %s", err)
				outconn.Close()
				conn.Close()
				conn = nil
				outconn = nil
				return
			}
			if bytes.Index(reply[:n], []byte("200")) == -1 {
				err = fmt.Errorf("error greeting to proxy, response: %s", string(reply[:n]))
				outconn.Close()
				conn.Close()
				conn = nil
				outconn = nil
				return
			}
		}
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
func initDnsHosts(file string, dnsHosts *map[string]string, subfix string) {
	hosts := file
	if hosts == "" {
		return
	}
	if utils.PathExists(hosts) {
		_content, err := ioutil.ReadFile(hosts)
		if err != nil {
			return
		}
		dnsHostArr := strings.Split(strings.Replace(string(_content), "\r", "", -1), "\n")
		n := 0
		last := ""
		for _, dnsHost := range dnsHostArr {
			dnsHost = strings.Trim(dnsHost, " \t")
			if strings.HasPrefix(dnsHost, "#") {
				continue
			}
			u := strings.Fields(strings.Trim(dnsHost, " "))
			if subfix != "" {
				//hosts
				if len(u) == 2 {
					(*dnsHosts)[u[1]+subfix] = u[0]
					n++
				}
			} else {
				//dns forward
				if len(u) == 2 && u[1] != "" {
					(*dnsHosts)[u[0]] = u[1]
					last = u[1]
					n++
				} else if len(u) > 0 {
					(*dnsHosts)[u[0]] = last
					n++
				}
			}
		}
		if n > 0 {
			debugf("hosts file %s loaded, %d", hosts, n)
		}
	} else {
		panic(fmt.Errorf("host file not found , %s", hosts))
	}
}
func dnsServer() {
	dns.HandleFunc(".", dnsCallback)
	go func() {
		defer func() {
			if e := recover(); e != nil {
				debugf("callback handler crashed, err : %s\nstack:%s", e, string(debug.Stack()))
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
	//hosts
	for _, q := range req.Question {
		if q.Qtype == dns.TypeA {
			//log.Printf("q.Name %s %v", q.Name, dnsHosts)
			if v, ok := dnsHosts[q.Name]; ok {
				m := new(dns.Msg)
				m.SetReply(req)
				m.Compress = false
				m.Answer = []dns.RR{}
				rr, _ := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, v))
				m.Answer = append(m.Answer, rr)
				w.WriteMsg(m)
				debugf("id: %5d hosts: HIT %v", id, query)
				return
			}
		}
	}

	//cache
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

	//resolve
	answer := []byte{}

	//forward resovle
	for _, q := range req.Question {
		if q.Qtype == dns.TypeA {
			dnsAddr := ""
			domain := strings.TrimRight(q.Name, ".")
			if _d, ok := dnsGlobCache.Load(domain); ok {
				dnsAddr = _d.(string)
			} else {
				for k, v := range dnsForward {
					if strings.Index(v, ":") == -1 {
						v = v + ":53"
					}
					g := glob.MustCompile(k, '.')
					//debugf("%s -> %s : %v", k, v, g.Match(domain))
					if g.Match(domain) {
						dnsAddr = v
						break
					}
				}
			}

			if dnsAddr != "" {
				if _, ok := dnsGlobCache.Load(domain); !ok {
					dnsGlobCache.Store(domain, dnsAddr)
				}
				c := new(dns.Client)
				c.Dialer = &net.Dialer{
					Timeout: time.Duration(timeout) * time.Millisecond,
				}
				debugf("use %s relsove %s", dnsAddr, domain)
				m, _, err := c.Exchange(req, dnsAddr)
				if err != nil {
					debugf(err)
				} else {
					answer, _ = m.Pack()
				}
			}
		}
	}
	//nonforward resovle, use parent resovle
	if len(answer) == 0 {
		//use parent resolve
		lbAddr := lb.Select("", loadBalanceOnlyHA)
		debugf("id: %5d resolve: %v %s %s", id, query, lbAddr, dnsServerAddress)
		outconn, err := getOutconn(lbAddr, dnsServerAddress)
		if err != nil {
			debugf("dns query fail, %s", err)
			return
		}
		defer func() {
			outconn.Close()
		}()
		b, _ := req.Pack()
		outconn.Write(append([]byte{0, byte(len(b))}, b...))
		answer, _ = ioutil.ReadAll(outconn)
		if len(answer) < 3 {
			debugf("dns query fail, bad response")
			outconn.Close()
			return
		}
		answer = answer[2:]
	}
	defer func() {
		answer = nil
	}()
	m = &dns.Msg{}
	m.Unpack(answer)
	m.Id = req.Id
	if len(m.Answer) == 0 {
		debugf("dns query fail, no answer")
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
	cache.Set(key, answer, time.Second*time.Duration(ttl))
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
func getOutconn(lbAddr, targetAddr string) (outconn net.Conn, err error) {
	if outboundUDP {
		outconn, err = clienttransport.TOUConnectHost(lbAddr, method, password, compress, timeout*1000)
	} else {
		if outboundEncrypt {
			outconn, err = clienttransport.TCPSConnectHost(lbAddr, method, password, compress, timeout*1000)
		} else {
			outconn, err = net.DialTimeout("tcp", lbAddr, time.Duration(timeout)*time.Second)
		}
	}
	if err == nil && targetAddr != "" {
		outconn.Write(utils.BuildPacketData(targetAddr))
	}
	return
}
func initLB() {
	configs := lbx.BackendsConfig{}
	for _, addr := range forwardsAddr {
		_addrInfo := strings.Split(addr, "@")
		_addr := _addrInfo[0]
		weight := 1
		if len(_addrInfo) == 2 {
			weight, _ = strconv.Atoi(_addrInfo[1])
		}
		configs = append(configs, &lbx.BackendConfig{
			Address:       _addr,
			Weight:        weight,
			ActiveAfter:   loadBalanceActiveAfter,
			InactiveAfter: loadBalanceInactiveAfter,
			Timeout:       time.Duration(loadBalanceTimeout) * time.Millisecond,
			RetryTime:     time.Duration(loadBalanceRetryTime) * time.Millisecond,
		})
	}
	lb = lbx.NewGroup(utils.LBMethod(loadBalanceMethod), configs, nil, log, false)
}
