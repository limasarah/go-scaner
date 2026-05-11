package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ScanResult struct {
	Target string `json:"target"`
	Port   int    `json:"port"`
	Open   bool   `json:"open"`
	Banner string `json:"banner,omitempty"`
	Error  string `json:"error,omitempty"`
	Engine string `json:"engine"`
}

type scanTask struct {
	TargetIP string
	Port     int
}

func main() {
	target := flag.String("target", "127.0.0.1", "IP ou hostname para escanear")
	iface := flag.String("iface", "eth0", "Interface de rede para coletar IP local")
	fromPort := flag.Int("from", 1, "Porta inicial")
	toPort := flag.Int("to", 1024, "Porta final")
	workers := flag.Int("workers", 100, "Número de goroutines de escaneamento")
	flag.Parse()

	if *fromPort < 1 {
		*fromPort = 1
	}
	if *toPort < *fromPort {
		log.Fatalf("porta final deve ser maior ou igual à porta inicial")
	}

	ipAddr, err := resolveTargetIP(*target)
	if err != nil {
		log.Fatalf("falha ao resolver alvo: %v", err)
	}

	localIP, err := resolveLocalIPv4(*iface)
	if err != nil {
		log.Printf("não foi possível obter IP local em %s: %v", *iface, err)
		localIP = net.ParseIP("0.0.0.0")
	}

	taskChan := make(chan scanTask, *workers)
	resultChan := make(chan ScanResult, *workers)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(taskChan, resultChan, localIP.String(), ipAddr.String(), &wg)
	}

	go func() {
		for p := *fromPort; p <= *toPort; p++ {
			taskChan <- scanTask{TargetIP: ipAddr.String(), Port: p}
		}
		close(taskChan)
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	openResults := []ScanResult{}
	for res := range resultChan {
		if res.Open {
			openResults = append(openResults, res)
		}
	}

	data, err := json.MarshalIndent(openResults, "", "  ")
	if err != nil {
		log.Fatalf("erro ao codificar JSON: %v", err)
	}
	fmt.Println(string(data))
}

func worker(tasks <-chan scanTask, results chan<- ScanResult, localIP, targetIP string, wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range tasks {
		results <- scanPort(task, localIP, targetIP)
	}
}

func scanPort(task scanTask, localIP, targetIP string) ScanResult {
	result := ScanResult{
		Target: targetIP,
		Port:   task.Port,
		Open:   false,
		Engine: "tcp-connect",
	}

	if _, err := createSYNPacket(localIP, targetIP, 0, task.Port); err != nil {
		result.Error = fmt.Sprintf("erro no probe SYN: %v", err)
	}

	address := fmt.Sprintf("%s:%d", targetIP, task.Port)
	conn, err := net.DialTimeout("tcp", address, 400*time.Millisecond)
	if err != nil {
		if result.Error == "" {
			result.Error = err.Error()
		}
		return result
	}
	defer conn.Close()

	result.Open = true
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		result.Banner = string(buffer[:n])
	}

	return result
}

func resolveTargetIP(target string) (net.IP, error) {
	ip := net.ParseIP(target)
	if ip != nil {
		return ip, nil
	}
	addrs, err := net.LookupHost(target)
	if err != nil {
		return nil, err
	}
	return net.ParseIP(addrs[0]), nil
}

func resolveLocalIPv4(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP, nil
		}
	}
	return nil, fmt.Errorf("nenhum endereço IPv4 encontrado em %s", ifaceName)
}

func createSYNPacket(srcIP, dstIP string, srcPort, dstPort int) ([]byte, error) {
	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Seq:     110502,
		Window:  64240,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
