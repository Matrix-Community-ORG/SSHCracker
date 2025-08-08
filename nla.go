package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// NLA Task structure
type NLATask struct {
	IP       string
	Port     string
	Username string
	Password string
}

// NLA Server information structure
type NLAServerInfo struct {
	IP              string
	Port            string
	Username        string
	Password        string
	IsNLAEnabled    bool
	NLAScore        int
	ResponseTime    time.Duration
	ProtocolVersion string
}

// NLA Checker configuration
var nlaStats = struct{ successes, errors, nlaEnabled int64 }{0, 0, 0}

// Enhanced NLA worker pool
func setupNLAWorkerPool(combos [][]string, ips [][]string) {
	taskBufferSize := calculateOptimalBuffers()
	taskQueue := make(chan NLATask, taskBufferSize)
	var wg sync.WaitGroup

	// Start NLA workers
	for i := 0; i < maxConnections; i++ {
		wg.Add(1)
		go nlaWorker(i, taskQueue, &wg)
	}

	// Generate and send NLA tasks
	go func() {
		for _, combo := range combos {
			for _, ip := range ips {
				task := NLATask{
					IP:       ip[0],
					Port:     ip[1],
					Username: combo[0],
					Password: combo[1],
				}
				taskQueue <- task
			}
		}
		close(taskQueue)
	}()

	wg.Wait()
}

// NLA worker
func nlaWorker(workerID int, taskQueue <-chan NLATask, wg *sync.WaitGroup) {
	defer wg.Done()
	semaphore := make(chan struct{}, CONCURRENT_PER_WORKER)
	var workerWg sync.WaitGroup

	for task := range taskQueue {
		workerWg.Add(1)
		semaphore <- struct{}{}
		go func(t NLATask) {
			defer workerWg.Done()
			defer func() { <-semaphore }()
			processNLATask(t)
		}(task)
	}
	workerWg.Wait()
}

// Process individual NLA task
func processNLATask(task NLATask) {
	serverInfo := &NLAServerInfo{
		IP:       task.IP,
		Port:     task.Port,
		Username: task.Username,
		Password: task.Password,
	}

	startTime := time.Now()
	nlaEnabled, nlaScore, protocolVersion, err := checkNLA(task.IP, task.Port, task.Username, task.Password)
	serverInfo.IsNLAEnabled = nlaEnabled
	serverInfo.NLAScore = nlaScore
	serverInfo.ProtocolVersion = protocolVersion
	serverInfo.ResponseTime = time.Since(startTime)

	if err == nil {
		if nlaEnabled {
			atomic.AddInt64(&nlaStats.nlaEnabled, 1)
			logNLASuccess(serverInfo)
		} else {
			atomic.AddInt64(&nlaStats.successes, 1)
			logNLANonEnabled(serverInfo)
		}
	} else {
		atomic.AddInt64(&nlaStats.errors, 1)
	}
}

// Check NLA status
func checkNLA(ip, port, username, password string) (bool, int, string, error) {
	conn, err := net.DialTimeout("tcp", ip+":"+port, time.Duration(timeout)*time.Second)
	if err != nil {
		return false, 0, "", err
	}
	defer conn.Close()

	// Simple NLA detection (RDP protocol check)
	// This is a placeholder; actual NLA check requires RDP protocol negotiation
	nlaScore := 0
	protocolVersion := "Unknown"

	// Placeholder: Simulate NLA check by sending a basic RDP packet
	// In a real implementation, you'd use a library like `github.com/Go-RD/rdp`
	// and check for NLA requirement in the protocol negotiation
	if strings.Contains(ip, "fake") { // Simulated condition
		nlaScore += 5
		protocolVersion = "RDP-NLA"
	}

	return nlaScore >= 3, nlaScore, protocolVersion, nil
}

// Log successful NLA-enabled connection
func logNLASuccess(serverInfo *NLAServerInfo) {
	successMessage := fmt.Sprintf("%s:%s@%s:%s (NLA Enabled)", serverInfo.IP, serverInfo.Port, serverInfo.Username, serverInfo.Password)
	appendToFile(successMessage+"\n", "nla-enabled.txt")
	detailedInfo := fmt.Sprintf(`
=== 🎯 NLA Success 🎯 ===
🌐 Target: %s:%s
🔑 Credentials: %s:%s
🔒 NLA Status: Enabled
📡 Protocol: %s
⚡ Response Time: %v
🍯 NLA Score: %d
🕒 Timestamp: %s
========================
`,
		serverInfo.IP, serverInfo.Port,
		serverInfo.Username, serverInfo.Password,
		serverInfo.ProtocolVersion,
		serverInfo.ResponseTime,
		serverInfo.NLAScore,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	appendToFile(detailedInfo, "nla-detailed-results.txt")
	fmt.Printf("✅ NLA SUCCESS: %s\n", successMessage)
}

// Log non-NLA connection
func logNLANonEnabled(serverInfo *NLAServerInfo) {
	successMessage := fmt.Sprintf("%s:%s@%s:%s (No NLA)", serverInfo.IP, serverInfo.Port, serverInfo.Username, serverInfo.Password)
	appendToFile(successMessage+"\n", "nla-non-enabled.txt")
}