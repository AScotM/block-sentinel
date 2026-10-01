package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const version = "1.0.0"

type Severity int

const (
	SeverityNormal Severity = iota
	SeverityBusy
	SeveritySaturated
)

func (s Severity) String() string {
	switch s {
	case SeverityNormal:
		return "NORMAL"
	case SeverityBusy:
		return "BUSY"
	case SeveritySaturated:
		return "SATURATED"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

type DiskCounters struct {
	Major                 uint64
	Minor                 uint64
	Name                  string
	ReadsCompleted        uint64
	ReadsMerged           uint64
	SectorsRead           uint64
	ReadTimeMS            uint64
	WritesCompleted       uint64
	WritesMerged          uint64
	SectorsWritten        uint64
	WriteTimeMS           uint64
	IOInProgress          uint64
	IOTimeMS              uint64
	WeightedIOTimeMS      uint64
	DiscardsCompleted     uint64
	DiscardsMerged        uint64
	SectorsDiscarded      uint64
	DiscardTimeMS         uint64
	FlushesCompleted      uint64
	FlushTimeMS           uint64
}

type DeviceMetadata struct {
	Name               string `json:"name"`
	Major              uint64 `json:"major"`
	Minor              uint64 `json:"minor"`
	DeviceType         string `json:"device_type"`
	Rotational         bool   `json:"rotational"`
	Scheduler          string `json:"scheduler"`
	LogicalBlockSize   uint64 `json:"logical_block_size"`
	PhysicalBlockSize  uint64 `json:"physical_block_size"`
	MinimumIOSize      uint64 `json:"minimum_io_size"`
	OptimalIOSize      uint64 `json:"optimal_io_size"`
	ReadAheadKB        uint64 `json:"read_ahead_kb"`
	QueueDepth         uint64 `json:"queue_depth"`
	Model              string `json:"model,omitempty"`
	Vendor             string `json:"vendor,omitempty"`
	Serial             string `json:"serial,omitempty"`
	SizeBytes          uint64 `json:"size_bytes"`
	Removable          bool   `json:"removable"`
	ReadOnly           bool   `json:"read_only"`
}

type DeviceSample struct {
	Metadata             DeviceMetadata `json:"metadata"`
	ReadIOPS             float64        `json:"read_iops"`
	WriteIOPS            float64        `json:"write_iops"`
	DiscardIOPS          float64        `json:"discard_iops"`
	FlushIOPS            float64        `json:"flush_iops"`
	ReadBytesPerSecond   float64        `json:"read_bytes_per_second"`
	WriteBytesPerSecond  float64        `json:"write_bytes_per_second"`
	DiscardBytesPerSecond float64       `json:"discard_bytes_per_second"`
	ReadLatencyMS        float64        `json:"read_latency_ms"`
	WriteLatencyMS       float64        `json:"write_latency_ms"`
	DiscardLatencyMS     float64        `json:"discard_latency_ms"`
	AverageQueueSize     float64        `json:"average_queue_size"`
	UtilizationPercent   float64        `json:"utilization_percent"`
	IOInProgress         uint64         `json:"io_in_progress"`
	ReadsCompleted       uint64         `json:"reads_completed"`
	WritesCompleted      uint64         `json:"writes_completed"`
	SectorsRead          uint64         `json:"sectors_read"`
	SectorsWritten       uint64         `json:"sectors_written"`
	Severity             Severity       `json:"severity"`
}

type Snapshot struct {
	Version         string         `json:"version"`
	Timestamp       string         `json:"timestamp"`
	Hostname        string         `json:"hostname"`
	Kernel          string         `json:"kernel"`
	IntervalSeconds float64        `json:"interval_seconds"`
	Devices         []DeviceSample `json:"devices"`
	Overall         Severity       `json:"overall"`
}

type Config struct {
	Interval   time.Duration
	Watch      bool
	JSON       bool
	ShowAll    bool
	Device     string
	Top        int
	SortBy     string
	ProcRoot   string
	SysRoot    string
	ShowVersion bool
}

func main() {
	config, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if config.ShowVersion {
		fmt.Printf("Block Sentinel %s\n", version)
		return
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	if config.Watch {
		runWatch(config, signals)
		return
	}

	snapshot, err := sample(config, signals)
	if err != nil {
		if errors.Is(err, errInterrupted) {
			return
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if config.JSON {
		printJSON(snapshot)
	} else {
		printHuman(snapshot)
	}
}

var errInterrupted = errors.New("interrupted")

func parseFlags() (Config, error) {
	var config Config
	var intervalSeconds float64

	config.ProcRoot = "/proc"
	config.SysRoot = "/sys"

	flag.Float64Var(&intervalSeconds, "interval", 1.0, "")
	flag.BoolVar(&config.Watch, "watch", false, "")
	flag.BoolVar(&config.JSON, "json", false, "")
	flag.BoolVar(&config.ShowAll, "all", false, "")
	flag.StringVar(&config.Device, "device", "", "")
	flag.IntVar(&config.Top, "top", 0, "")
	flag.StringVar(&config.SortBy, "sort", "util", "")
	flag.StringVar(&config.ProcRoot, "proc", "/proc", "")
	flag.StringVar(&config.SysRoot, "sys", "/sys", "")
	flag.BoolVar(&config.ShowVersion, "version", false, "")

	flag.Usage = func() {
		name := filepath.Base(os.Args[0])

		fmt.Fprintf(os.Stderr, "Block Sentinel %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [OPTIONS]\n\n", name)
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  --interval SECONDS   Sampling interval, default 1\n")
		fmt.Fprintf(os.Stderr, "  --watch              Continuously monitor devices\n")
		fmt.Fprintf(os.Stderr, "  --json               Emit JSON\n")
		fmt.Fprintf(os.Stderr, "  --all                Include loop, RAM and device-mapper devices\n")
		fmt.Fprintf(os.Stderr, "  --device NAME        Monitor one block device\n")
		fmt.Fprintf(os.Stderr, "  --top N              Show only N busiest devices\n")
		fmt.Fprintf(os.Stderr, "  --sort FIELD         util, read, write, iops, queue, latency or name\n")
		fmt.Fprintf(os.Stderr, "  --proc PATH          Alternate procfs root\n")
		fmt.Fprintf(os.Stderr, "  --sys PATH           Alternate sysfs root\n")
		fmt.Fprintf(os.Stderr, "  --version            Show version\n")
		fmt.Fprintf(os.Stderr, "  --help               Show help\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s\n", name)
		fmt.Fprintf(os.Stderr, "  %s --watch\n", name)
		fmt.Fprintf(os.Stderr, "  %s --watch --interval 2\n", name)
		fmt.Fprintf(os.Stderr, "  %s --device sda\n", name)
		fmt.Fprintf(os.Stderr, "  %s --device vda --watch\n", name)
		fmt.Fprintf(os.Stderr, "  %s --top 5 --sort iops\n", name)
		fmt.Fprintf(os.Stderr, "  %s --all\n", name)
		fmt.Fprintf(os.Stderr, "  %s --json\n", name)
	}

	flag.Parse()

	if flag.NArg() != 0 {
		return config, fmt.Errorf("unexpected argument: %s", flag.Arg(0))
	}

	if intervalSeconds <= 0 {
		return config, errors.New("--interval must be greater than zero")
	}

	config.Interval = time.Duration(intervalSeconds * float64(time.Second))

	if config.Interval < 100*time.Millisecond {
		return config, errors.New("--interval must be at least 0.1 seconds")
	}

	if config.Top < 0 {
		return config, errors.New("--top cannot be negative")
	}

	switch config.SortBy {
	case "util", "read", "write", "iops", "queue", "latency", "name":
	default:
		return config, fmt.Errorf("unsupported sort field: %s", config.SortBy)
	}

	if strings.TrimSpace(config.Device) != "" {
		config.Device = filepath.Base(strings.TrimSpace(config.Device))

		if config.Device == "." || config.Device == "/" || config.Device == "" {
			return config, errors.New("invalid device name")
		}
	}

	return config, nil
}

func runWatch(config Config, signals <-chan os.Signal) {
	for {
		snapshot, err := sample(config, signals)
		if err != nil {
			if errors.Is(err, errInterrupted) {
				if !config.JSON {
					fmt.Println()
				}
				return
			}

			if config.JSON {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			} else {
				clearScreen()
				fmt.Printf("Block Sentinel\n==============\n\nError: %v\n", err)
			}

			select {
			case <-time.After(config.Interval):
			case <-signals:
				if !config.JSON {
					fmt.Println()
				}
				return
			}

			continue
		}

		if config.JSON {
			printJSON(snapshot)
		} else {
			clearScreen()
			printHuman(snapshot)
		}

		select {
		case <-signals:
			if !config.JSON {
				fmt.Println()
			}
			return
		default:
		}
	}
}

func sample(config Config, signals <-chan os.Signal) (Snapshot, error) {
	var snapshot Snapshot

	first, err := readDiskstats(config)
	if err != nil {
		return snapshot, err
	}

	start := time.Now()

	timer := time.NewTimer(config.Interval)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-signals:
		return snapshot, errInterrupted
	}

	elapsed := time.Since(start)

	second, err := readDiskstats(config)
	if err != nil {
		return snapshot, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	kernel := readTrimmed(filepath.Join(config.ProcRoot, "sys", "kernel", "osrelease"))
	if kernel == "" {
		kernel = "unknown"
	}

	names := make([]string, 0, len(second))

	for name := range second {
		if _, ok := first[name]; !ok {
			continue
		}

		if config.Device != "" && name != config.Device {
			continue
		}

		if !config.ShowAll && shouldIgnoreDevice(name, config.SysRoot) {
			continue
		}

		names = append(names, name)
	}

	sort.Strings(names)

	if config.Device != "" && len(names) == 0 {
		return snapshot, fmt.Errorf("device %s was not found or disappeared during sampling", config.Device)
	}

	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return snapshot, errors.New("invalid sampling interval")
	}

	var devices []DeviceSample

	for _, name := range names {
		before := first[name]
		after := second[name]

		device := calculateSample(config, before, after, seconds)
		devices = append(devices, device)
	}

	sortSamples(devices, config.SortBy)

	if config.Top > 0 && len(devices) > config.Top {
		devices = devices[:config.Top]
	}

	overall := SeverityNormal

	for _, device := range devices {
		if device.Severity > overall {
			overall = device.Severity
		}
	}

	snapshot = Snapshot{
		Version:         version,
		Timestamp:       time.Now().Format(time.RFC3339),
		Hostname:        hostname,
		Kernel:          kernel,
		IntervalSeconds: seconds,
		Devices:         devices,
		Overall:         overall,
	}

	return snapshot, nil
}

func readDiskstats(config Config) (map[string]DiskCounters, error) {
	path := filepath.Join(config.ProcRoot, "diskstats")

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}

	result := make(map[string]DiskCounters)

	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		fields := strings.Fields(line)

		if len(fields) < 14 {
			continue
		}

		major, err1 := strconv.ParseUint(fields[0], 10, 64)
		minor, err2 := strconv.ParseUint(fields[1], 10, 64)

		if err1 != nil || err2 != nil {
			continue
		}

		counters := DiskCounters{
			Major: major,
			Minor: minor,
			Name:  fields[2],
		}

		values := make([]uint64, 0, len(fields)-3)
		valid := true

		for _, field := range fields[3:] {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				valid = false
				break
			}
			values = append(values, value)
		}

		if !valid || len(values) < 11 {
			continue
		}

		counters.ReadsCompleted = values[0]
		counters.ReadsMerged = values[1]
		counters.SectorsRead = values[2]
		counters.ReadTimeMS = values[3]
		counters.WritesCompleted = values[4]
		counters.WritesMerged = values[5]
		counters.SectorsWritten = values[6]
		counters.WriteTimeMS = values[7]
		counters.IOInProgress = values[8]
		counters.IOTimeMS = values[9]
		counters.WeightedIOTimeMS = values[10]

		if len(values) >= 15 {
			counters.DiscardsCompleted = values[11]
			counters.DiscardsMerged = values[12]
			counters.SectorsDiscarded = values[13]
			counters.DiscardTimeMS = values[14]
		}

		if len(values) >= 17 {
			counters.FlushesCompleted = values[15]
			counters.FlushTimeMS = values[16]
		}

		result[counters.Name] = counters
	}

	if len(result) == 0 {
		return nil, errors.New("no block-device statistics found")
	}

	return result, nil
}

func calculateSample(config Config, before, after DiskCounters, seconds float64) DeviceSample {
	reads := delta(after.ReadsCompleted, before.ReadsCompleted)
	writes := delta(after.WritesCompleted, before.WritesCompleted)
	discards := delta(after.DiscardsCompleted, before.DiscardsCompleted)
	flushes := delta(after.FlushesCompleted, before.FlushesCompleted)

	sectorsRead := delta(after.SectorsRead, before.SectorsRead)
	sectorsWritten := delta(after.SectorsWritten, before.SectorsWritten)
	sectorsDiscarded := delta(after.SectorsDiscarded, before.SectorsDiscarded)

	readTime := delta(after.ReadTimeMS, before.ReadTimeMS)
	writeTime := delta(after.WriteTimeMS, before.WriteTimeMS)
	discardTime := delta(after.DiscardTimeMS, before.DiscardTimeMS)

	ioTime := delta(after.IOTimeMS, before.IOTimeMS)
	weightedTime := delta(after.WeightedIOTimeMS, before.WeightedIOTimeMS)

	metadata := readMetadata(config.SysRoot, after)

	sectorSize := uint64(512)

	readBytes := sectorsRead * sectorSize
	writeBytes := sectorsWritten * sectorSize
	discardBytes := sectorsDiscarded * sectorSize

	sample := DeviceSample{
		Metadata:              metadata,
		ReadIOPS:              float64(reads) / seconds,
		WriteIOPS:             float64(writes) / seconds,
		DiscardIOPS:           float64(discards) / seconds,
		FlushIOPS:             float64(flushes) / seconds,
		ReadBytesPerSecond:    float64(readBytes) / seconds,
		WriteBytesPerSecond:   float64(writeBytes) / seconds,
		DiscardBytesPerSecond: float64(discardBytes) / seconds,
		AverageQueueSize:      float64(weightedTime) / 1000.0 / seconds,
		UtilizationPercent:    float64(ioTime) / (seconds * 1000.0) * 100,
		IOInProgress:          after.IOInProgress,
		ReadsCompleted:        after.ReadsCompleted,
		WritesCompleted:       after.WritesCompleted,
		SectorsRead:           after.SectorsRead,
		SectorsWritten:        after.SectorsWritten,
	}

	if reads > 0 {
		sample.ReadLatencyMS = float64(readTime) / float64(reads)
	}

	if writes > 0 {
		sample.WriteLatencyMS = float64(writeTime) / float64(writes)
	}

	if discards > 0 {
		sample.DiscardLatencyMS = float64(discardTime) / float64(discards)
	}

	if sample.UtilizationPercent > 100 {
		sample.UtilizationPercent = 100
	}

	sample.Severity = evaluateDevice(sample)

	return sample
}

func delta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

func readMetadata(sysRoot string, counters DiskCounters) DeviceMetadata {
	name := counters.Name
	classPath := filepath.Join(sysRoot, "class", "block", name)

	metadata := DeviceMetadata{
		Name:  name,
		Major: counters.Major,
		Minor: counters.Minor,
	}

	if isPartition(classPath) {
		metadata.DeviceType = "partition"
	} else if strings.HasPrefix(name, "dm-") {
		metadata.DeviceType = "device-mapper"
	} else if strings.HasPrefix(name, "md") {
		metadata.DeviceType = "raid"
	} else if strings.HasPrefix(name, "loop") {
		metadata.DeviceType = "loop"
	} else if strings.HasPrefix(name, "ram") {
		metadata.DeviceType = "ram"
	} else if strings.HasPrefix(name, "zram") {
		metadata.DeviceType = "zram"
	} else {
		metadata.DeviceType = "disk"
	}

	rotational := readUint(filepath.Join(classPath, "queue", "rotational"))
	metadata.Rotational = rotational == 1

	metadata.Scheduler = readScheduler(filepath.Join(classPath, "queue", "scheduler"))
	metadata.LogicalBlockSize = readUint(filepath.Join(classPath, "queue", "logical_block_size"))
	metadata.PhysicalBlockSize = readUint(filepath.Join(classPath, "queue", "physical_block_size"))
	metadata.MinimumIOSize = readUint(filepath.Join(classPath, "queue", "minimum_io_size"))
	metadata.OptimalIOSize = readUint(filepath.Join(classPath, "queue", "optimal_io_size"))
	metadata.ReadAheadKB = readUint(filepath.Join(classPath, "queue", "read_ahead_kb"))
	metadata.QueueDepth = readQueueDepth(classPath)

	metadata.Model = readTrimmed(filepath.Join(classPath, "device", "model"))
	metadata.Vendor = readTrimmed(filepath.Join(classPath, "device", "vendor"))
	metadata.Serial = readTrimmed(filepath.Join(classPath, "device", "serial"))

	sizeSectors := readUint(filepath.Join(classPath, "size"))
	metadata.SizeBytes = sizeSectors * 512

	metadata.Removable = readUint(filepath.Join(classPath, "removable")) == 1
	metadata.ReadOnly = readUint(filepath.Join(classPath, "ro")) == 1

	return metadata
}

func isPartition(classPath string) bool {
	_, err := os.Stat(filepath.Join(classPath, "partition"))
	return err == nil
}

func readScheduler(path string) string {
	value := readTrimmed(path)
	if value == "" {
		return "unknown"
	}

	fields := strings.Fields(value)

	for _, field := range fields {
		if strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]") {
			return strings.TrimSuffix(strings.TrimPrefix(field, "["), "]")
		}
	}

	if len(fields) > 0 {
		return fields[0]
	}

	return "unknown"
}

func readQueueDepth(classPath string) uint64 {
	paths := []string{
		filepath.Join(classPath, "device", "queue_depth"),
		filepath.Join(classPath, "queue", "nr_requests"),
	}

	for _, path := range paths {
		if value, ok := readUintOK(path); ok {
			return value
		}
	}

	return 0
}

func shouldIgnoreDevice(name, sysRoot string) bool {
	if strings.HasPrefix(name, "loop") {
		return true
	}

	if strings.HasPrefix(name, "ram") {
		return true
	}

	if strings.HasPrefix(name, "zram") {
		return true
	}

	if strings.HasPrefix(name, "fd") {
		return true
	}

	if strings.HasPrefix(name, "sr") {
		return true
	}

	if strings.HasPrefix(name, "dm-") {
		return true
	}

	classPath := filepath.Join(sysRoot, "class", "block", name)

	if isPartition(classPath) {
		return true
	}

	return false
}

func evaluateDevice(sample DeviceSample) Severity {
	util := sample.UtilizationPercent
	queue := sample.AverageQueueSize
	latency := sample.ReadLatencyMS

	if sample.WriteLatencyMS > latency {
		latency = sample.WriteLatencyMS
	}

	switch {
	case util >= 95:
		return SeveritySaturated
	case latency >= 100:
		return SeveritySaturated
	case queue >= 8:
		return SeveritySaturated
	case util >= 75:
		return SeverityBusy
	case latency >= 30:
		return SeverityBusy
	case queue >= 2:
		return SeverityBusy
	default:
		return SeverityNormal
	}
}

func sortSamples(samples []DeviceSample, field string) {
	sort.SliceStable(samples, func(i, j int) bool {
		a := samples[i]
		b := samples[j]

		switch field {
		case "name":
			return a.Metadata.Name < b.Metadata.Name

		case "read":
			if a.ReadBytesPerSecond == b.ReadBytesPerSecond {
				return a.Metadata.Name < b.Metadata.Name
			}
			return a.ReadBytesPerSecond > b.ReadBytesPerSecond

		case "write":
			if a.WriteBytesPerSecond == b.WriteBytesPerSecond {
				return a.Metadata.Name < b.Metadata.Name
			}
			return a.WriteBytesPerSecond > b.WriteBytesPerSecond

		case "iops":
			aIOPS := a.ReadIOPS + a.WriteIOPS
			bIOPS := b.ReadIOPS + b.WriteIOPS

			if aIOPS == bIOPS {
				return a.Metadata.Name < b.Metadata.Name
			}
			return aIOPS > bIOPS

		case "queue":
			if a.AverageQueueSize == b.AverageQueueSize {
				return a.Metadata.Name < b.Metadata.Name
			}
			return a.AverageQueueSize > b.AverageQueueSize

		case "latency":
			aLatency := a.ReadLatencyMS
			if a.WriteLatencyMS > aLatency {
				aLatency = a.WriteLatencyMS
			}

			bLatency := b.ReadLatencyMS
			if b.WriteLatencyMS > bLatency {
				bLatency = b.WriteLatencyMS
			}

			if aLatency == bLatency {
				return a.Metadata.Name < b.Metadata.Name
			}
			return aLatency > bLatency

		default:
			if a.UtilizationPercent == b.UtilizationPercent {
				return a.Metadata.Name < b.Metadata.Name
			}
			return a.UtilizationPercent > b.UtilizationPercent
		}
	})
}

func printHuman(snapshot Snapshot) {
	fmt.Println("Block Sentinel")
	fmt.Println("==============")
	fmt.Println()
	fmt.Printf("Host:     %s\n", snapshot.Hostname)
	fmt.Printf("Kernel:   %s\n", snapshot.Kernel)
	fmt.Printf("Interval: %.2fs\n", snapshot.IntervalSeconds)
	fmt.Printf("Time:     %s\n", snapshot.Timestamp)
	fmt.Println()

	if len(snapshot.Devices) == 0 {
		fmt.Println("No matching block devices found")
		fmt.Println()
		fmt.Printf("Overall: %s\n", snapshot.Overall)
		return
	}

	fmt.Printf(
		"%-10s %-8s %12s %12s %9s %9s %8s %8s %10s\n",
		"DEVICE",
		"TYPE",
		"READ/s",
		"WRITE/s",
		"R-IOPS",
		"W-IOPS",
		"QUEUE",
		"UTIL",
		"STATE",
	)

	for _, device := range snapshot.Devices {
		fmt.Printf(
			"%-10s %-8s %12s %12s %9.1f %9.1f %8.2f %7.1f%% %10s\n",
			device.Metadata.Name,
			shortDeviceType(device.Metadata),
			formatRate(device.ReadBytesPerSecond),
			formatRate(device.WriteBytesPerSecond),
			device.ReadIOPS,
			device.WriteIOPS,
			device.AverageQueueSize,
			device.UtilizationPercent,
			device.Severity,
		)
	}

	fmt.Println()

	for _, device := range snapshot.Devices {
		printDeviceDetails(device)
	}

	fmt.Printf("Overall: %s\n", snapshot.Overall)
}

func printDeviceDetails(device DeviceSample) {
	meta := device.Metadata

	fmt.Printf("Device %s\n", meta.Name)
	fmt.Println(strings.Repeat("-", 7+len(meta.Name)))

	if meta.Model != "" {
		fmt.Printf("Model:           %s\n", meta.Model)
	}

	if meta.Vendor != "" {
		fmt.Printf("Vendor:          %s\n", meta.Vendor)
	}

	if meta.Serial != "" {
		fmt.Printf("Serial:          %s\n", meta.Serial)
	}

	fmt.Printf("Major/minor:     %d:%d\n", meta.Major, meta.Minor)
	fmt.Printf("Type:            %s\n", meta.DeviceType)

	if meta.Rotational {
		fmt.Printf("Media:           rotational\n")
	} else {
		fmt.Printf("Media:           non-rotational\n")
	}

	fmt.Printf("Size:            %s\n", formatBytes(float64(meta.SizeBytes)))
	fmt.Printf("Scheduler:       %s\n", meta.Scheduler)

	if meta.LogicalBlockSize > 0 {
		fmt.Printf("Logical block:   %s\n", formatBytes(float64(meta.LogicalBlockSize)))
	}

	if meta.PhysicalBlockSize > 0 {
		fmt.Printf("Physical block:  %s\n", formatBytes(float64(meta.PhysicalBlockSize)))
	}

	if meta.MinimumIOSize > 0 {
		fmt.Printf("Minimum I/O:     %s\n", formatBytes(float64(meta.MinimumIOSize)))
	}

	if meta.OptimalIOSize > 0 {
		fmt.Printf("Optimal I/O:     %s\n", formatBytes(float64(meta.OptimalIOSize)))
	}

	if meta.ReadAheadKB > 0 {
		fmt.Printf("Read ahead:      %s\n", formatBytes(float64(meta.ReadAheadKB*1024)))
	}

	if meta.QueueDepth > 0 {
		fmt.Printf("Queue depth:     %d\n", meta.QueueDepth)
	}

	fmt.Printf("Read throughput: %s\n", formatRate(device.ReadBytesPerSecond))
	fmt.Printf("Write throughput:%s\n", padRate(formatRate(device.WriteBytesPerSecond)))
	fmt.Printf("Read IOPS:       %.2f\n", device.ReadIOPS)
	fmt.Printf("Write IOPS:      %.2f\n", device.WriteIOPS)

	if device.DiscardIOPS > 0 {
		fmt.Printf("Discard IOPS:    %.2f\n", device.DiscardIOPS)
	}

	if device.FlushIOPS > 0 {
		fmt.Printf("Flush IOPS:      %.2f\n", device.FlushIOPS)
	}

	fmt.Printf("Read latency:    %.2f ms\n", device.ReadLatencyMS)
	fmt.Printf("Write latency:   %.2f ms\n", device.WriteLatencyMS)

	if device.DiscardIOPS > 0 {
		fmt.Printf("Discard latency: %.2f ms\n", device.DiscardLatencyMS)
	}

	fmt.Printf("Average queue:   %.2f\n", device.AverageQueueSize)
	fmt.Printf("I/O in progress: %d\n", device.IOInProgress)
	fmt.Printf("Utilization:     %.1f%%\n", device.UtilizationPercent)
	fmt.Printf("State:           %s\n", device.Severity)
	fmt.Println()
}

func padRate(value string) string {
	return " " + value
}

func shortDeviceType(meta DeviceMetadata) string {
	switch meta.DeviceType {
	case "device-mapper":
		return "dm"
	case "partition":
		return "part"
	default:
		return meta.DeviceType
	}
}

func printJSON(snapshot Snapshot) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(snapshot); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
	}
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

func readUint(path string) uint64 {
	value, _ := readUintOK(path)
	return value
}

func readUintOK(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}

	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}

	return value, true
}

func formatRate(bytesPerSecond float64) string {
	return formatBytes(bytesPerSecond) + "/s"
}

func formatBytes(value float64) string {
	const (
		kib = 1024.0
		mib = 1024.0 * kib
		gib = 1024.0 * mib
		tib = 1024.0 * gib
	)

	switch {
	case value >= tib:
		return fmt.Sprintf("%.2f TiB", value/tib)
	case value >= gib:
		return fmt.Sprintf("%.2f GiB", value/gib)
	case value >= mib:
		return fmt.Sprintf("%.2f MiB", value/mib)
	case value >= kib:
		return fmt.Sprintf("%.2f KiB", value/kib)
	default:
		return fmt.Sprintf("%.0f B", value)
	}
}
