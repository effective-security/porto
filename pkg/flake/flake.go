// Package flake implements Snowflake, a distributed unique ID generator inspired by Twitter's Snowflake.
//
// A Flake ID is composed of
//
//	39 bits for time in units of 10 msec
//	 8 bits for a sequence number
//	16 bits for a machine id
package flake

import (
	"net"
	"sync"
	"time"

	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "flake")

// IDGenerator defines an interface to generate unique ID accross the cluster
type IDGenerator interface {
	// NextID generates a next unique ID.
	NextID() uint64
}

// DefaultIDGenerator for the app
var DefaultIDGenerator IDGenerator

// NowFunc returns the current time; it's overridden in tests.
var NowFunc = time.Now

func init() {
	DefaultIDGenerator = NewIDGenerator(Settings{
		StartTime: DefaultStartTime,
	})
}

// These constants are the bit lengths of Flake ID parts.
const (
	BitLenMachineID = 16                                    // bit length of machine id, 2^16
	BitLenSequence  = 6                                     // bit length of sequence number
	BitLenTime      = 63 - BitLenMachineID - BitLenSequence // bit length of time
	MaskSequence16  = uint16(1<<BitLenSequence - 1)
	MaskSequence    = uint64(MaskSequence16) << BitLenMachineID
	MaskMachineID   = uint64(1<<BitLenMachineID - 1)

	FlakeTimeUnit = int64(1 * time.Millisecond)
)

// DefaultStartTime provides default start time for the Flake
var DefaultStartTime = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC).UTC()

// Settings configures Flake:
//
// StartTime is the time since which the Flake time is defined as the elapsed time.
// If StartTime is 0, the start time of the Flake is set to "2021-01-01 00:00:00 +0000 UTC".
// If StartTime is ahead of the current time, Flake is not created.
//
// MachineID returns the unique ID of the Flake instance.
// If MachineID returns an error, Flake is not created.
// If MachineID is nil, default MachineID is used.
// Default MachineID returns the lower 8 bits of the private IP address,
//
// CheckMachineID validates the uniqueness of the machine ID.
// If CheckMachineID returns false, Flake is not created.
// If CheckMachineID is nil, no validation is done.
type Settings struct {
	StartTime      time.Time
	MachineID      func() (uint16, error)
	CheckMachineID func(uint16) bool
}

// Flake is a distributed unique ID generator.
type Flake struct {
	mutex       sync.Mutex
	startTime   int64
	elapsedTime int64
	sequence    uint16
	maxSequence uint16
	machineID   uint16
	firstID     uint64
	lastID      uint64
}

// NewIDGenerator returns a new Flake configured with the given Settings.
// NewIDGenerator panics in the following cases:
// - Settings.StartTime is ahead of the current time.
// - Settings.MachineID returns an error.
// - Settings.CheckMachineID returns false.
func NewIDGenerator(st Settings) IDGenerator {
	sf := new(Flake)
	sf.sequence = MaskSequence16

	now := NowFunc()
	if st.StartTime.IsZero() {
		st.StartTime = DefaultStartTime
	}

	if st.StartTime.After(now) {
		logger.Panicf("start time %s is ahead of current time: %s",
			st.StartTime.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	sf.startTime = toFlakeTime(st.StartTime)

	var err error
	if st.MachineID == nil {
		sf.machineID, err = defaultMachineID()
	} else {
		sf.machineID, err = st.MachineID()
	}
	if err != nil {
		logger.Panicf("machine ID failed: %+v", err)
	}
	if st.CheckMachineID != nil && !st.CheckMachineID(sf.machineID) {
		logger.Panicf("CheckMachineID ID failed: %d", sf.machineID)
	}

	sf.firstID = sf.NextID()
	idTime := IDTime(sf, sf.firstID)

	logger.KV(xlog.DEBUG,
		"start_time", st.StartTime.Format(time.RFC3339),
		"start_flaketime", sf.startTime,
		"machine_id", sf.machineID,
		"first_id", sf.firstID,
		"frist_id_meta", Decompose(sf.firstID),
		"first_id_time", idTime.Format(time.RFC3339),
	)

	return sf
}

// NextID generates a next unique ID.
// After the Flake time overflows, NextID panics.
func (sf *Flake) NextID() uint64 {
	sf.mutex.Lock()
	defer sf.mutex.Unlock()

	current := currentElapsedTime(sf.startTime)
	if sf.elapsedTime < current {
		sf.elapsedTime = current
		sf.sequence = 0
	} else { // sf.elapsedTime >= current
		sf.sequence = (sf.sequence + 1) & MaskSequence16
		if sf.sequence > sf.maxSequence {
			sf.maxSequence = sf.sequence
		}

		if sf.sequence == 0 {
			sf.elapsedTime++
			overtime := sf.elapsedTime - current
			sleep := sleepTime((overtime))
			//logger.Noticef("sleep_overtime=%v", sleep)
			time.Sleep(sleep)
		}
	}

	sf.lastID = sf.toID()
	return sf.lastID
}

func toFlakeTime(t time.Time) int64 {
	return t.UnixNano() / FlakeTimeUnit
}

func fromFlakeTime(f int64) time.Time {
	return time.Unix(0, f*FlakeTimeUnit).UTC()
}

func currentElapsedTime(startTime int64) int64 {
	return toFlakeTime(NowFunc()) - startTime
}

func sleepTime(overtime int64) time.Duration {
	return time.Nanosecond *
		time.Duration(overtime*FlakeTimeUnit-NowFunc().UnixNano()%FlakeTimeUnit)
}

func (sf *Flake) toID() uint64 {
	if sf.elapsedTime >= 1<<BitLenTime {
		logger.Panic("over the time limit")
	}

	return uint64(sf.elapsedTime)<<(BitLenSequence+BitLenMachineID) |
		uint64(sf.sequence)<<BitLenMachineID |
		uint64(sf.machineID)
}

// NOTE: we don't return error here,
// as Mac and test containers may not have InterfaceAddrs
func defaultMachineID() (uint16, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		logger.KV(xlog.ERROR, "reason", "InterfaceAddrs", "err", err)
		return 0, nil
	}

	for _, a := range as {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		ip := ipnet.IP.To16()
		last := len(ip)
		id := (uint16(ip[last-2])<<8 + uint16(ip[last-1])) & uint16(MaskMachineID)
		//logger.Noticef("machine_id=%d, ip=%v, ip_len=%d", id, ip.String(), last)
		return id, nil
	}
	logger.KV(xlog.ERROR, "reason", "no_private_ip")
	return 0, nil
}

// Decompose returns a set of Flake ID parts.
func Decompose(id uint64) map[string]uint64 {
	msb := id >> 63
	time := id >> (BitLenSequence + BitLenMachineID)
	sequence := (id & MaskSequence) >> BitLenMachineID
	machineID := id & MaskMachineID
	return map[string]uint64{
		"id":         id,
		"msb":        msb,
		"time":       time,
		"sequence":   sequence,
		"machine_id": machineID,
	}
}

// IDTime returns the timestamp of the flake ID.
func IDTime(g IDGenerator, id uint64) time.Time {
	start := int64(0)
	if fl, ok := g.(*Flake); ok {
		start = fl.startTime
	}
	return fromFlakeTime(start + int64(id>>(BitLenSequence+BitLenMachineID)))
}

// FirstID returns the first ID generated by the generator.
func FirstID(g IDGenerator) uint64 {
	if fl, ok := g.(*Flake); ok {
		return fl.firstID
	}
	return 0
}

// LastID returns the last ID generated by the generator.
func LastID(g IDGenerator) uint64 {
	if fl, ok := g.(*Flake); ok {
		return fl.lastID
	}
	return 0
}
