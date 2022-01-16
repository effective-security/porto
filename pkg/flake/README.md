Flake
=========

A fork from https://github.com/sony/sonyflake

Flake is a distributed unique ID generator inspired by [Twitter's Snowflake](https://blog.twitter.com/2010/announcing-snowflake).  

Differences from the original Sonyflake:
- panic instead of returning errors, as these errors are mostly non actionable and should never occur: `NextID() uint64`
- time units are 1 msec instead of 10
- 16 bits for a machine id,
- 6  bits for a sequence number (64 per 1 ms)
- 41 bits for time in units of 1 msec 

As a result, Flake has the following advantages and disadvantages:

- The lifetime (69 years) is similar to that of Snowflake (69 years)
- It can work on more distributed machines (2^16) than Snowflake (2^10)
- It can generate 2^6 IDs per 1 msec at most in a single machine/thread

Installation
------------

```
go get github.com/effective-security/porto/pkg/flake
```

Usage
-----

The function NewIDGenerator creates a new IDGenerator instance.

```go
func NewIDGenerator(st Settings) IDGenerator
```

You can configure Flake by the struct Settings:

```go
type Settings struct {
	StartTime      time.Time
	MachineID      func() (uint16, error)
	CheckMachineID func(uint16) bool
}
```

- StartTime is the time since which the Flake time is defined as the elapsed time.
  If StartTime is 0, the start time of the Sonyflake is set to "2021-01-01 00:00:00 +0000 UTC".
  If StartTime is ahead of the current time, Flake is not created.

- MachineID returns the unique ID of the Flake instance.
  If MachineID returns an error, Flake will panic.
  If MachineID is nil, default MachineID is used.
  Default MachineID returns the lower 8 bits of the private IP address.

- CheckMachineID validates the uniqueness of the machine ID.
  If CheckMachineID returns false, Flake will panic.
  If CheckMachineID is nil, no validation is done.

In order to get a new unique ID, you just have to call the method NextID.

```go
func (sf *Flake) NextID() uint64
```

License
-------

The MIT License (MIT)
