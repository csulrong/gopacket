// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build linux

package afpacket

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// OptTPacketVersion is the version of TPacket to use.
// It can be passed into NewTPacket.
type OptTPacketVersion int

// String returns a string representation of the version, generally of the form V#.
func (t OptTPacketVersion) String() string {
	switch t {
	case TPacketVersion1:
		return "V1"
	case TPacketVersion2:
		return "V2"
	case TPacketVersion3:
		return "V3"
	case TPacketVersionHighestAvailable:
		return "HighestAvailable"
	}
	return "InvalidVersion"
}

// OptSocketType is the socket type used to open the TPacket socket.
type OptSocketType int

func (t OptSocketType) String() string {
	switch t {
	case SocketRaw:
		return "SOCK_RAW"
	case SocketDgram:
		return "SOCK_DGRAM"
	}
	return "UnknownSocketType"
}

// TPacket version numbers for use with NewHandle.
const (
	// TPacketVersionHighestAvailable tells NewHandle to use the highest available version of tpacket the kernel has available.
	// This is the default, should a version number not be given in NewHandle's options.
	TPacketVersionHighestAvailable = OptTPacketVersion(-1)
	TPacketVersion1                = OptTPacketVersion(unix.TPACKET_V1)
	TPacketVersion2                = OptTPacketVersion(unix.TPACKET_V2)
	TPacketVersion3                = OptTPacketVersion(unix.TPACKET_V3)
	tpacketVersionMax              = TPacketVersion3
	tpacketVersionMin              = -1
	// SocketRaw is the default socket type.  It returns packet data
	// including the link layer (ethernet headers, etc).
	SocketRaw = OptSocketType(unix.SOCK_RAW)
	// SocketDgram strips off the link layer when reading packets, and adds
	// the link layer back automatically on packet writes (coming soon...)
	SocketDgram = OptSocketType(unix.SOCK_DGRAM)
)

// OptInterface is the specific interface to bind to.
// It can be passed into NewTPacket.
type OptInterface string

// OptFrameSize is TPacket's tp_frame_size
// It can be passed into NewTPacket.
type OptFrameSize int

// OptBlockSize is TPacket's tp_block_size
// It can be passed into NewTPacket.
type OptBlockSize int

// OptNumBlocks is TPacket's tp_block_nr
// It can be passed into NewTPacket.
type OptNumBlocks int

// RxRingOptions is the collection of options for TPacket's rx ring
// It can be passed into NewTPacket.
type RxRingOptions RingOptions

// TxRingOptions is the collection of options for TPacket's tx ring
// It can be passed into NewTPacket.
type TxRingOptions RingOptions

// OptBlockTimeout is TPacket v3's tp_retire_blk_tov.  Note that it has only millisecond granularity, so must be >= 1 ms.
// It can be passed into NewTPacket.
type OptBlockTimeout time.Duration

// OptPollTimeout is the number of milliseconds that poll() should block waiting  for a file
// descriptor to become ready. Specifying a negative value in  time‐out means an infinite timeout.
type OptPollTimeout time.Duration

// OptAddVLANHeader modifies the packet data that comes back from the
// kernel by adding in the VLAN header that the NIC stripped.  AF_PACKET by
// default uses VLAN offloading, in which the NIC strips the VLAN header off of
// the packet before handing it to the kernel.  This means that, even if a
// packet has an 802.1q header on the wire, it'll show up without one by the
// time it goes through AF_PACKET.  If this option is true, the VLAN header is
// added back in before the packet is returned.  Note that this potentially has
// a large performance hit, especially in otherwise zero-copy operation.
//
// Note that if you do not need to have a "real" VLAN layer, it may be
// preferable to use the VLAN ID provided by the AncillaryVLAN struct
// in CaptureInfo.AncillaryData, which is populated out-of-band and has
// negligible performance impact. Such ancillary data will automatically
// be provided if available.
type OptAddVLANHeader bool

// Default constants used by options.
const (
	DefaultFrameSize    = 4096                   // Default value for OptFrameSize.
	DefaultBlockSize    = DefaultFrameSize * 128 // Default value for OptBlockSize.
	DefaultNumBlocks    = 128                    // Default value for OptNumBlocks.
	DefaultBlockTimeout = 64 * time.Millisecond  // Default value for OptBlockTimeout.
	DefaultPollTimeout  = -1 * time.Millisecond  // Default value for OptPollTimeout. This blocks forever.
)

type RingOptions struct {
	FrameSize      int
	BlockSize      int
	NumBlocks      int
	framesPerBlock int
}

type options struct {
	rxRing        RingOptions
	txRing        RingOptions
	addVLANHeader bool
	blockTimeout  time.Duration
	pollTimeout   time.Duration
	version       OptTPacketVersion
	socktype      OptSocketType
	iface         string
}

var defaultOpts = options{
	rxRing: RingOptions{
		FrameSize:      DefaultFrameSize,
		BlockSize:      DefaultBlockSize,
		NumBlocks:      DefaultNumBlocks,
		framesPerBlock: DefaultBlockSize / DefaultFrameSize,
	},
	txRing: RingOptions{
		FrameSize:      DefaultFrameSize,
		BlockSize:      DefaultBlockSize,
		NumBlocks:      DefaultNumBlocks,
		framesPerBlock: DefaultBlockSize / DefaultFrameSize,
	},
	blockTimeout: DefaultBlockTimeout,
	pollTimeout:  DefaultPollTimeout,
	version:      TPacketVersionHighestAvailable,
	socktype:     SocketRaw,
}

func parseOptions(opts ...interface{}) (ret options, err error) {
	ret = defaultOpts
	for _, opt := range opts {
		switch v := opt.(type) {
		case RxRingOptions:
			ret.rxRing = RingOptions(v)
			ret.rxRing.framesPerBlock = v.BlockSize / v.FrameSize
		case TxRingOptions:
			ret.txRing = RingOptions(v)
			ret.txRing.framesPerBlock = v.BlockSize / v.FrameSize
		case OptBlockTimeout:
			ret.blockTimeout = time.Duration(v)
		case OptPollTimeout:
			ret.pollTimeout = time.Duration(v)
		case OptTPacketVersion:
			ret.version = v
		case OptInterface:
			ret.iface = string(v)
		case OptSocketType:
			ret.socktype = v
		case OptAddVLANHeader:
			ret.addVLANHeader = bool(v)
		default:
			err = errors.New("unknown type in options")
			return
		}
	}
	if err = ret.check(); err != nil {
		return
	}

	return
}
func (o options) check() error {
	switch {
	case o.rxRing.BlockSize%pageSize != 0:
		return fmt.Errorf("rx ring: block size %d must be divisible by page size %d", o.rxRing.BlockSize, pageSize)
	case o.rxRing.BlockSize%o.rxRing.FrameSize != 0:
		return fmt.Errorf("rx ring: block size %d must be divisible by frame size %d", o.rxRing.BlockSize, o.rxRing.FrameSize)
	case o.txRing.BlockSize%pageSize != 0:
		return fmt.Errorf("tx ring: block size %d must be divisible by page size %d", o.txRing.BlockSize, pageSize)
	case o.txRing.BlockSize%o.txRing.FrameSize != 0:
		return fmt.Errorf("tx ring: block size %d must be divisible by frame size %d", o.txRing.BlockSize, o.txRing.FrameSize)
	case o.rxRing.NumBlocks < 1 && o.txRing.NumBlocks < 1:
		return fmt.Errorf("num blocks of both rx and tx rings cannot be < 1 at the same time")
	case o.blockTimeout < time.Millisecond:
		return fmt.Errorf("block timeout %v must be > %v", o.blockTimeout, time.Millisecond)
	case o.version < tpacketVersionMin || o.version > tpacketVersionMax:
		return fmt.Errorf("tpacket version %v is invalid", o.version)
	}
	return nil
}
