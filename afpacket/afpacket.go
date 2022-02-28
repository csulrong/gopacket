// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build linux

// Package afpacket provides Go bindings for MMap'd AF_PACKET socket reading.
package afpacket

// Couldn't have done this without:
// http://lxr.free-electrons.com/source/Documentation/networking/packet_mmap.txt
// http://codemonkeytips.blogspot.co.uk/2011/07/asynchronous-packet-socket-reading-with.html

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/google/gopacket"
)

/*
#include <linux/if_packet.h>  // AF_PACKET, sockaddr_ll
#include <linux/if_ether.h>  // ETH_P_ALL
#include <sys/socket.h>  // socket()
#include <unistd.h>  // close()
#include <arpa/inet.h>  // htons()
#include <sys/mman.h>  // mmap(), munmap()
#include <poll.h>  // poll()
*/
import "C"

var pageSize = unix.Getpagesize()

// ErrPoll returned by poll
var ErrPoll = errors.New("packet poll failed")

// ErrTimeout returned on poll timeout
var ErrTimeout = errors.New("packet poll timeout expired")

// ErrFill returned on filling packet to tx ring
var ErrFill = errors.New("no available frames for filling packet")

// AncillaryVLAN structures are used to pass the captured VLAN
// as ancillary data via CaptureInfo.
type AncillaryVLAN struct {
	// The VLAN VID provided by the kernel.
	VLAN int
}

// Stats is a set of counters detailing the work TPacket has done so far.
type Stats struct {
	// Packets is the total number of packets returned to the caller.
	Packets int64
	// Polls is the number of blocking syscalls made waiting for packets.
	// This should always be <= Packets, since with TPacket one syscall
	// can (and often does) return many results.
	Polls int64
}

// SocketStats is a struct where socket stats are stored
type SocketStats C.struct_tpacket_stats

// Packets returns the number of packets seen by this socket.
func (s *SocketStats) Packets() uint {
	return uint(s.tp_packets)
}

// Drops returns the number of packets dropped on this socket.
func (s *SocketStats) Drops() uint {
	return uint(s.tp_drops)
}

// SocketStatsV3 is a struct where socket stats for TPacketV3 are stored
type SocketStatsV3 C.struct_tpacket_stats_v3

// Packets returns the number of packets seen by this socket.
func (s *SocketStatsV3) Packets() uint {
	return uint(s.tp_packets)
}

// Drops returns the number of packets dropped on this socket.
func (s *SocketStatsV3) Drops() uint {
	return uint(s.tp_drops)
}

// QueueFreezes returns the number of queue freezes on this socket.
func (s *SocketStatsV3) QueueFreezes() uint {
	return uint(s.tp_freeze_q_cnt)
}

// TPacket implements packet receiving for Linux AF_PACKET versions 1, 2, and 3.
type TPacket struct {
	// stats is simple statistics on TPacket's run. This MUST be the first entry to ensure alignment for sync.atomic
	stats Stats
	// fd is the C file descriptor.
	fd int
	// ring points to the memory space which is a continuous buffer for both rx and tx ring.
	ring []byte
	// rxRing points to the memory space of the rx ring buffer shared by tpacket and the kernel.
	rxRing []byte
	// rawRxRing is the unsafe pointer that we use to poll for incoming packets
	rawRxRing unsafe.Pointer
	// txRing points to the memory space of the tx ring buffer shared by tpacket and the kernel.
	txRing []byte
	// rawTxRing is the unsafe pointer that we use to fill outgoing packets
	rawTxRing unsafe.Pointer
	// opts contains read-only options for the TPacket object.
	opts options
	// guard rx
	rxMu sync.Mutex
	// rxOffset is the offset into the rx ring of the current header.
	rxOffset int
	// rxCurrent is the current header for rx.
	rxCurrent header
	// guards tx
	txMu sync.Mutex
	// txOffset is the offset into the tx ring of the current header.
	txOffset int
	// shouldReleasePacket is set to true whenever we return packet data, to make sure we remember to release that data back to the kernel.
	shouldReleasePacket bool
	// headerNextNeeded is set to true when header need to move to the next packet. No need to move it case of poll error.
	headerNextNeeded bool
	// tpVersion is the version of TPacket actually in use, set by setRequestedTPacketVersion.
	tpVersion OptTPacketVersion
	// Hackity hack hack hack.  We need to return a pointer to the header with
	// getTPacketHeader, and we don't want to allocate a v3wrapper every time,
	// so we leave it in the TPacket object and return a pointer to it.
	v3Rx v3wrapper
	// v3Tx holds pointer to frame in tx-ring for transmitting packet
	v3Tx v3wrapper

	statsMu sync.Mutex // guards stats below
	// socketStats contains stats from the socket
	socketStats SocketStats
	// same as socketStats, but with an extra field freeze_q_cnt
	socketStatsV3 SocketStatsV3
}

var _ gopacket.ZeroCopyPacketDataSource = &TPacket{}

// bindToInterface binds the TPacket socket to a particular named interface.
func (h *TPacket) bindToInterface(ifaceName string) error {
	ifIndex := 0
	// An empty string here means to listen to all interfaces
	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("InterfaceByName: %v", err)
		}
		ifIndex = iface.Index
	}
	s := &unix.SockaddrLinklayer{
		Protocol: htons(uint16(unix.ETH_P_ALL)),
		Ifindex:  ifIndex,
	}
	return unix.Bind(h.fd, s)
}

// setTPacketVersion asks the kernel to set TPacket to a particular version, and returns an error on failure.
func (h *TPacket) setTPacketVersion(version OptTPacketVersion) error {
	if err := unix.SetsockoptInt(h.fd, unix.SOL_PACKET, unix.PACKET_VERSION, int(version)); err != nil {
		return fmt.Errorf("setsockopt packet_version: %v", err)
	}
	return nil
}

// setRequestedTPacketVersion tries to set TPacket to the requested version or versions.
func (h *TPacket) setRequestedTPacketVersion() error {
	switch {
	case (h.opts.version == TPacketVersionHighestAvailable || h.opts.version == TPacketVersion3) && h.setTPacketVersion(TPacketVersion3) == nil:
		h.tpVersion = TPacketVersion3
	case (h.opts.version == TPacketVersionHighestAvailable || h.opts.version == TPacketVersion2) && h.setTPacketVersion(TPacketVersion2) == nil:
		h.tpVersion = TPacketVersion2
	case (h.opts.version == TPacketVersionHighestAvailable || h.opts.version == TPacketVersion1) && h.setTPacketVersion(TPacketVersion1) == nil:
		h.tpVersion = TPacketVersion1
	default:
		return errors.New("no known tpacket versions work on this machine")
	}
	return nil
}

// setUpRing sets up the shared-memory ring buffer between the user process and the kernel.
func (h *TPacket) setUpRing() (err error) {
	totalRxSize := int(h.opts.rxRing.framesPerBlock * h.opts.rxRing.NumBlocks * h.opts.rxRing.FrameSize)
	totalTxSize := int(h.opts.txRing.framesPerBlock * h.opts.txRing.NumBlocks * h.opts.txRing.FrameSize)
	totalSize := totalRxSize + totalTxSize

	switch h.tpVersion {
	case TPacketVersion1, TPacketVersion2:
		// setup rx ring
		if h.opts.rxRing.NumBlocks > 0 {
			var tp C.struct_tpacket_req
			tp.tp_block_size = C.uint(h.opts.rxRing.BlockSize)
			tp.tp_block_nr = C.uint(h.opts.rxRing.NumBlocks)
			tp.tp_frame_size = C.uint(h.opts.rxRing.FrameSize)
			tp.tp_frame_nr = C.uint(h.opts.rxRing.framesPerBlock * h.opts.rxRing.NumBlocks)
			if err := setsockopt(h.fd, unix.SOL_PACKET, unix.PACKET_RX_RING, unsafe.Pointer(&tp), unsafe.Sizeof(tp)); err != nil {
				return fmt.Errorf("setsockopt packet_rx_ring: %v", err)
			}
		}

		// setup tx ring
		if h.opts.txRing.NumBlocks > 0 {
			var tp C.struct_tpacket_req
			tp.tp_block_size = C.uint(h.opts.txRing.BlockSize)
			tp.tp_block_nr = C.uint(h.opts.txRing.NumBlocks)
			tp.tp_frame_size = C.uint(h.opts.txRing.FrameSize)
			tp.tp_frame_nr = C.uint(h.opts.txRing.framesPerBlock * h.opts.txRing.NumBlocks)
			if err := setsockopt(h.fd, unix.SOL_PACKET, unix.PACKET_TX_RING, unsafe.Pointer(&tp), unsafe.Sizeof(tp)); err != nil {
				return fmt.Errorf("setsockopt packet_tx_ring: %v", err)
			}
		}

	case TPacketVersion3:
		// setup v3 rx ring
		if h.opts.rxRing.NumBlocks > 0 {
			var tp C.struct_tpacket_req3
			tp.tp_block_size = C.uint(h.opts.rxRing.BlockSize)
			tp.tp_block_nr = C.uint(h.opts.rxRing.NumBlocks)
			tp.tp_frame_size = C.uint(h.opts.rxRing.FrameSize)
			tp.tp_frame_nr = C.uint(h.opts.rxRing.framesPerBlock * h.opts.rxRing.NumBlocks)
			tp.tp_retire_blk_tov = C.uint(h.opts.blockTimeout / time.Millisecond)
			if err := setsockopt(h.fd, unix.SOL_PACKET, unix.PACKET_RX_RING, unsafe.Pointer(&tp), unsafe.Sizeof(tp)); err != nil {
				return fmt.Errorf("setsockopt packet_rx_ring v3: %v", err)
			}
		}

		// setup v3 tx ring
		if h.opts.txRing.NumBlocks > 0 {
			var tp C.struct_tpacket_req3
			tp.tp_block_size = C.uint(h.opts.txRing.BlockSize)
			tp.tp_block_nr = C.uint(h.opts.txRing.NumBlocks)
			tp.tp_frame_size = C.uint(h.opts.txRing.FrameSize)
			tp.tp_frame_nr = C.uint(h.opts.txRing.framesPerBlock * h.opts.txRing.NumBlocks)
			tp.tp_retire_blk_tov = C.uint(h.opts.blockTimeout / time.Millisecond)
			if err := setsockopt(h.fd, unix.SOL_PACKET, unix.PACKET_TX_RING, unsafe.Pointer(&tp), unsafe.Sizeof(tp)); err != nil {
				return fmt.Errorf("setsockopt packet_rx_ring v3: %v", err)
			}
		}

	default:
		return errors.New("invalid tpVersion")
	}

	// https://www.kernel.org/doc/html/latest/networking/packet_mmap.html
	// To use one socket for capture and transmission, the mapping of both the RX and TX buffer ring
	// has to be done with one call to mmap
	h.ring, err := unix.Mmap(h.fd, 0, totalSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return err
	}
	if h.ring == nil {
		return errors.New("no ring")
	}
	h.rxRing = h.ring[:totalRxSize]
	h.rawRxRing = unsafe.Pointer(&h.rxRing[0])

	h.txRing = h.ring[totalRxSize:]
	h.rawTxRing = unsafe.Pointer(&h.txRing[0])

	return nil
}

// Close cleans up the TPacket.  It should not be used after the Close call.
func (h *TPacket) Close() {
	if h.fd == -1 {
		return // already closed.
	}
	if h.ring != nil {
		unix.Munmap(h.ring)
	}
	h.ring = nil
	h.rxRing = nil
	h.txRing = nil
	unix.Close(h.fd)
	h.fd = -1
	runtime.SetFinalizer(h, nil)
}

// NewTPacket returns a new TPacket object for reading packets off the wire.
// Its behavior may be modified by passing in any/all of afpacket.Opt* to this
// function.
// If this function succeeds, the user should be sure to Close the returned
// TPacket when finished with it.
func NewTPacket(opts ...interface{}) (h *TPacket, err error) {
	h = &TPacket{}
	if h.opts, err = parseOptions(opts...); err != nil {
		return nil, err
	}
	var proto int = int(htons(unix.ETH_P_ALL))
	if h.opts.rxRing.NumBlocks == 0 {
		// only created for transmission, set protocol to zero to avoid an expensive call
		// to packet_rcv() in kernel
		proto = 0
	}
	fd, err := unix.Socket(unix.AF_PACKET, int(h.opts.socktype), proto)
	if err != nil {
		return nil, err
	}
	h.fd = fd
	if err = h.bindToInterface(h.opts.iface); err != nil {
		goto errlbl
	}
	if err = h.setRequestedTPacketVersion(); err != nil {
		goto errlbl
	}
	if err = h.setUpRing(); err != nil {
		goto errlbl
	}
	// Clear stat counter from socket
	if err = h.InitSocketStats(); err != nil {
		goto errlbl
	}
	runtime.SetFinalizer(h, (*TPacket).Close)
	return h, nil
errlbl:
	h.Close()
	return nil, err
}

// SetBPF attaches a BPF filter to the underlying socket
func (h *TPacket) SetBPF(filter []bpf.RawInstruction) error {
	var p unix.SockFprog
	if len(filter) > int(^uint16(0)) {
		return errors.New("filter too large")
	}
	p.Len = uint16(len(filter))
	p.Filter = (*unix.SockFilter)(unsafe.Pointer(&filter[0]))

	return setsockopt(h.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, unsafe.Pointer(&p), unix.SizeofSockFprog)
}

func (h *TPacket) releaseCurrentPacket() error {
	h.rxCurrent.clearStatus()
	h.rxOffset++
	h.shouldReleasePacket = false
	return nil
}

// ZeroCopyReadPacketData reads the next packet off the wire, and returns its data.
// The slice returned by ZeroCopyReadPacketData points to bytes owned by the
// TPacket.  Each call to ZeroCopyReadPacketData invalidates any data previously
// returned by ZeroCopyReadPacketData.  Care must be taken not to keep pointers
// to old bytes when using ZeroCopyReadPacketData... if you need to keep data past
// the next time you call ZeroCopyReadPacketData, use ReadPacketData, which copies
// the bytes into a new buffer for you.
//  tp, _ := NewTPacket(...)
//  data1, _, _ := tp.ZeroCopyReadPacketData()
//  // do everything you want with data1 here, copying bytes out of it if you'd like to keep them around.
//  data2, _, _ := tp.ZeroCopyReadPacketData()  // invalidates bytes in data1
func (h *TPacket) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	h.rxMu.Lock()
retry:
	if h.rxCurrent == nil || !h.headerNextNeeded || !h.rxCurrent.next() {
		if h.shouldReleasePacket {
			h.releaseCurrentPacket()
		}
		h.rxCurrent = h.getTPacketHeader(true)
		if err = h.pollForFirstPacket(h.rxCurrent); err != nil {
			h.headerNextNeeded = false
			h.rxMu.Unlock()
			return
		}
		// We received an empty block
		if h.rxCurrent.getLength() == 0 {
			goto retry
		}
	}
	data = h.rxCurrent.getData(&h.opts)
	ci.Timestamp = h.rxCurrent.getTime()
	ci.CaptureLength = len(data)
	ci.Length = h.rxCurrent.getLength()
	ci.InterfaceIndex = h.rxCurrent.getIfaceIndex()
	vlan := h.rxCurrent.getVLAN()
	if vlan >= 0 {
		ci.AncillaryData = append(ci.AncillaryData, AncillaryVLAN{vlan})
	}
	atomic.AddInt64(&h.stats.Packets, 1)
	h.headerNextNeeded = true
	h.rxMu.Unlock()

	return
}

// Stats returns statistics on the packets the TPacket has seen so far.
func (h *TPacket) Stats() (Stats, error) {
	return Stats{
		Polls:   atomic.LoadInt64(&h.stats.Polls),
		Packets: atomic.LoadInt64(&h.stats.Packets),
	}, nil
}

// InitSocketStats clears socket counters and return empty stats.
func (h *TPacket) InitSocketStats() error {
	if h.tpVersion == TPacketVersion3 {
		socklen := unsafe.Sizeof(h.socketStatsV3)
		slt := C.socklen_t(socklen)
		var ssv3 SocketStatsV3

		err := getsockopt(h.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS, unsafe.Pointer(&ssv3), uintptr(unsafe.Pointer(&slt)))
		if err != nil {
			return err
		}
		h.socketStatsV3 = SocketStatsV3{}
	} else {
		socklen := unsafe.Sizeof(h.socketStats)
		slt := C.socklen_t(socklen)
		var ss SocketStats

		err := getsockopt(h.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS, unsafe.Pointer(&ss), uintptr(unsafe.Pointer(&slt)))
		if err != nil {
			return err
		}
		h.socketStats = SocketStats{}
	}
	return nil
}

// SocketStats saves stats from the socket to the TPacket instance.
func (h *TPacket) SocketStats() (SocketStats, SocketStatsV3, error) {
	h.statsMu.Lock()
	defer h.statsMu.Unlock()
	// We need to save the counters since asking for the stats will clear them
	if h.tpVersion == TPacketVersion3 {
		socklen := unsafe.Sizeof(h.socketStatsV3)
		slt := C.socklen_t(socklen)
		var ssv3 SocketStatsV3

		err := getsockopt(h.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS, unsafe.Pointer(&ssv3), uintptr(unsafe.Pointer(&slt)))
		if err != nil {
			return SocketStats{}, SocketStatsV3{}, err
		}

		h.socketStatsV3.tp_packets += ssv3.tp_packets
		h.socketStatsV3.tp_drops += ssv3.tp_drops
		h.socketStatsV3.tp_freeze_q_cnt += ssv3.tp_freeze_q_cnt
		return h.socketStats, h.socketStatsV3, nil
	}
	socklen := unsafe.Sizeof(h.socketStats)
	slt := C.socklen_t(socklen)
	var ss SocketStats

	err := getsockopt(h.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS, unsafe.Pointer(&ss), uintptr(unsafe.Pointer(&slt)))
	if err != nil {
		return SocketStats{}, SocketStatsV3{}, err
	}

	h.socketStats.tp_packets += ss.tp_packets
	h.socketStats.tp_drops += ss.tp_drops
	return h.socketStats, h.socketStatsV3, nil
}

// ReadPacketDataTo reads packet data into a user-supplied buffer.
// This function reads up to the length of the passed-in slice.
// The number of bytes read into data will be returned in ci.CaptureLength,
// which is the minimum of the size of the passed-in buffer and the size of
// the captured packet.
func (h *TPacket) ReadPacketDataTo(data []byte) (ci gopacket.CaptureInfo, err error) {
	var d []byte
	d, ci, err = h.ZeroCopyReadPacketData()
	if err != nil {
		return
	}
	ci.CaptureLength = copy(data, d)
	return
}

// ReadPacketData reads the next packet, copies it into a new buffer, and returns
// that buffer.  Since the buffer is allocated by ReadPacketData, it is safe for long-term
// use.  This implements gopacket.PacketDataSource.
func (h *TPacket) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	var d []byte
	d, ci, err = h.ZeroCopyReadPacketData()
	if err != nil {
		return
	}
	data = make([]byte, len(d))
	copy(data, d)
	return
}

func (h *TPacket) getTPacketHeader(rx bool) header {
	var position uintptr
	switch h.tpVersion {
	case TPacketVersion1:
		if rx {
			if h.rxOffset >= h.opts.rxRing.framesPerBlock*h.opts.rxRing.NumBlocks {
				h.rxOffset = 0
			}
			position = uintptr(h.rawRxRing) + uintptr(h.opts.rxRing.FrameSize*h.rxOffset)
		} else {
			if h.txOffset >= h.opts.txRing.framesPerBlock*h.opts.txRing.NumBlocks {
				h.txOffset = 0
			}
			position = uintptr(h.rawTxRing) + uintptr(h.opts.txRing.FrameSize*h.txOffset)
		}
		return (*v1header)(unsafe.Pointer(position))
	case TPacketVersion2:
		if rx {
			if h.rxOffset >= h.opts.rxRing.framesPerBlock*h.opts.rxRing.NumBlocks {
				h.rxOffset = 0
			}
			position = uintptr(h.rawRxRing) + uintptr(h.opts.rxRing.FrameSize*h.rxOffset)
		} else {
			if h.txOffset >= h.opts.txRing.framesPerBlock*h.opts.txRing.NumBlocks {
				h.txOffset = 0
			}
			position = uintptr(h.rawTxRing) + uintptr(h.opts.txRing.FrameSize*h.txOffset)
		}
		return (*v2header)(unsafe.Pointer(position))
	case TPacketVersion3:
		// TPacket3 uses each block to return values, instead of each frame.  Hence we need to rotate when we hit #blocks, not #frames.
		if rx {
			if h.rxOffset >= h.opts.rxRing.NumBlocks {
				h.rxOffset = 0
			}
			position = uintptr(h.rawRxRing) + uintptr(h.opts.rxRing.FrameSize*h.rxOffset*h.opts.rxRing.framesPerBlock)
			h.v3Rx = initV3Wrapper(unsafe.Pointer(position), true)
			return &h.v3Rx
		} else {
			if h.txOffset >= h.opts.txRing.framesPerBlock*h.opts.txRing.NumBlocks {
				h.txOffset = 0
			}
			// NOTE: txOffset points to #frame in tx ring, instead of #block like rxOffset in rx ring
			position = uintptr(h.rawTxRing) + uintptr(h.opts.txRing.FrameSize*h.txOffset)
			h.v3Tx = initV3Wrapper(unsafe.Pointer(position), false)
			return &h.v3Tx
		}
	}
	panic("handle tpacket version is invalid")
}

func (h *TPacket) pollForFirstPacket(hdr header) error {
	tm := int(h.opts.pollTimeout / time.Millisecond)
	for hdr.getStatus()&unix.TP_STATUS_USER == 0 {
		pollset := [1]unix.PollFd{
			{
				Fd:     int32(h.fd),
				Events: unix.POLLIN,
			},
		}
		n, err := unix.Poll(pollset[:], tm)
		if n == 0 {
			return ErrTimeout
		}

		atomic.AddInt64(&h.stats.Polls, 1)
		if pollset[0].Revents&unix.POLLERR > 0 {
			return ErrPoll
		}
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
	}

	h.shouldReleasePacket = true
	return nil
}

// FanoutType determines the type of fanout to use with a TPacket SetFanout call.
type FanoutType int

// FanoutType values.
const (
	FanoutHash FanoutType = unix.PACKET_FANOUT_HASH
	// It appears that defrag only works with FanoutHash, see:
	// http://lxr.free-electrons.com/source/net/packet/af_packet.c#L1204
	FanoutHashWithDefrag FanoutType = unix.PACKET_FANOUT_FLAG_DEFRAG
	FanoutLoadBalance    FanoutType = unix.PACKET_FANOUT_LB
	FanoutCPU            FanoutType = unix.PACKET_FANOUT_CPU
	FanoutRollover       FanoutType = unix.PACKET_FANOUT_ROLLOVER
	FanoutRandom         FanoutType = unix.PACKET_FANOUT_RND
	FanoutQueueMapping   FanoutType = unix.PACKET_FANOUT_QM
	FanoutCBPF           FanoutType = unix.PACKET_FANOUT_CBPF
	FanoutEBPF           FanoutType = unix.PACKET_FANOUT_EBPF
)

// SetFanout activates TPacket's fanout ability.
// Use of Fanout requires creating multiple TPacket objects and the same id/type to
// a SetFanout call on each.  Note that this can be done cross-process, so if two
// different processes both call SetFanout with the same type/id, they'll share
// packets between them.  The same should work for multiple TPacket objects within
// the same process.
func (h *TPacket) SetFanout(t FanoutType, id uint16) error {
	h.rxMu.Lock()
	defer h.rxMu.Unlock()
	arg := C.int(t) << 16
	arg |= C.int(id)
	return setsockopt(h.fd, unix.SOL_PACKET, unix.PACKET_FANOUT, unsafe.Pointer(&arg), unsafe.Sizeof(arg))
}

// WritePacketData transmits a raw packet.
func (h *TPacket) WritePacketData(pkt []byte) error {
	_, err := unix.Write(h.fd, pkt)
	return err
}

// BypassQdisc enables bypassing qdisc layer and forces pushing packets to driver directly.
func (h *TPacket) BypassQdisc() error {
	h.txMu.Lock()
	defer h.txMu.Unlock()
	v := C.int(1)
	return setsockopt(h.fd, unix.SOL_SOCKET, unix.PACKET_QDISC_BYPASS, unsafe.Pointer(&v), unsafe.Sizeof(v))
}

// Fill a packet's data to the tx ring
func (h *TPacket) FillPacketData(pkt []byte) error {
	h.txMu.Lock()
	defer h.txMu.Unlock()

	for h.txOffset = 0; h.txOffset < h.opts.txRing.framesPerBlock*h.opts.txRing.NumBlocks; h.txOffset++ {
		// find an available frame for holding the packet data
		txCurrent := h.getTPacketHeader(false)
		if txCurrent.getStatus() != unix.TP_STATUS_AVAILABLE {
			continue
		}

		// put the packet data into the frame
		txCurrent.putData(pkt)

		// call sendto in non-blocking mode to notify kernel to send the packet to output device
		unix.Sendto(h.fd, nil, unix.MSG_DONTWAIT, nil)

		return nil
	}

	// not found an available frame to fill the packet to tx ring
	return ErrFill
}

// Fill a packet to the TX ring
func (h *TPacket) FillPacket(pkt gopacket.Packet) error {
	return h.FillPacketData(pkt.Data())
}

// Fill multiple packets to the TX ring at a time
func (h *TPacket) FillPackets(pkts []gopacket.Packet) (numFilled int) {
	if len(pkts) == 0 {
		return
	}

	h.txMu.Lock()
	defer h.txMu.Unlock()

	// iterate frames in tx ring to find available slots for holding the packet data
	for h.txOffset = 0; h.txOffset < h.opts.txRing.framesPerBlock*h.opts.txRing.NumBlocks && numFilled < len(pkts); h.txOffset++ {
		txCurrent := h.getTPacketHeader(false)
		if txCurrent.getStatus() != unix.TP_STATUS_AVAILABLE {
			continue
		}

		// put the packet data into the frame
		pkt := pkts[numFilled]
		txCurrent.putData(pkt.Data())
	}

	// call sendto in non-blocking mode to notify kernel to send the packet to output device
	unix.Sendto(h.fd, nil, unix.MSG_DONTWAIT, nil)

	return
}
