// Copyright 2015-2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license described in the
// LICENSE file.

package netlink

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"encoding/hex"
	"strconv"
	"unsafe"

	"github.com/platinasystems/elib"
)

type Socket struct {
	socket             int
	pid                uint32
	tx_sequence_number uint
	tx_buffer          elib.ByteVec
	rx_buffer          elib.ByteVec
	rx_chan            chan Message
	quit_chan          chan struct{}
}

func (n *Socket) reset_tx_buffer() {
	if len(n.tx_buffer) != 0 {
		n.tx_buffer = n.tx_buffer[:0]
	}
}

type Message interface {
	netlinkMessage()
	Parse(b []byte)
	TxAdd(s *Socket)
}

func (h *Header) String() (s string) {
	s = fmt.Sprintf("%s: seq %d, len %d, pid %d", MessageType(h.Type).String(), h.Sequence, h.Len, h.Pid)
	if h.Flags != 0 {
		s += ", flags " + h.Flags.String()
	}
	return
}

type NoopMessage struct {
	Header Header
}

func (m *NoopMessage) netlinkMessage() {}
func (m *NoopMessage) Parse(b []byte) {
	*m = *(*NoopMessage)(unsafe.Pointer(&b[0]))
}
func (m *NoopMessage) String() string { return m.Header.String() }
func (m *NoopMessage) TxAdd(s *Socket) {
	m.Header.Type = NLMSG_NOOP
	s.TxAddReq(&m.Header, 0)
}

type DoneMessage struct {
	Header Header
}

func (m *DoneMessage) netlinkMessage() {}
func (m *DoneMessage) Parse(b []byte)  { *m = *(*DoneMessage)(unsafe.Pointer(&b[0])) }
func (m *DoneMessage) String() string  { return m.Header.String() }
func (m *DoneMessage) TxAdd(s *Socket) {
	m.Header.Type = NLMSG_NOOP
	s.TxAddReq(&m.Header, 0)
}

type ErrorMessage struct {
	Header Header
	// Unix errno for error.
	Errno int32
	// Header for message with error.
	Req Header
}

func (m *ErrorMessage) netlinkMessage() {}
func (m *ErrorMessage) Parse(b []byte)  { *m = *(*ErrorMessage)(unsafe.Pointer(&b[0])) }
func (m *ErrorMessage) TxAdd(s *Socket) {
	m.Header.Type = NLMSG_ERROR
	b := s.TxAddReq(&m.Header, 4+SizeofHeader)
	e := (*ErrorMessage)(unsafe.Pointer(&b[0]))
	e.Errno = m.Errno
	e.Req = m.Req
}

func (m *ErrorMessage) String() string {
	s := m.Header.String()
	s += fmt.Sprintf(": %s, failed header: %s", syscall.Errno(-m.Errno),
		m.Req.String())
	return s
}

type Attr interface {
	attr()
	String() string
	// Size of instance of this attribute in bytes.
	Size() int
	// Set value of attribute byte array.
	Set(v []byte)
}

type AttrType interface {
	attrType()
	String(i int) string
}

//go:generate go build github.com/platinasystems/elib/gentemplate
//go:generate ./gentemplate -d Package=netlink -id Attr -d Type=Attr github.com/platinasystems/elib/vec.tmpl

type stringAttr string
type hexStringAttr []byte
type int32Attr int32
type int8Attr int8

func (a stringAttr) attr()          {}
func (a stringAttr) Size() int      { return len(a) + 1 }
func (a stringAttr) Set(v []byte)   { copy(v, a); v = append(v, 0) }
func (a stringAttr) String() string { return string(a) }

func (a int32Attr) attr()          {}
func (a int32Attr) Size() int      { return 4 }
func (a int32Attr) Set(v []byte)   { *(*int32Attr)(unsafe.Pointer(&v[0])) = a }
func (a int32Attr) String() string { return strconv.FormatInt(int64(a), 10) }

func (a int8Attr) attr()          {}
func (a int8Attr) Size() int      { return 1 }
func (a int8Attr) Set(v []byte)   { v[0] = byte(a) }
func (a int8Attr) String() string { return strconv.FormatInt(int64(a), 10) }

func (a hexStringAttr) attr()          {}
func (a hexStringAttr) Size() int      { return len(a) }
func (a hexStringAttr) Set(v []byte)   { copy(v, a) }
func (a hexStringAttr) String() string { return hex.EncodeToString(a) }

func (a AttrVec) Size() (l int) {
	for i := range a {
		if a[i] != nil {
			l += SizeofNlAttr + attrAlignLen(a[i].Size())
		}
	}
	return
}

func (a AttrVec) Set(v []byte) {
	vi := 0
	for i := range a {
		if a[i] == nil {
			continue
		}

		s := a[i].Size()

		// Fill in attribute header.
		nla := (*NlAttr)(unsafe.Pointer(&v[vi]))
		nla.Kind = uint16(i)
		nla.Len = uint16(SizeofNlAttr + s)

		// Fill in attribute value.
		a[i].Set(v[vi+SizeofNlAttr : vi+SizeofNlAttr+s])
		vi += SizeofNlAttr + attrAlignLen(s)
	}
}

type AttrArray struct {
	X    AttrVec
	Type AttrType
}

func (a AttrArray) attr()        {}
func (a AttrArray) Size() int    { return a.X.Size() }
func (a AttrArray) Set(v []byte) { a.X.Set(v) }

func (a AttrArray) String() string {
	s := ""
	for i := range a.X {
		if a.X[i] != nil {
			if len(s) > 0 {
				s += ", "
			}
			s += fmt.Sprintf("%s: %s", a.Type.String(i), a.X[i].String())
		}
	}
	return s
}

type LinkStats [n_link_stat]uint32
type LinkStats64 [n_link_stat]uint64

func (a *LinkStats) attr()        {}
func (a *LinkStats) Size() int    { return int(n_link_stat) * 4 }
func (a *LinkStats) Set(v []byte) { *(*LinkStats)(unsafe.Pointer(&v[0])) = *a }
func (a *LinkStats) String() string {
	s := ""
	for i := range a {
		t := LinkStatType(i)
		if a[t] != 0 || t == rx_packets || t == tx_packets {
			if len(s) > 0 {
				s += ", "
			}
			s += fmt.Sprintf("%s: %d", t, a[t])
		}
	}
	return s
}

func (a *LinkStats64) attr()        {}
func (a *LinkStats64) Size() int    { return int(n_link_stat) * 8 }
func (a *LinkStats64) Set(v []byte) { *(*LinkStats64)(unsafe.Pointer(&v[0])) = *a }
func (a *LinkStats64) String() string {
	s := ""
	for i := range a {
		t := LinkStatType(i)
		if a[t] != 0 || t == rx_packets || t == tx_packets {
			if len(s) > 0 {
				s += ", "
			}
			s += fmt.Sprintf("%s: %d", t, a[t])
		}
	}
	return s
}

type IfInfoMessage struct {
	Header Header
	IfInfomsg
	Attrs [IFLA_MAX]Attr
}

func (m *IfInfoMessage) netlinkMessage() {}

const attrFormat = "\n  %-16s %s"

func (m *IfInfoMessage) String() string {
	s := m.Header.String()

	s += fmt.Sprintf("\nIndex: %d, Family: %s, Type: %s, Flags: %s", m.Index,
		AddressFamily(m.Family),
		IfInfoAttrKind(m.Header.Type),
		IfInfoFlags(m.Flags))
	if m.Change != 0 {
		s += fmt.Sprintf(", Changed flags: %s", IfInfoFlags(m.Change))
	}
	for i := range m.Attrs {
		if m.Attrs[i] != nil {
			s += fmt.Sprintf(attrFormat, IfInfoAttrKind(i), m.Attrs[i])
		}
	}
	return s
}

func (m *IfInfoMessage) Parse(b []byte) {
	p := (*IfInfoMessage)(unsafe.Pointer(&b[0]))
	m.Header = p.Header
	m.IfInfomsg = p.IfInfomsg
	b = b[SizeofHeader+SizeofIfInfomsg:]
	for i := 0; i < len(b); {
		n, v, next_i := nextAttr(b, i)
		i = next_i
		switch IfInfoAttrKind(n.Kind) {
		case IFLA_IFNAME, IFLA_QDISC:
			m.Attrs[n.Kind] = stringAttr(string(v[:len(v)-1]))
		case IFLA_NUM_RX_QUEUES, IFLA_NUM_TX_QUEUES, IFLA_PORT_SELF, IFLA_MTU, IFLA_TXQLEN, IFLA_PROMISCUITY, IFLA_GROUP, IFLA_CARRIER_CHANGES:
			m.Attrs[n.Kind] = int32Attr(*(*int32)(unsafe.Pointer(&v[0])))
		case IFLA_CARRIER:
			m.Attrs[n.Kind] = int8Attr(*(*int8)(unsafe.Pointer(&v[0])))
		case IFLA_STATS:
			m.Attrs[n.Kind] = (*LinkStats)(unsafe.Pointer(&v[0]))
		case IFLA_STATS64:
			m.Attrs[n.Kind] = (*LinkStats64)(unsafe.Pointer(&v[0]))
		case IFLA_AF_SPEC:
			m.Attrs[n.Kind] = parse_af_spec(v)
		case IFLA_ADDRESS, IFLA_BROADCAST:
			m.Attrs[n.Kind] = afAddr(AF_UNSPEC, v)
		default:
			m.Attrs[n.Kind] = hexStringAttr(v)
		}
	}
}

func (m *IfInfoMessage) TxAdd(s *Socket) {
	as := AttrVec(m.Attrs[:])
	l := as.Size()
	b := s.TxAddReq(&m.Header, SizeofIfInfomsg+l)
	i := (*IfInfoMessage)(unsafe.Pointer(&b[0]))
	i.IfInfomsg = m.IfInfomsg
	as.Set(b[SizeofHeader+SizeofIfInfomsg:])
}

type Ip4DevConf [IPV4_DEVCONF_MAX]uint32

func (a *Ip4DevConf) attr() {}
func (a *Ip4DevConf) Size() int {
	panic("not implemented")
	return 0
}
func (a *Ip4DevConf) Set(v []byte) {
	panic("not implemented")
}

func (a *Ip4DevConf) String() string {
	s := ""
	for i := range a {
		t := Ip4DevConfKind(i)
		if a[t] != 0 {
			if len(s) > 0 {
				s += ", "
			}
			s += fmt.Sprintf("%s: %d", t, a[t])
		}
	}
	return s
}

func parse_ip4_af_spec(b []byte) *AttrArray {
	as := &AttrArray{Type: &Ip4IfAttrType{}}
	for i := 0; i < len(b); {
		n, v, next_i := nextAttr(b, i)
		i = next_i
		t := Ip4IfAttrKind(n.Kind)
		as.X.Validate(uint(t))
		switch t {
		case IFLA_INET_CONF:
			as.X[t] = (*Ip4DevConf)(unsafe.Pointer(&v[0]))
		default:
			as.X[t] = hexStringAttr(v)
		}
	}
	return as
}

type Ip6DevConf [IPV6_DEVCONF_MAX]uint32

func (a *Ip6DevConf) attr() {}
func (a *Ip6DevConf) Size() int {
	panic("not implemented")
	return 0
}
func (a *Ip6DevConf) Set(v []byte) {
	panic("not implemented")
}
func (a *Ip6DevConf) String() string {
	s := ""
	for i := range a {
		t := Ip6DevConfKind(i)
		if a[t] != 0 {
			if len(s) > 0 {
				s += ", "
			}
			s += fmt.Sprintf("%s: %d", t, a[t])
		}
	}
	return s
}

func parse_ip6_af_spec(b []byte) *AttrArray {
	as := &AttrArray{Type: &Ip6IfAttrType{}}
	for i := 0; i < len(b); {
		n, v, next_i := nextAttr(b, i)
		i = next_i
		t := Ip6IfAttrKind(n.Kind)
		as.X.Validate(uint(t))
		switch t {
		case IFLA_INET6_CONF:
			as.X[t] = (*Ip6DevConf)(unsafe.Pointer(&v[0]))
		default:
			as.X[t] = hexStringAttr(v)
		}
	}
	return as
}

func parse_af_spec(b []byte) *AttrArray {
	as := &AttrArray{Type: &AddressFamilyAttrType{}}
	for i := 0; i < len(b); {
		n, v, next_i := nextAttr(b, i)
		i = next_i
		af := AddressFamily(n.Kind)
		as.X.Validate(uint(af))
		switch af {
		case AF_INET:
			as.X[af] = parse_ip4_af_spec(v)
		case AF_INET6:
			as.X[af] = parse_ip6_af_spec(v)
		default:
			panic("unknown address family " + af.String())
		}
	}
	return as
}

type IfAddrMessage struct {
	Header Header
	IfAddrmsg
	Attrs [IFA_MAX]Attr
}

func (m *IfAddrMessage) netlinkMessage() {}

func (m *IfAddrMessage) String() string {
	s := m.Header.String()
	s += fmt.Sprintf("\nIndex: %d, Family: %s, Prefix Len %d, Flags: %s, Scope: %s", m.Index,
		AddressFamily(m.Family),
		m.Prefixlen, IfAddrFlags(m.Header.Flags), Scope(m.Scope))
	for i := range m.Attrs {
		if m.Attrs[i] != nil {
			s += fmt.Sprintf(attrFormat, IfAddrAttrKind(i), m.Attrs[i])
		}
	}
	return s
}

func (m *IfAddrMessage) Parse(b []byte) {
	p := (*IfAddrMessage)(unsafe.Pointer(&b[0]))
	m.Header = p.Header
	m.IfAddrmsg = p.IfAddrmsg
	b = b[SizeofHeader+SizeofIfAddrmsg:]
	for i := 0; i < len(b); {
		n, v, next_i := nextAttr(b, i)
		i = next_i
		switch IfAddrAttrKind(n.Kind) {
		case IFA_LABEL:
			m.Attrs[n.Kind] = stringAttr(v[:len(v)-1])
		case IFA_FLAGS:
			m.Attrs[n.Kind] = *(*IfAddrFlagAttr)(unsafe.Pointer(&v[0]))
		case IFA_CACHEINFO:
			m.Attrs[n.Kind] = (*IfAddrCacheInfo)(unsafe.Pointer(&v[0]))
		case IFA_ADDRESS, IFA_BROADCAST, IFA_LOCAL:
			m.Attrs[n.Kind] = afAddr(AddressFamily(m.Family), v)
		default:
			m.Attrs[n.Kind] = hexStringAttr(v)
		}
	}
	return
}

func (m *IfAddrMessage) TxAdd(s *Socket) {
	as := AttrVec(m.Attrs[:])
	l := as.Size()
	b := s.TxAddReq(&m.Header, SizeofIfAddrmsg+l)
	i := (*IfAddrMessage)(unsafe.Pointer(&b[0]))
	i.IfAddrmsg = m.IfAddrmsg
	as.Set(b[SizeofHeader+SizeofIfAddrmsg:])
}

type IfAddrFlagAttr uint32

func (a IfAddrFlagAttr) attr()          {}
func (a IfAddrFlagAttr) Size() int      { return 4 }
func (a IfAddrFlagAttr) Set(v []byte)   { *(*IfAddrFlagAttr)(unsafe.Pointer(&v[0])) = a }
func (a IfAddrFlagAttr) String() string { return IfAddrFlags(a).String() }

type RouteMessage struct {
	Header Header
	Rtmsg
	Attrs [RTA_MAX]Attr
}

func (m *RouteMessage) netlinkMessage() {}

func (m *RouteMessage) String() string {
	s := m.Header.String()
	s += fmt.Sprintf("\nFamily: %s, Src/Dst Len %d/%d, Tos %d, Table %d, Protocol %s, Scope: %s, Type %s",
		AddressFamily(m.Family),
		m.SrcLen, m.DstLen, m.Tos, m.Table, m.Protocol, m.Scope, m.Type)
	if m.Flags != 0 {
		s += ", Flags " + m.Flags.String()
	}
	for i := range m.Attrs {
		if m.Attrs[i] != nil {
			s += fmt.Sprintf(attrFormat, RouteAttrKind(i), m.Attrs[i])
		}
	}
	return s
}

func (m *RouteMessage) Parse(b []byte) {
	p := (*RouteMessage)(unsafe.Pointer(&b[0]))
	m.Header = p.Header
	m.Rtmsg = p.Rtmsg
	b = b[SizeofHeader+SizeofRtmsg:]
	for i := 0; i < len(b); {
		n, v, next_i := nextAttr(b, i)
		i = next_i
		switch RouteAttrKind(n.Kind) {
		case RTA_DST, RTA_SRC, RTA_PREFSRC, RTA_GATEWAY:
			m.Attrs[n.Kind] = afAddr(AddressFamily(m.Family), v)
		case RTA_TABLE, RTA_OIF, RTA_PRIORITY:
			m.Attrs[n.Kind] = int32Attr(*(*int32)(unsafe.Pointer(&v[0])))
		default:
			m.Attrs[n.Kind] = hexStringAttr(v)
		}
	}
	return
}

func (m *RouteMessage) TxAdd(s *Socket) {
	as := AttrVec(m.Attrs[:])
	l := as.Size()
	b := s.TxAddReq(&m.Header, SizeofRtmsg+l)
	i := (*RouteMessage)(unsafe.Pointer(&b[0]))
	i.Rtmsg = m.Rtmsg
	as.Set(b[SizeofHeader+SizeofRtmsg:])
}

type NeighborMessage struct {
	Header Header
	Ndmsg
	Attrs [NDA_MAX]Attr
}

func (m *NeighborMessage) netlinkMessage() {}

func (m *NeighborMessage) AttrBytes(kind NeighborAttrKind) []byte {
	return m.Attrs[kind].(Byter).Bytes()
}

func (m *NeighborMessage) String() string {
	s := m.Header.String()
	s += fmt.Sprintf(" Index: %d, Family: %s, Type %s, State %s",
		m.Index, AddressFamily(m.Family),
		RouteType(m.Type), NeighborState(m.State))
	if m.Flags != 0 {
		s += fmt.Sprintf(", Flags %s", NeighborFlags(m.Flags))
	}
	for i := range m.Attrs {
		if m.Attrs[i] != nil {
			s += fmt.Sprintf(attrFormat, NeighborAttrKind(i), m.Attrs[i])
		}
	}
	return s
}

func (m *NeighborMessage) Parse(b []byte) {
	p := (*NeighborMessage)(unsafe.Pointer(&b[0]))
	m.Header = p.Header
	m.Ndmsg = p.Ndmsg
	b = b[SizeofHeader+SizeofNdmsg:]
	for i := 0; i < len(b); {
		n, v, next_i := nextAttr(b, i)
		i = next_i
		switch NeighborAttrKind(n.Kind) {
		case NDA_DST:
			m.Attrs[n.Kind] = afAddr(AddressFamily(m.Family), v)
		case NDA_LLADDR:
			m.Attrs[n.Kind] = afAddr(AF_UNSPEC, v)
		case NDA_PROBES:
			m.Attrs[n.Kind] = int32Attr(*(*int32)(unsafe.Pointer(&v[0])))
		default:
			m.Attrs[n.Kind] = hexStringAttr(v)
		}
	}
	return
}

func (m *NeighborMessage) TxAdd(s *Socket) {
	as := AttrVec(m.Attrs[:])
	l := as.Size()
	b := s.TxAddReq(&m.Header, SizeofNdmsg+l)
	i := (*NeighborMessage)(unsafe.Pointer(&b[0]))
	i.Ndmsg = m.Ndmsg
	as.Set(b[SizeofHeader+SizeofNdmsg:])
}

// txAdd adds a both a nlmsghdr and a request header (e.g. ifinfomsg, ifaddrmsg, rtmsg, ...)
//   to the end of the tx buffer.
func (s *Socket) TxAddReq(header *Header, nBytes int) []byte {
	i := len(s.tx_buffer)
	s.tx_buffer.Resize(uint(messageAlignLen(nBytes) + SizeofHeader))
	h := (*Header)(unsafe.Pointer(&s.tx_buffer[i]))
	h.Len = uint32(nBytes + SizeofHeader)
	h.Type = header.Type
	h.Flags = header.Flags | NLM_F_REQUEST
	h.Pid = s.pid
	header.Pid = s.pid

	// Sequence 0 is reserved for unsolicited messages from kernel.
	if s.tx_sequence_number == 0 {
		s.tx_sequence_number = 1
	}
	h.Sequence = uint32(s.tx_sequence_number)
	header.Sequence = uint32(s.tx_sequence_number)
	s.tx_sequence_number++

	return s.tx_buffer[i:]
}

func (s *Socket) TxAdd(m Message) { m.TxAdd(s) }

func (s *Socket) Tx(m Message) {
	s.TxAdd(m)
	for i := 0; i < len(s.tx_buffer); {
		n, err := syscall.Write(s.socket, s.tx_buffer[i:])
		if err != nil {
			panic(err)
		}
		i += n
	}
	s.reset_tx_buffer()
}

// AFMessage is a generic message depending only on address family.
type GenMessage struct {
	Header
	AddressFamily
}

const SizeofGenMessage = 1

func (m *GenMessage) netlinkMessage() {}
func (m *GenMessage) Parse(b []byte) {
	p := (*GenMessage)(unsafe.Pointer(&b[0]))
	m.Header = p.Header
	m.AddressFamily = p.AddressFamily
}
func (m *GenMessage) TxAdd(s *Socket) {
	b := s.TxAddReq(&m.Header, SizeofGenMessage)
	p := (*GenMessage)(unsafe.Pointer(&b[0]))
	p.AddressFamily = m.AddressFamily
}

func nextAttr(b []byte, i int) (n *NlAttr, v []byte, j int) {
	n = (*NlAttr)(unsafe.Pointer(&b[i]))
	v = b[i+SizeofNlAttr : i+int(n.Len)]
	j = i + attrAlignLen(int(n.Len))
	return
}

func (s *Socket) fillRxBuffer() {
	i := len(s.rx_buffer)
	s.rx_buffer.Resize(4096)
	m, err := syscall.Read(s.socket, s.rx_buffer[i:])
	if err != nil {
		panic(err)
	}
	s.rx_buffer = s.rx_buffer[:i+m]
}

func (s *Socket) rxDispatch(h *Header, msg []byte) {
	var m Message
	switch h.Type {
	case NLMSG_NOOP:
		m = &NoopMessage{}
	case NLMSG_ERROR:
		m = &ErrorMessage{}
	case NLMSG_DONE:
		m = &DoneMessage{}
	case RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK, RTM_SETLINK:
		m = &IfInfoMessage{}
	case RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR:
		m = &IfAddrMessage{}
	case RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE:
		m = &RouteMessage{}
	case RTM_NEWNEIGH, RTM_DELNEIGH, RTM_GETNEIGH:
		m = &NeighborMessage{}
	default:
		panic("unhandled message " + h.Type.String())
	}
	m.Parse(msg)
	s.rx_chan <- m
}

func (s *Socket) Rx() (Message, error) {
	var err error
	msg, opened := <-s.rx_chan
	if !opened {
		err = io.EOF
	}
	return msg, err
}

func (s *Socket) rx() (done bool) {
	s.fillRxBuffer()
	for i := 0; i+SizeofHeader <= len(s.rx_buffer); {
		h := (*Header)(unsafe.Pointer(&s.rx_buffer[i]))
		l := messageAlignLen(int(h.Len))
		if i+l > len(s.rx_buffer) {
			if i == len(s.rx_buffer) {
				s.rx_buffer = s.rx_buffer[:0]
			} else {
				copy(s.rx_buffer[:], s.rx_buffer[i:])
			}
			break
		}

		done = h.Type == NLMSG_DONE
		msg := s.rx_buffer[i : i+int(h.Len)]
		s.rxDispatch(h, msg)
		i += l
	}
	return
}

func (s *Socket) rxUntilDone() {
	for !s.rx() {
	}
}

func New(rx chan Message) (s *Socket, err error) {
	s = &Socket{
		rx_chan:   rx,
		quit_chan: make(chan struct{}),
	}
	s.socket, err = syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		err = os.NewSyscallError("socket", err)
		return
	}
	defer func() {
		if err != nil && s.socket > 0 {
			syscall.Close(s.socket)
		}
	}()

	sa := &syscall.SockaddrNetlink{
		Family: uint16(AF_NETLINK),
		Pid:    s.pid,
		Groups: (1<<RTNLGRP_LINK | 1<<RTNLGRP_NEIGH |
			1<<RTNLGRP_IPV4_IFADDR | 1<<RTNLGRP_IPV4_ROUTE | 1<<RTNLGRP_IPV4_MROUTE |
			1<<RTNLGRP_IPV6_IFADDR | 1<<RTNLGRP_IPV6_ROUTE | 1<<RTNLGRP_IPV6_MROUTE),
	}

	if err = syscall.Bind(s.socket, sa); err != nil {
		err = os.NewSyscallError("bind", err)
		return
	}

	// Increase socket buffering.
	bytes := 128 << 10
	if err = os.NewSyscallError("setsockopt SO_RCVBUF", syscall.SetsockoptInt(s.socket, syscall.SOL_SOCKET, syscall.SO_RCVBUF, bytes)); err != nil {
		return
	}
	if err = os.NewSyscallError("setsockopt SO_SNDBUF", syscall.SetsockoptInt(s.socket, syscall.SOL_SOCKET, syscall.SO_SNDBUF, bytes)); err != nil {
		return
	}
	return
}

func (s *Socket) Close() error {
	close(s.quit_chan)
	return nil
}

type ListenReq struct {
	MsgType
	AddressFamily
}

var DefaultListenReqs = []ListenReq{
	{RTM_GETLINK, AF_PACKET},
	{RTM_GETADDR, AF_INET},
	{RTM_GETROUTE, AF_INET},
	{RTM_GETNEIGH, AF_INET},
	{RTM_GETADDR, AF_INET6},
	{RTM_GETNEIGH, AF_INET6},
	{RTM_GETROUTE, AF_INET6},
}

func (s *Socket) Listen(reqs ...ListenReq) {
	if len(reqs) == 0 {
		reqs = DefaultListenReqs
	}
	for _, r := range reqs {
		m := &GenMessage{}
		m.Type = r.MsgType
		m.Flags = NLM_F_DUMP
		m.AddressFamily = r.AddressFamily
		s.Tx(m)
		s.rxUntilDone()
	}

	for {
		select {
		case _, _ = <-s.quit_chan:
			syscall.Close(s.socket)
			s.socket = -1
			close(s.rx_chan)
			return
		default:
		}
		s.rx()
	}
}
