// Copyright 2015-2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license described in the
// LICENSE file.

package netlink

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"encoding/hex"
	"strconv"
	"unsafe"

	"github.com/platinasystems/elib"
)

type attrer interface {
	attr()
}
type attrTyper interface {
	attrType()
}
type Byter interface {
	Bytes() []byte
}
type IthStringer interface {
	IthString(int) string
}
type Closer interface {
	Close() error
}
type netlinkMessager interface {
	netlinkMessage()
}
type Parser interface {
	Parse([]byte)
}
type Runer interface {
	Rune() rune
}
type Setter interface {
	Set([]byte)
}
type Sizer interface {
	Size() int
}
type Stringer interface {
	String() string
}
type TxAdder interface {
	TxAdd(*Socket)
}
type Uint8er interface {
	Uint() uint8
}
type Uint32er interface {
	Uint() uint32
}
type Uint64er interface {
	Uint() uint64
}

type AttrType interface {
	attrTyper
	IthStringer
}

type Attr interface {
	attrer
	Setter
	Sizer
	Stringer
}

type Message interface {
	netlinkMessager
	Closer
	Parser
	Stringer
	TxAdder
}

type Socket struct {
	socket             int
	pid                uint32
	tx_sequence_number uint
	tx_buffer          elib.ByteVec
	rx_buffer          elib.ByteVec
	rx_chan            chan Message
	quit_chan          chan struct{}
	sync.Mutex
	rsvp map[uint32]chan *ErrorMessage
}

func (n *Socket) reset_tx_buffer() {
	if len(n.tx_buffer) != 0 {
		n.tx_buffer = n.tx_buffer[:0]
	}
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

func NewNoopMessageBytes(b []byte) *NoopMessage {
	m := pool.NoopMessage.Get().(*NoopMessage)
	m.Parse(b)
	return m
}

func (m *NoopMessage) netlinkMessage() {}
func (m *NoopMessage) Close() error {
	pool.NoopMessage.Put(m)
	return nil
}
func (m *NoopMessage) Parse(b []byte) {
	*m = *(*NoopMessage)(unsafe.Pointer(&b[0]))
}
func (m *NoopMessage) String() string {
	return m.Header.String()
}
func (m *NoopMessage) TxAdd(s *Socket) {
	m.Header.Type = NLMSG_NOOP
	s.TxAddReq(&m.Header, 0)
}

type DoneMessage struct {
	Header Header
}

func NewDoneMessageBytes(b []byte) *DoneMessage {
	m := pool.DoneMessage.Get().(*DoneMessage)
	m.Parse(b)
	return m
}

func (m *DoneMessage) netlinkMessage() {}
func (m *DoneMessage) Close() error {
	pool.DoneMessage.Put(m)
	return nil
}
func (m *DoneMessage) String() string {
	return m.Header.String()
}
func (m *DoneMessage) Parse(b []byte) {
	*m = *(*DoneMessage)(unsafe.Pointer(&b[0]))
}
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

func NewErrorMessageBytes(b []byte) *ErrorMessage {
	m := pool.ErrorMessage.Get().(*ErrorMessage)
	m.Parse(b)
	return m
}

func (m *ErrorMessage) netlinkMessage() {}
func (m *ErrorMessage) Close() error {
	pool.ErrorMessage.Put(m)
	return nil
}
func (m *ErrorMessage) Parse(b []byte) {
	*m = *(*ErrorMessage)(unsafe.Pointer(&b[0]))
}
func (m *ErrorMessage) String() string {
	s := m.Header.String()
	s += fmt.Sprintf(": %s, failed header: %s", syscall.Errno(-m.Errno),
		m.Req.String())
	return s
}
func (m *ErrorMessage) TxAdd(s *Socket) {
	m.Header.Type = NLMSG_ERROR
	b := s.TxAddReq(&m.Header, 4+SizeofHeader)
	e := (*ErrorMessage)(unsafe.Pointer(&b[0]))
	e.Errno = m.Errno
	e.Req = m.Req
}

func freeAttrs(attrs []Attr) {
	for i, a := range attrs {
		if a != nil {
			if method, found := a.(Closer); found {
				method.Close()
			}
			attrs[i] = nil
		}
	}
}

type StringAttr string

func StringAttrBytes(b []byte) StringAttr {
	return StringAttr(string(b))
}
func (a StringAttr) attr() {}
func (a StringAttr) Size() int {
	return len(a) + 1
}
func (a StringAttr) Set(v []byte) {
	copy(v, a)
	v = append(v, 0)
}
func (a StringAttr) String() string {
	return string(a)
}

type Uint8Attr uint8

func (a Uint8Attr) attr() {}
func (a Uint8Attr) Rune() rune {
	return rune(a)
}
func (a Uint8Attr) Set(v []byte) {
	v[0] = byte(a)
}
func (a Uint8Attr) Size() int {
	return 1
}
func (a Uint8Attr) String() string {
	return strconv.FormatUint(uint64(a), 10)
}
func (a Uint8Attr) Uint() uint8 {
	return uint8(a)
}

type Uint32Attr uint32

func Uint32AttrBytes(b []byte) Uint32Attr {
	return Uint32Attr(*(*uint32)(unsafe.Pointer(&b[0])))
}

func (a Uint32Attr) attr() {}
func (a Uint32Attr) Set(v []byte) {
	*(*Uint32Attr)(unsafe.Pointer(&v[0])) = a
}
func (a Uint32Attr) Size() int {
	return 4
}
func (a Uint32Attr) String() string {
	return strconv.FormatUint(uint64(a), 10)
}
func (a Uint32Attr) Uint() uint32 {
	return uint32(a)
}

type Uint64Attr uint64

func Uint64AttrBytes(b []byte) Uint64Attr {
	return Uint64Attr(*(*uint64)(unsafe.Pointer(&b[0])))
}

func (a Uint64Attr) attr() {}
func (a Uint64Attr) Set(v []byte) {
	*(*Uint64Attr)(unsafe.Pointer(&v[0])) = a
}
func (a Uint64Attr) Size() int {
	return 8
}
func (a Uint64Attr) String() string {
	return strconv.FormatUint(uint64(a), 10)
}
func (a Uint64Attr) Uint() uint64 {
	return uint64(a)
}

type HexStringAttr bytes.Buffer

func NewHexStringAttrBytes(b []byte) *HexStringAttr {
	h := (*HexStringAttr)(pool.Bytes.Get().(*bytes.Buffer))
	h.Parse(b)
	return h
}

func (a *HexStringAttr) attr() {}
func (a *HexStringAttr) Buffer() *bytes.Buffer {
	return (*bytes.Buffer)(a)
}
func (a *HexStringAttr) Close() error {
	buf := a.Buffer()
	buf.Reset()
	pool.Bytes.Put(buf)
	return nil
}
func (a *HexStringAttr) Parse(b []byte) {
	a.Buffer().Write(b)
}
func (a *HexStringAttr) Set(v []byte) {
	copy(v, a.Buffer().Bytes())
}
func (a *HexStringAttr) Size() int {
	return a.Buffer().Len()
}
func (a *HexStringAttr) String() string {
	return hex.EncodeToString(a.Buffer().Bytes())
}

//go:generate go build github.com/platinasystems/elib/gentemplate
//go:generate ./gentemplate -d Package=netlink -id Attr -d VecType=AttrVec -d Type=Attr github.com/platinasystems/elib/vec.tmpl

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

func (a *AttrArray) attr() {}
func (a *AttrArray) Close() error {
	for i, x := range a.X {
		if x != nil {
			if method, found := x.(Closer); found {
				method.Close()
			}
			a.X[i] = nil
		}
	}
	if method, found := a.Type.(Closer); found {
		method.Close()
	}
	pool.AttrArray.Put(a)
	return nil
}
func (a *AttrArray) Set(v []byte) {
	a.X.Set(v)
}
func (a *AttrArray) Size() int {
	return a.X.Size()
}
func (a *AttrArray) String() string {
	s := ""
	for i := range a.X {
		if a.X[i] != nil {
			if len(s) > 0 {
				s += ", "
			}
			s += fmt.Sprintf("%s: %s",
				a.Type.IthString(i), a.X[i].String())
		}
	}
	return s
}

type LinkStats [N_link_stat]uint32

func NewLinkStatsBytes(b []byte) *LinkStats {
	a := pool.LinkStats.Get().(*LinkStats)
	a.Parse(b)
	return a
}

func (a *LinkStats) attr() {}
func (a *LinkStats) Close() error {
	pool.LinkStats.Put(a)
	return nil
}
func (a *LinkStats) Parse(b []byte) {
	*a = *(*LinkStats)(unsafe.Pointer(&b[0]))
}
func (a *LinkStats) Set(v []byte) {
	*(*LinkStats)(unsafe.Pointer(&v[0])) = *a
}
func (a *LinkStats) Size() int {
	return int(N_link_stat) * 4
}
func (a *LinkStats) String() string {
	s := ""
	for i := range a {
		t := LinkStatType(i)
		if a[t] != 0 || t == Rx_packets || t == Tx_packets {
			if len(s) > 0 {
				s += ", "
			}
			s += fmt.Sprintf("%s: %d", t, a[t])
		}
	}
	return s
}

type LinkStats64 [N_link_stat]uint64

func NewLinkStats64Bytes(b []byte) *LinkStats64 {
	a := pool.LinkStats64.Get().(*LinkStats64)
	a.Parse(b)
	return a
}

func (a *LinkStats64) attr() {}
func (a *LinkStats64) Close() error {
	pool.LinkStats64.Put(a)
	return nil
}
func (a *LinkStats64) Parse(b []byte) {
	*a = *(*LinkStats64)(unsafe.Pointer(&b[0]))
}
func (a *LinkStats64) Set(v []byte) {
	*(*LinkStats64)(unsafe.Pointer(&v[0])) = *a
}
func (a *LinkStats64) Size() int {
	return int(N_link_stat) * 8
}
func (a *LinkStats64) String() string {
	s := ""
	for i := range a {
		t := LinkStatType(i)
		if a[t] != 0 || t == Rx_packets || t == Tx_packets {
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

func NewIfInfoMessageBytes(b []byte) *IfInfoMessage {
	m := pool.IfInfoMessage.Get().(*IfInfoMessage)
	m.Parse(b)
	return m
}

const attrFormat = "\n  %-16s %s"

func (m *IfInfoMessage) netlinkMessage() {}

func (m *IfInfoMessage) Close() error {
	freeAttrs(m.Attrs[:])
	pool.IfInfoMessage.Put(m)
	return nil
}

func (m *IfInfoMessage) Parse(b []byte) {
	p := (*IfInfoMessage)(unsafe.Pointer(&b[0]))
	m.Header = p.Header
	m.IfInfomsg = p.IfInfomsg
	b = b[SizeofHeader+SizeofIfInfomsg:]
	for i := 0; i < len(b); {
		n, v, next_i := nextAttr(b, i)
		i = next_i
		switch t := IfInfoAttrKind(n.Kind); t {
		case IFLA_IFNAME, IFLA_QDISC:
			m.Attrs[n.Kind] = StringAttrBytes(v[:len(v)-1])
		case IFLA_MTU, IFLA_LINK, IFLA_MASTER,
			IFLA_WEIGHT,
			IFLA_NET_NS_PID, IFLA_NET_NS_FD, IFLA_LINK_NETNSID,
			IFLA_EXT_MASK, IFLA_PROMISCUITY,
			IFLA_NUM_TX_QUEUES, IFLA_NUM_RX_QUEUES, IFLA_TXQLEN,
			IFLA_GSO_MAX_SEGS, IFLA_GSO_MAX_SIZE,
			IFLA_CARRIER_CHANGES,
			IFLA_GROUP:
			m.Attrs[n.Kind] = Uint32AttrBytes(v)
		case IFLA_CARRIER, IFLA_LINKMODE, IFLA_PROTO_DOWN:
			m.Attrs[n.Kind] = Uint8Attr(v[0])
		case IFLA_OPERSTATE:
			m.Attrs[n.Kind] = IfOperState(v[0])
		case IFLA_STATS:
			m.Attrs[n.Kind] = NewLinkStatsBytes(v)
		case IFLA_STATS64:
			m.Attrs[n.Kind] = NewLinkStats64Bytes(v)
		case IFLA_AF_SPEC:
			m.Attrs[n.Kind] = parse_af_spec(v)
		case IFLA_ADDRESS, IFLA_BROADCAST:
			m.Attrs[n.Kind] = afAddr(AF_UNSPEC, v)
		default:
			if t < IFLA_MAX {
				m.Attrs[n.Kind] = NewHexStringAttrBytes(v)
			} else {
				panic(fmt.Errorf("%#v: unknown attr", n.Kind))
			}
		}
	}
}

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

func (m *IfInfoMessage) TxAdd(s *Socket) {
	as := AttrVec(m.Attrs[:])
	l := as.Size()
	b := s.TxAddReq(&m.Header, SizeofIfInfomsg+l)
	i := (*IfInfoMessage)(unsafe.Pointer(&b[0]))
	i.IfInfomsg = m.IfInfomsg
	as.Set(b[SizeofHeader+SizeofIfInfomsg:])
}

type Ip4DevConf [IPV4_DEVCONF_MAX]uint32

func NewIp4DevConfBytes(b []byte) *Ip4DevConf {
	a := pool.Ip4DevConf.Get().(*Ip4DevConf)
	a.Parse(b)
	return a
}

func (a *Ip4DevConf) attr() {}
func (a *Ip4DevConf) Close() error {
	pool.Ip4DevConf.Put(a)
	return nil
}
func (a *Ip4DevConf) Parse(b []byte) {
	*a = *(*Ip4DevConf)(unsafe.Pointer(&b[0]))
}
func (a *Ip4DevConf) Set(v []byte) {
	panic("not implemented")
}
func (a *Ip4DevConf) Size() int {
	panic("not implemented")
	return 0
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
	as := pool.AttrArray.Get().(*AttrArray)
	as.Type = NewIp4IfAttrType()
	for i := 0; i < len(b); {
		n, v, next_i := nextAttr(b, i)
		i = next_i
		t := Ip4IfAttrKind(n.Kind)
		as.X.Validate(uint(t))
		switch t {
		case IFLA_INET_CONF:
			as.X[t] = NewIp4DevConfBytes(v)
		default:
			as.X[t] = NewHexStringAttrBytes(v)
		}
	}
	return as
}

type Ip6DevConf [IPV6_DEVCONF_MAX]uint32

func NewIp6DevConfBytes(b []byte) *Ip6DevConf {
	a := pool.Ip6DevConf.Get().(*Ip6DevConf)
	a.Parse(b)
	return a
}

func (a *Ip6DevConf) attr() {}
func (a *Ip6DevConf) Close() error {
	pool.Ip6DevConf.Put(a)
	return nil
}
func (a *Ip6DevConf) Parse(b []byte) {
	*a = *(*Ip6DevConf)(unsafe.Pointer(&b[0]))
}
func (a *Ip6DevConf) Set(v []byte) {
	panic("not implemented")
}
func (a *Ip6DevConf) Size() int {
	panic("not implemented")
	return 0
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
	as := pool.AttrArray.Get().(*AttrArray)
	as.Type = NewIp6IfAttrType()
	for i := 0; i < len(b); {
		n, v, next_i := nextAttr(b, i)
		i = next_i
		t := Ip6IfAttrKind(n.Kind)
		as.X.Validate(uint(t))
		switch t {
		case IFLA_INET6_CONF:
			as.X[t] = NewIp6DevConfBytes(v)
		default:
			as.X[t] = NewHexStringAttrBytes(v)
		}
	}
	return as
}

func parse_af_spec(b []byte) *AttrArray {
	as := pool.AttrArray.Get().(*AttrArray)
	as.Type = NewAddressFamilyAttrType()
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

func NewIfAddrMessageBytes(b []byte) *IfAddrMessage {
	m := pool.IfAddrMessage.Get().(*IfAddrMessage)
	m.Parse(b)
	return m
}

func (m *IfAddrMessage) netlinkMessage() {}

func (m *IfAddrMessage) Close() error {
	freeAttrs(m.Attrs[:])
	pool.IfAddrMessage.Put(m)
	return nil
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
			m.Attrs[n.Kind] = StringAttrBytes(v[:len(v)-1])
		case IFA_FLAGS:
			m.Attrs[n.Kind] = IfAddrFlagAttrBytes(v)
		case IFA_CACHEINFO:
			m.Attrs[n.Kind] = NewIfAddrCacheInfoBytes(v)
		case IFA_ADDRESS, IFA_BROADCAST, IFA_LOCAL:
			m.Attrs[n.Kind] = afAddr(AddressFamily(m.Family), v)
		default:
			m.Attrs[n.Kind] = NewHexStringAttrBytes(v)
		}
	}
	return
}

func (m *IfAddrMessage) String() string {
	s := m.Header.String()
	s += fmt.Sprintf("\nIndex: %d, Family: %s, Prefix Len %d, Flags: %s, Scope: %s", m.Index,
		AddressFamily(m.Family),
		m.Prefixlen, IfAddrFlags(m.Header.Flags), RtScope(m.Scope))
	for i := range m.Attrs {
		if m.Attrs[i] != nil {
			s += fmt.Sprintf(attrFormat, IfAddrAttrKind(i), m.Attrs[i])
		}
	}
	return s
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

func IfAddrFlagAttrBytes(b []byte) IfAddrFlagAttr {
	return *(*IfAddrFlagAttr)(unsafe.Pointer(&b[0]))
}

func (a IfAddrFlagAttr) attr() {}
func (a IfAddrFlagAttr) Size() int {
	return 4
}
func (a IfAddrFlagAttr) Set(v []byte) {
	*(*IfAddrFlagAttr)(unsafe.Pointer(&v[0])) = a
}
func (a IfAddrFlagAttr) String() string {
	return IfAddrFlags(a).String()
}

type RouteMessage struct {
	Header Header
	Rtmsg
	Attrs [RTA_MAX]Attr
}

func NewRouteMessageBytes(b []byte) *RouteMessage {
	m := pool.RouteMessage.Get().(*RouteMessage)
	m.Parse(b)
	return m
}

func (m *RouteMessage) netlinkMessage() {}

func (m *RouteMessage) Close() error {
	freeAttrs(m.Attrs[:])
	pool.RouteMessage.Put(m)
	return nil
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
			m.Attrs[n.Kind] = Uint32AttrBytes(v)
		default:
			m.Attrs[n.Kind] = NewHexStringAttrBytes(v)
		}
	}
	return
}

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

func NewNeighborMessageBytes(b []byte) *NeighborMessage {
	m := pool.NeighborMessage.Get().(*NeighborMessage)
	m.Parse(b)
	return m
}

func (m *NeighborMessage) netlinkMessage() {}

func (m *NeighborMessage) AttrBytes(kind NeighborAttrKind) []byte {
	return m.Attrs[kind].(Byter).Bytes()
}

func (m *NeighborMessage) Close() error {
	freeAttrs(m.Attrs[:])
	pool.NeighborMessage.Put(m)
	return nil
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
		case NDA_CACHEINFO:
			m.Attrs[n.Kind] = NewNeighborCacheInfoBytes(v)
		case NDA_PROBES:
			m.Attrs[n.Kind] = Uint32AttrBytes(v)
		default:
			m.Attrs[n.Kind] = NewHexStringAttrBytes(v)
		}
	}
	return
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
	if header.Sequence == 0 {
		if s.tx_sequence_number == 0 {
			s.tx_sequence_number = 1
		}
		h.Sequence = uint32(s.tx_sequence_number)
		header.Sequence = uint32(s.tx_sequence_number)
		s.tx_sequence_number++
	}

	return s.tx_buffer[i:]
}

func (s *Socket) TxAdd(m Message) { m.TxAdd(s) }

func (s *Socket) Tx(m Message) {
	s.TxAdd(m)
	s.TxFlush()
}

func (s *Socket) Rsvp(m Message) chan *ErrorMessage {
	var hp *Header
	s.Lock()
	defer s.Unlock()
	ch := make(chan *ErrorMessage, 1)
	switch t := m.(type) {
	case *IfInfoMessage:
		hp = &t.Header
	case *IfAddrMessage:
		hp = &t.Header
	case *RouteMessage:
		hp = &t.Header
	case *NeighborMessage:
		hp = &t.Header
	default:
		panic("unsupported netlink message type")
	}
	s.TxAdd(m)
	if s.rsvp == nil {
		s.rsvp = make(map[uint32]chan *ErrorMessage)
	}
	s.rsvp[hp.Sequence] = ch
	s.TxFlush()
	return ch
}

func (s *Socket) TxFlush() {
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
func (m *GenMessage) Close() error {
	pool.GenMessage.Put(m)
	return nil
}
func (m *GenMessage) Parse(b []byte) {
	p := (*GenMessage)(unsafe.Pointer(&b[0]))
	m.Header = p.Header
	m.AddressFamily = p.AddressFamily
}
func (m *GenMessage) String() string {
	return m.Header.String() + " " + m.AddressFamily.String()

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
	var errMsg *ErrorMessage
	switch h.Type {
	case NLMSG_NOOP:
		m = NewNoopMessageBytes(msg)
	case NLMSG_ERROR:
		errMsg = NewErrorMessageBytes(msg)
		m = errMsg
	case NLMSG_DONE:
		m = NewDoneMessageBytes(msg)
	case RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK, RTM_SETLINK:
		m = NewIfInfoMessageBytes(msg)
	case RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR:
		m = NewIfAddrMessageBytes(msg)
	case RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE:
		m = NewRouteMessageBytes(msg)
	case RTM_NEWNEIGH, RTM_DELNEIGH, RTM_GETNEIGH:
		m = NewNeighborMessageBytes(msg)
	default:
		panic("unhandled message " + h.Type.String())
	}
	if errMsg != nil && errMsg.Req.Pid == s.pid {
		s.Lock()
		defer s.Unlock()
		if s.rsvp != nil {
			ch, found := s.rsvp[errMsg.Req.Sequence]
			if found {
				ch <- errMsg
				close(ch)
				delete(s.rsvp, errMsg.Req.Sequence)
				return
			}
		}
	}
	if s.rx_chan != nil {
		s.rx_chan <- m
	}
}

func (s *Socket) Rx() (Message, error) {
	if s.rx_chan != nil {
		if msg, opened := <-s.rx_chan; opened {
			return msg, nil
		}
	}
	return nil, io.EOF
}

func (s *Socket) rx() (done bool) {
	s.fillRxBuffer()
	i := 0
	for {
		q := len(s.rx_buffer)
		// Have at least a valid message header in buffer?
		if i+SizeofHeader > q {
			s.rx_buffer = s.rx_buffer[:q-i]
			break
		}
		// Have a full message in recieve buffer?
		h := (*Header)(unsafe.Pointer(&s.rx_buffer[i]))
		l := messageAlignLen(int(h.Len))
		if i+l > q {
			if i == len(s.rx_buffer) {
				s.rx_buffer = s.rx_buffer[:0]
			} else {
				copy(s.rx_buffer, s.rx_buffer[i:])
				s.rx_buffer = s.rx_buffer[:q-i]
			}
			break
		}

		done = h.Type == NLMSG_DONE
		s.rxDispatch(h, s.rx_buffer[i:i+int(h.Len)])
		i += l
	}
	return
}

func (s *Socket) rxUntilDone() {
	for !s.rx() {
	}
}

var DefaultGroups = []MulticastGroup{
	RTNLGRP_LINK,
	RTNLGRP_NEIGH,
	RTNLGRP_IPV4_IFADDR,
	RTNLGRP_IPV4_ROUTE,
	RTNLGRP_IPV4_MROUTE,
	RTNLGRP_IPV6_IFADDR,
	RTNLGRP_IPV6_ROUTE,
	RTNLGRP_IPV6_MROUTE,
}

func New(rx chan Message, groups ...MulticastGroup) (s *Socket, err error) {
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

	var groupbits uint32
	if len(groups) == 0 {
		groups = DefaultGroups
	}
	for _, group := range groups {
		if group != NOOP_RTNLGRP {
			groupbits |= 1 << group
		}
	}

	sa := &syscall.SockaddrNetlink{
		Family: uint16(AF_NETLINK),
		Pid:    s.pid,
		Groups: groupbits,
	}

	if err = syscall.Bind(s.socket, sa); err != nil {
		err = os.NewSyscallError("bind", err)
		return
	}

	// Increase socket buffering.
	bytes := 1024 << 10
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
	s.Lock()
	defer s.Unlock()
	for k, ch := range s.rsvp {
		close(ch)
		delete(s.rsvp, k)
	}
	s.rsvp = nil
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

var NoopListenReq = ListenReq{NLMSG_NOOP, AF_UNSPEC}

func (s *Socket) Listen(reqs ...ListenReq) {
	if len(reqs) == 0 {
		reqs = DefaultListenReqs
	}
	for _, r := range reqs {
		if r.MsgType == NLMSG_NOOP {
			continue
		}
		m := pool.GenMessage.Get().(*GenMessage)
		m.Type = r.MsgType
		m.Flags = NLM_F_DUMP
		m.AddressFamily = r.AddressFamily
		s.Tx(m)
		s.rxUntilDone()
	}

	for {
		select {
		case _ = <-s.quit_chan:
			syscall.Close(s.socket)
			s.socket = -1
			close(s.rx_chan)
			s.rx_chan = nil
			s.quit_chan = nil
			return
		default:
		}
		s.rx()
	}
}
