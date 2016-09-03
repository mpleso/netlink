// Copyright 2015-2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license described in the
// LICENSE file.

package netlink

import (
	"bytes"
	"sync"
)

var pool = struct {
	Empty           sync.Pool
	DoneMessage     sync.Pool
	ErrorMessage    sync.Pool
	GenMessage      sync.Pool
	IfAddrMessage   sync.Pool
	IfInfoMessage   sync.Pool
	NeighborMessage sync.Pool
	NoopMessage     sync.Pool
	RouteMessage    sync.Pool
	AttrArray       sync.Pool
	LinkStats       sync.Pool
	LinkStats64     sync.Pool
	Ip4Address      sync.Pool
	Ip6Address      sync.Pool
	EthernetAddress sync.Pool
	Ip4DevConf      sync.Pool
	Ip6DevConf      sync.Pool
	IfAddrCacheInfo sync.Pool
	RtaCacheInfo    sync.Pool
	NdaCacheInfo    sync.Pool
	Bytes           sync.Pool
}{
	Empty: sync.Pool{
		New: func() interface{} {
			return new(Empty)
		},
	},
	DoneMessage: sync.Pool{
		New: func() interface{} {
			return new(DoneMessage)
		},
	},
	ErrorMessage: sync.Pool{
		New: func() interface{} {
			return new(ErrorMessage)
		},
	},
	GenMessage: sync.Pool{
		New: func() interface{} {
			return new(GenMessage)
		},
	},
	IfAddrMessage: sync.Pool{
		New: func() interface{} {
			return new(IfAddrMessage)
		},
	},
	IfInfoMessage: sync.Pool{
		New: func() interface{} {
			return new(IfInfoMessage)
		},
	},
	NeighborMessage: sync.Pool{
		New: func() interface{} {
			return new(NeighborMessage)
		},
	},
	NoopMessage: sync.Pool{
		New: func() interface{} {
			return new(NoopMessage)
		},
	},
	RouteMessage: sync.Pool{
		New: func() interface{} {
			return new(RouteMessage)
		},
	},
	AttrArray: sync.Pool{
		New: func() interface{} {
			return new(AttrArray)
		},
	},
	LinkStats: sync.Pool{
		New: func() interface{} {
			return new(LinkStats)
		},
	},
	LinkStats64: sync.Pool{
		New: func() interface{} {
			return new(LinkStats64)
		},
	},
	Ip4Address: sync.Pool{
		New: func() interface{} {
			return new(Ip4Address)
		},
	},
	Ip6Address: sync.Pool{
		New: func() interface{} {
			return new(Ip6Address)
		},
	},
	EthernetAddress: sync.Pool{
		New: func() interface{} {
			return new(EthernetAddress)
		},
	},
	Ip4DevConf: sync.Pool{
		New: func() interface{} {
			return new(Ip4DevConf)
		},
	},
	Ip6DevConf: sync.Pool{
		New: func() interface{} {
			return new(Ip6DevConf)
		},
	},
	IfAddrCacheInfo: sync.Pool{
		New: func() interface{} {
			return new(IfAddrCacheInfo)
		},
	},
	RtaCacheInfo: sync.Pool{
		New: func() interface{} {
			return new(RtaCacheInfo)
		},
	},
	NdaCacheInfo: sync.Pool{
		New: func() interface{} {
			return new(NdaCacheInfo)
		},
	},
	Bytes: sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	},
}
