// Copyright 2015-2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license described in the
// LICENSE file.

package main

import (
	"fmt"
	"github.com/platinasystems/netlink"
)

func main() {
	rx := make(chan netlink.Message, 64)
	s, err := netlink.New(rx)
	if err != nil {
		panic(err)
	}
	go s.Listen()
	for m := range rx {
		fmt.Printf("%v\n", m)
		m.Close()
	}
}
