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
	for {
		m := <-rx
		fmt.Printf("%v\n", m)
	}
}
