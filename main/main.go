package main

import (
	"netlink"
)

func main() {
	n, err := netlink.New()
	if err != nil {
		panic(err)
	}
	for {
		n.Rx()
	}
}
