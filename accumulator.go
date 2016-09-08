// Copyright 2015-2016 Platina Systems, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license described in the
// LICENSE file.

package netlink

import (
	"fmt"
	"io"
)

// Accumulate Read, Write, and fmt.Fprint* return values
type Accumulator struct {
	N   int64
	Err error
}

func (acc *Accumulator) Accumulate(v interface{}, err error) {
	switch t := v.(type) {
	case int:
		acc.N += int64(t)
	case int64:
		acc.N += int64(t)
	default:
		panic(fmt.Errorf("can't accumulate %T", t))
	}
	if acc.Err == nil {
		acc.Err = err
	}
}

func (acc *Accumulator) Fprint(w io.Writer, args ...interface{}) {
	acc.Accumulate(fmt.Fprint(w, args...))
}

func (acc *Accumulator) Fprintf(w io.Writer, format string,
	args ...interface{}) {
	acc.Accumulate(fmt.Fprintf(w, format, args...))
}

func (acc *Accumulator) Fprintln(w io.Writer, args ...interface{}) {
	acc.Accumulate(fmt.Fprintln(w, args...))
}

func (acc *Accumulator) Reset() {
	*acc = Accumulator{}
}
