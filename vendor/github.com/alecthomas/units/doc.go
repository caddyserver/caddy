// Package units provides helpful unit multipliers and functions for Go.
//
// The goal of this package is to have functionality similar to the time [1] package.
//
//
// [1] http://golang.org/pkg/time/
//
// It allows for code like this:
//
//     n, err := ParseBase2Bytes("1KB")
//     // n == 1024
//     n = units.Mebibyte * 512
package units
