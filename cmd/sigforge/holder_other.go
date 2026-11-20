//go:build !linux

package main

import "os"

// holderPID names no holder where the system has no list of file locks to read.
func holderPID(*os.File) string { return "" }
