package redir

import (
	"syscall"
	"unsafe"
)

const GETSOCKOPT = 15 // https://golang.org/src/syscall/syscall_linux_386.go#L183

func getsockopt(s int, level int, name int, val uintptr, vallen *uint32) (err error) {
	var a [6]uintptr
	a[0], a[1], a[2], a[3], a[4], a[5] = uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0
	if _, _, errno := syscall.Syscall6(syscall.SYS_SOCKETCALL, GETSOCKOPT, uintptr(unsafe.Pointer(&a)), 0, 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
