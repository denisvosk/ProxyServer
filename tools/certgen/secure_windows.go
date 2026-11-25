//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// An explicit protected DACL grants inherited full control only to the current
// account and LocalSystem. No private key exists before this directory is made.
func makeSecureDirectory(path string) error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("open process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read account SID: %w", err)
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return fmt.Errorf("format account SID: %w", err)
	}
	sddl, err := syscall.UTF16PtrFromString("O:" + sid + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return err
	}
	convert := syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	var descriptor uintptr
	result, _, callErr := convert.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if result == 0 {
		return fmt.Errorf("create protected ACL: %w", callErr)
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	sa := syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
		InheritHandle:      0,
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return syscall.CreateDirectory(name, &sa)
}
