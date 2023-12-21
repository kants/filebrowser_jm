//go:build !unix
// +build !unix

package util

import (
	"fmt"
	"strconv"
	"syscall"
	"unsafe"
)

var (
	modkernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGetVolumeInformation = modkernel32.NewProc("GetVolumeInformationW")
)

func GetDiskCode() (string, error) {
	volumeName := make([]uint16, 100)
	fileSystemName := make([]uint16, 100)
	var volumeSerialNumber uint32
	var maximumComponentLength uint32
	var fileSystemFlags uint32

	rootPath := syscall.StringToUTF16Ptr("C:\\") // 指定要获取信息的磁盘路径，这里以C盘为例

	ret, _, _ := procGetVolumeInformation.Call(
		uintptr(unsafe.Pointer(rootPath)),
		uintptr(unsafe.Pointer(&volumeName[0])),
		uintptr(len(volumeName)),
		uintptr(unsafe.Pointer(&volumeSerialNumber)),
		uintptr(unsafe.Pointer(&maximumComponentLength)),
		uintptr(unsafe.Pointer(&fileSystemFlags)),
		uintptr(unsafe.Pointer(&fileSystemName[0])),
		uintptr(len(fileSystemName)),
	)

	if ret == 0 {
		err := fmt.Errorf("获取磁盘信息失败")
		return "", err
	}

	// fmt.Printf("磁盘唯一ID（序列号）：%d\n", volumeSerialNumber)
	strSerialNum := strconv.FormatInt(int64(volumeSerialNumber), 10)
	return strSerialNum, nil
}
