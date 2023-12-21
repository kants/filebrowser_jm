//go:build unix
// +build unix

package util

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func GetDiskCode() (string, error) {
	// 获取根目录的文件信息
	fileInfo, err := os.Stat("/")
	if err != nil {
		fmt.Println("无法获取根目录的文件信息：", err)
		return "", err
	}

	// 转换为系统相关的文件信息
	sysInfo := fileInfo.Sys().(*syscall.Stat_t)

	// 获取磁盘唯一ID
	diskID := sysInfo.Dev

	// fmt.Printf("磁盘唯一ID：%d\n", diskID)
	return strconv.FormatUint(diskID, 10), nil
}
