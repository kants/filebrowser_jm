package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"filebrowser/cmd"
	"filebrowser/makelicense"
)

func main() {
	// testKey
	// testKey()
	// createLicenseFile();

	// 读取LICENSE文件
	license, err := ioutil.ReadFile("LICENSE-FILE")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// 校验数据
	_, err = makelicense.ValidateLicense(string(license))
	if err != nil {
		fmt.Println("validate failed:", err)
		os.Exit(1)
	}

	// time.Sleep(10 * time.Second)
	cmd.Execute()
}
