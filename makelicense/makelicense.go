package makelicense

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"filebrowser/util"

	"github.com/pkg/errors"
)

const (
	privateKeyPath = "private_key.pem"
	publicKeyPath  = "public_key.pem"
)
const (
	privateKeyData = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEArgkiODZ/z/CR5qjHeACdvy2E2qG2iOYp8gKUTA/p1O4Ih0Sh
4sGDjSDuzu4XbypH5aeGYkKNDfyqgtrJC5I8cjQ/LUl5q9CrUAM/oHk9Wf53WfAp
vo3pfh4LbQTtSJ1Ld0yi3gTP2+1lgCAhqtTzK3F01pqL2bM9p4Qk6RlBO4PnRO2t
cENQ0tiNXiViQGEUDh4yp/f405MXm7qbBPNU9xwE+SWR1Em6OrGbwEbDtwfJfKQ7
+GzY/YiVh/eTHxz/1Qrn7PtkqEDHBspLnbhCTp1H9+42alwecrnVpJEy6vgrzUbK
AmRTQb5AaLVdihWNzWoZazwEIhs2BFQFZoiERwIDAQABAoIBAQCprY4HcFs8yTf2
wyd3AGLMOf0FjBUDdCQBKDKd1gYM6+a0u116T2GK/0jVx5xhbb+bULHcqzYLJQS5
f8Xz2ifE0Nuns7NEqLXd1Mz8EDiYvVhv/48zkfjMVU6eg+c0nOcu8TD5dYeSzOng
+XLZs7VB7eQUN6mSHwdFg7jY6x6Gfn98PsNpt7JYkD9rQ/SOB/U4PL8cUZSXtGyU
sLdJWfllqOrSRVNrfS5ew4vcKoKefoi6419TIZCDzvqob62SNNf8xereMz1/FyhE
6/Nu8i45vxukZZO29TnKweZFKjJ5kZt+RQAJiuFGFvqHbw4S8jShYNpfzgDYNHd6
zJVlnA5BAoGBAMcoJOeUAWFLl7Zk8U3qfqCRnD2m9HQcuSTrEFOLcDKjckQLE8Si
ZBzbRk7Lry9vZwIWlw1eJz0wTGzkBQAlq7NIIdPg8miPzMxkkp4yUXM072bZKmwE
v7tx56I0FlDDfD4E++j+XLDCnKExWL1XFfyrk1BZOXK3gA7uB6fVQbZNAoGBAN+1
dJLMqvQ9K6dEEEcpgaQLY1FfsV2CaPqy2wO1UP5dp3GnAm0A2tZ5RwoIJoEbzuer
XRxvYfXITQ5slZEjzkX5KKOXgFT3c+rhNwjy3P8RCSyWuxqjHXUc2hTlwbhPqTru
qChF+zgk1vAndSfV6v2+CfUjq1HVD9LTOqPRHlbjAoGBALqJV0ew0ToYW5lzIrEg
Gkq7F+SHJCA9Zwy1Py2BRS2o+bXRyko68Bo3J7tV/FgpuAm0rvbOYWJmgq7bQ/PH
VPMvdL/HykU1q1UmPk3+Q1vtEO78KUfTiuI+5f5/Wwd6kjxk3q500Mye+6XfWoa9
stJewjRX3f8c8M0LFhCVJl9hAoGBAILJiETG6W9vT9UzgrzH9GYezkrlwkEkHBHt
fQP2/kooINveQxnNNSPMtY6U40X6JwXkdsRIDiJunzY+n1bCczcPiwXRbhK+tQNt
9goCStfIcu+hk/PnxzIP0yQCizYhRJQSsTcSauQRDaRLvT+z3fXJI/MwjlmCUgT0
v0TE3pL3AoGBAKTXJkNZvmF5/LZwK/ANnmPQMcUVOS7bDMVcp4AoSga/7MEgSVbp
IXvonn9QvFNXOfNwRAiSk1KYcH5aG0ivuP6pKfuN/OMsOFv/GotC5v50o6BkHske
Csbvy6e2Hown/DudFf5L9u2eRWkNB5S8uAP9Wm672W8tJvx9w+NcJRet
-----END RSA PRIVATE KEY-----
`

	publicKeyData = `
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEArgkiODZ/z/CR5qjHeACdvy2E2qG2iOYp8gKUTA/p1O4Ih0Sh4sGD
jSDuzu4XbypH5aeGYkKNDfyqgtrJC5I8cjQ/LUl5q9CrUAM/oHk9Wf53WfApvo3p
fh4LbQTtSJ1Ld0yi3gTP2+1lgCAhqtTzK3F01pqL2bM9p4Qk6RlBO4PnRO2tcENQ
0tiNXiViQGEUDh4yp/f405MXm7qbBPNU9xwE+SWR1Em6OrGbwEbDtwfJfKQ7+GzY
/YiVh/eTHxz/1Qrn7PtkqEDHBspLnbhCTp1H9+42alwecrnVpJEy6vgrzUbKAmRT
Qb5AaLVdihWNzWoZazwEIhs2BFQFZoiERwIDAQAB
-----END RSA PUBLIC KEY-----
`
)

var (
	ExpiredDate = ""
)

func KeyPairWithPin() ([]byte, []byte, []byte, error) {
	bits := 4096
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "rsa.GenerateKey")
	}

	tpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "169.264.169.254"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "x509.CreateCertificate")
	}

	buf := &bytes.Buffer{}
	err = pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derCert,
	})
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "pem.Encode")
	}

	pemCert := buf.Bytes()

	buf = &bytes.Buffer{}
	err = pem.Encode(buf, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "pem.Encode")
	}
	pemKey := buf.Bytes()

	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "x509.ParseCertificate")
	}

	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey.(*rsa.PublicKey))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "x509.MarshalPKIXPublicKey")
	}
	sum := sha256.Sum256(pubDER)
	pin := make([]byte, base64.StdEncoding.EncodedLen(len(sum)))
	base64.StdEncoding.Encode(pin, sum[:])

	return pemCert, pemKey, pin, nil
}

func generateKeyPair() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}

	publicKey := privateKey.PublicKey

	publicKeyFile, err := os.Create(publicKeyPath)
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&publicKey),
	}

	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		return err
	}

	return nil
}

func loadPrivateKey() (*rsa.PrivateKey, error) {
	// 解码PEM格式的私钥
	block, _ := pem.Decode([]byte(privateKeyData))
	if block == nil {
		// 处理解码错误
		err := fmt.Errorf("Failed to decode PEM private key")
		return nil, err
	}

	// 解析DER编码的私钥
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// 处理解析错误
		err := fmt.Errorf("Failed to parse private key:", err)
		return nil, err
	}

	return key, nil
}

func loadPublicKey() (*rsa.PublicKey, error) {
	// 解码PEM格式的公钥
	block, _ := pem.Decode([]byte(publicKeyData))
	if block == nil {
		// 处理解码错误
		err := fmt.Errorf("Failed to decode PEM public key")
		return nil, err
	}

	// 解析DER编码的公钥
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		// 处理解析错误
		err := fmt.Errorf("Failed to parse public key:", err)
		return nil, err
	}

	return key, nil
}

// 获取mac
func getMac() []string {
	var macs []string

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Failed to retrieve network interfaces:", err)
		return macs
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println("无法获取地址列表：", err)
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				hwAddr := iface.HardwareAddr.String()
				macs = append(macs, hwAddr)
				break
			}
		}
	}

	return macs
}

// 验证证书 mac diskcode fileb checkt day
func ValidateLicense(licenseCode string) (bool, error) {
	license, err := base64.StdEncoding.DecodeString(licenseCode)
	if err != nil {
		err := fmt.Errorf("token not regular")
		return false, err
	}

	// 解密
	privateKey, err := loadPrivateKey()
	if err != nil {
		fmt.Println("Failed to load private key:", err)
		return false, err
	}

	ciphertext := []byte(license)

	// 解密密文
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		fmt.Println(err)
		return false, err
	}

	dtoken, err := base64.StdEncoding.DecodeString(string(plaintext))
	if err != nil {
		err := fmt.Errorf("token not regular")
		return false, err
	}

	strToken := string(dtoken)
	tokens := strings.Split(strToken, " ")
	if len(tokens) != 5 {
		err := fmt.Errorf("Invalid token")
		return false, err
	}

	// mac
	var bFindMac bool = false
	macs := getMac()
	for _, str := range macs {
		if tokens[0] == str {
			bFindMac = true
			break
		}
	}

	if !bFindMac {
		err := fmt.Errorf("Invalid devicem")
		return false, err
	}

	// diskcode
	diskCode, err := util.GetDiskCode()
	if err != nil {
		err := fmt.Errorf("can't read disk")
		return false, err
	}

	if tokens[1] != diskCode {
		err := fmt.Errorf("Invalid deviced")
		return false, err
	}

	// fileb
	if tokens[2] != "fileb" {
		err := fmt.Errorf("Invalid devicef")
		return false, err
	}

	// fileb checkt day
	if tokens[2] != "fileb" {
		err := fmt.Errorf("Invalid device")
		return false, err
	}

	t, err := strconv.Atoi(tokens[3])
	if err != nil {
		err := fmt.Errorf("Invalid time")
		return false, err
	}

	days, err := strconv.Atoi(tokens[4])
	if err != nil {
		err := fmt.Errorf("Invalid timed")
		return false, err
	}

	now := time.Now().Unix()
	expireTime := t + days*24*3600

	tm := time.Unix(int64(expireTime), 0)
	ExpiredDate = tm.Format("2006-01-02")

	if int64(expireTime) < now {
		err := fmt.Errorf("Invalid timee")
		return false, err
	}

	return true, nil
}

// mac diskcode fileb checkt day
func makeLicense(days int) (string, error) {
	macs := getMac()

	diskCode, err := util.GetDiskCode()
	if err != nil {
		err := fmt.Errorf("can't read disk")
		return "", err
	}

	now := time.Now().Unix()
	str := fmt.Sprintf("%s %s fileb %d %d", macs[0], diskCode, now, days)

	token := base64.StdEncoding.EncodeToString([]byte(str))

	// 加密
	publicKey, err := loadPublicKey()
	if err != nil {
		return "", err
	}

	license, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(token))
	if err != nil {
		err := fmt.Errorf("Failed to encrypt license:", err)
		return "", err
	}

	licenseCode := base64.StdEncoding.EncodeToString([]byte(license))
	return string(licenseCode), nil
}

func createLicenseFile() {
	// 加密数据
	license, err := makeLicense(10)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		os.Exit(1)
	}

	err = ioutil.WriteFile("LICENSE-FILE", []byte(license), 0644)
	if err != nil {
		fmt.Println("写入文件失败:", err)
		os.Exit(1)
	}

	fmt.Println("LISCENSE SUCCESS")
}
