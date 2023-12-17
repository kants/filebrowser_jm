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
	SvrPemCert = `
-----BEGIN CERTIFICATE-----
MIIE8DCCAtigAwIBAgIBATANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw8xNjku
MjY0LjE2OS4yNTQwIBcNMjMxMjE3MTUwNzE1WhgPMjEyMzEyMTcxNTA3MTVaMBox
GDAWBgNVBAMTDzE2OS4yNjQuMTY5LjI1NDCCAiIwDQYJKoZIhvcNAQEBBQADggIP
ADCCAgoCggIBAOL9O+QFqbwCP70TssD30bkZjTZw8yxxFRgzFWabuVGK0QKFP500
JmHN4nqTfEmDwwwrMMAkPTBfRNqOHSs5x3TS6gsbaQE/hzfKW4r5WFgI9SCn8zZt
Llr9cVTGFP67g6JaNmwVjYj/5qIBicrA8SPRecUjaIgdbbytLtkOFr7BM6IuFaqp
Q10If4zEh+juZx1D/3mFoYiRuPduVOY78qYHFrsZvURIb1d/32NpGIdA5hM4loxM
osdFbFHrwCbmTxs0yIgr2R5VO/DZIlKzzQ63lrzcgOX/OAP4MaAf4a/dxejJvQLp
UdPOKteeOCskjOgzFET0j6lVC8oMv4mY/uuRGQEJwjBLXy7u1/79RjIIv1ZJWbZ+
7BsW0sZxi1T1pCT9PKjb2j0KxoGXkMweUx111osUus/EPM93kgWVkbCUx+D3c20i
K8FgmMyNQWrOdNs1sglW/BYICGBpJ1FewkHoY3Cte/c6/FXuLEzVb2cCjQetuhbr
3HUo4feHTGATHyBvhajyAclAFaZ2RIUTtpTLD5ZNvBKp08MVIfUzRj6mbZbYFy52
xbredlJmaeNY1BpeFJYKMfNV7gxDh/Eskyf4U/YlPiMSC/LW4GqvLU4U/FCrDgF1
XtUK700DxE95bGDFbc3JwBeevg3ilmmrOaHkRYBkd+NSUpuNa6R7WMQ/AgMBAAGj
PzA9MA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH
AwEwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAIn9xz9oEnsQUfj+Z
TmuJfCEtSIOYYRuGYqS4JMxCsSPPlzuexFgVrjl3Rd5k8d3X/Ng14UmPOg+Yfq4o
bR0hTVu93nPLwmxAk9YLWiAlGYqkHcXKeeNddsN+1mKGchc5eg357M3mpAr7Reo3
rNupYU2oTQCpJAxLll61KMugXDGrmUWZrwhRpwa2mi7dgLuAp8qFEBVYejhYhjtA
GJRsEIUbny/v1g+OQOro0JgZzsJfxjmAJWcLGtOrZ+2sLgyeTbufF2QI1ZcRhk/O
xYafwuKDJSfifJT/zKQHMbtzQIYFasHyNqONNIwbTx5xMKSD0V/odEHj/2TQNXUh
skeBc/FlsKnH2jwHf9ay7OgdYm+ej4OCKemvbGKKMp+1tjlJGWYFPWk/zCp8VrCg
bGxvz0FD8haseATQIMPjUNlT+rgiG82xyldN8LohihihGvK6KSATm+/Q3R9mSwXw
xj6we61nL5FHbnh5eDoWMNMrHCWMc/fqpJdyoiTOLfz20py23vF9dOeFcQwJVPMB
Mh2BIEWu8vn1bPduc1C2e9L8WxCAYx1toamnJ8uVP/C9CNCWyR08ny8ffqeUDN39
bEyQY6yn6ZBaupY7rTwGr3W06Ir6Xud5JWk8xHbvliWB5FzxlLEca7Z2sxomHQkz
biz0Lp8Zl4ouN8n8XZ8A9xM3diY=
-----END CERTIFICATE-----
`
	SvrPemKey = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`
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
