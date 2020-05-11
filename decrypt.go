package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// 私匙解密

// RSA解密
func Decrypt(cipherText []byte, privatePEM []byte) ([]byte, error) {
	// pem解码
	block, rest := pem.Decode(privatePEM)
	if block == nil {
		return nil, fmt.Errorf("解密失败：%+v", rest)
	}
	// X509解码
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解密失败：%+v", err)
	}
	// 对密文进行解密
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err != nil {
		return nil, fmt.Errorf("解密失败：%+v", err)
	}
	// 返回明文
	return plainText, nil
}

// DecryptPadding 分段解密
func DecryptPadding(cipherText, privatePEM []byte) (res []byte, err error) {
	for from, cur, l := 0, deSegmentSize, len(cipherText); from < l; {
		if cur > l {
			cur = l
		}
		buff := cipherText[from:cur]
		_buff, err2 := Decrypt(buff, privatePEM)
		if err2 != nil {
			return res, err2
		}
		res = append(res, _buff...)
		from, cur = cur, cur+deSegmentSize
	}
	return
}
