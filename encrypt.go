package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)



//  Encrypt RSA加密
func Encrypt(plainText []byte, publicPEM []byte) ([]byte, error) {
	// pem解码
	block, rest := pem.Decode(publicPEM)
	if block == nil {
		return nil, fmt.Errorf("加密失败：%+v", rest)
	}
	// x509解码
	
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("加密失败：%+v", err)
	}
	// 类型断言
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	// 对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		return nil, fmt.Errorf("加密失败：%+v", err)
	}
	// 返回密文
	return cipherText, nil
}

// EncryptPadding 分段加密
func EncryptPadding(plainText, publicPEM []byte) (res []byte, err error) {
	for from, cur, l := 0, enSegmentSize, len(plainText); from < l; {
		if cur > l {
			cur = l
		}
		buff := plainText[from:cur]
		_buff, err2 := Encrypt(buff, publicPEM)
		if err2 != nil {
			return res, err2
		}
		res = append(res, _buff...)
		from, cur = cur, cur+enSegmentSize
	}
	return
}
