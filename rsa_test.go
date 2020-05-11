package rsa

import (
	"testing"
)

const tLongStr = "333333333333333333333333333333333333333333333333333####################################################################################33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"

func TestRsa(t *testing.T) {
	// 生成密钥对，保存到文件
	pub, pvt, err := GenerateRSAKeyPairs()
	if err != nil {
		t.Error(err)
	}
	tStr := "hello world你好，rsa"
	message := []byte(tStr)
	// 加密
	cipherText, err := Encrypt(message, pub)
	if err != nil {
		t.Error(err)
	}
	if tStr == string(cipherText) {
		t.Error("加密失败")
	}
	// 解密
	plainText, err := Decrypt(cipherText, pvt)
	if err != nil {
		t.Error(err)
	}
	if string(plainText) != tStr {
		t.Error("加解密失败")
	}
	longMsg := []byte(tLongStr)
	cipherTextLong, err := EncryptPadding(longMsg, pub)
	if err != nil {
		t.Error(err)
		return
	}
	if tLongStr == string(cipherTextLong) {
		t.Error("加密失败")
		return
	}
	// 解密
	plainTextLong, err := DecryptPadding(cipherTextLong, pvt)
	if err != nil {
		t.Error(err)
		return
	}
	if string(plainTextLong) != tLongStr {
		t.Error("加解密失败")
		return
	}
}
