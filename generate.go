package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// 公匙加密
const keySize = 2048                     //  密匙对长度
const deSegmentSize = keySize / 8        // 解密分段
const enSegmentSize = deSegmentSize - 11 // 加密分段

// GenerateRSAKeyPairs 生成RSA私钥和公钥
func GenerateRSAKeyPairs() (publicKey []byte, privateKey []byte, err error) {
	// GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	// Reader是一个全局、共享的密码用强随机数生成器
	_privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return
	}
	// 保存私钥
	// 通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(_privateKey)
	// 使用pem格式对x509输出的内容进行编码
	// 构建一个pem.Block结构体对象
	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}
	// 获取公钥的数据
	_publicKey := _privateKey.PublicKey
	// X509对公钥编码
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&_publicKey)
	if err != nil {
		panic(err)
	}
	// 创建一个pem.Block结构体对象
	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}
	return pem.EncodeToMemory(&publicBlock), pem.EncodeToMemory(&privateBlock), nil
}
