package main

import (
	"crypto"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"

	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/labstack/echo/v4"
)

const (
	PrivateKey = "./keys/private_key.pem"
	PublicKey  = "./keys/public_key.pem"
)

type ResponseBody struct {
	Msg       Message `json:"msg"`
	Signature []byte  `json:"signature"`
}

type Message struct {
	NumberOfGPUs int       `json:"no_of_gpus"`
	GPUInfo      []GPUInfo `json:"gpu_info"`
}

type GPUInfo struct {
	ID      string `json:"id"`
	GPUType string `json:"gpu_type"`
}

func main() {
	e := echo.New()
	e.POST("/", func(c echo.Context) error {
		ret := nvml.Init()
		if ret != nvml.SUCCESS {
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Unable to initialize NVML: %v", nvml.ErrorString(ret)))
		}
		defer func() {
			ret := nvml.Shutdown()
			if ret != nvml.SUCCESS {
				log.Fatalf("Unable to shutdown NVML: %v", nvml.ErrorString(ret))
			}
		}()

		count, ret := nvml.DeviceGetCount()
		if ret != nvml.SUCCESS {
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Unable to get device count: %v", nvml.ErrorString(ret)))
		}

		gpuInfo := []GPUInfo{}
		for i := 0; i < count; i++ {
			info := GPUInfo{}
			device, ret := nvml.DeviceGetHandleByIndex(i)
			if ret != nvml.SUCCESS {
				return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Unable to get device at index %d: %v", i, nvml.ErrorString(ret)))
				log.Fatalf("Unable to get device at index %d: %v", i, nvml.ErrorString(ret))
			}

			arch, ret := device.GetName()
			device.GetConfComputeGpuAttestationReport()
			if ret != nvml.SUCCESS {
				return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Unable to get arch of device at index %d: %v", i, nvml.ErrorString(ret)))
				log.Fatalf("Unable to get arch of device at index %d: %v", i, nvml.ErrorString(ret))
			}
			info.GPUType = arch

			uuid, ret := device.GetUUID()
			if ret != nvml.SUCCESS {
				return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Unable to get uuid of device at index %d: %v", i, nvml.ErrorString(ret)))
				log.Fatalf("Unable to get uuid of device at index %d: %v", i, nvml.ErrorString(ret))
			}
			info.ID = uuid

			gpuInfo = append(gpuInfo, info)
		}

		data := Message{
			NumberOfGPUs: count,
			GPUInfo:      gpuInfo,
		}

		jsonData, err := json.Marshal(data)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Error converting to JSON: %v", err.Error()))
		}

		privKey, err := loadPrivateKey(PrivateKey)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Error generating private key: %v", err.Error()))
		}

		publicKey, err := loadPublicKey(PublicKey)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Error generating public key: %v", err.Error()))
		}

		signature, err := sign(jsonData, privKey)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Error generating signature: %v", err.Error()))
		}

		if err = verify(jsonData, signature, publicKey); err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}

		resp := ResponseBody{
			Msg: Message{
				NumberOfGPUs: count,
				GPUInfo:      gpuInfo,
			},
			Signature: signature,
		}

		return c.JSON(http.StatusOK, resp)
	})
	e.Logger.Fatal(e.Start(":8000"))
}

func sign(msg []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(msg)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("sign data: %v", err)
	}
	return signature, nil
}

func verify(msg []byte, signature []byte, publicKey *rsa.PublicKey) error {
	hashed := sha256.Sum256(msg)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); err != nil {
		return fmt.Errorf("verify signature: %v", err)
	}
	return nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyData := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDpV7dCamvCP8a4
a7eqOxy40kRSC1Nt8u7oEm1UyMXjJvo0cC1Ejpeb0qDPgxyHGK/uVbFZy1vGr2IT
g9zDSTLEq8NqQ2p94SGP2ezRr1CqxE0uqmqwA0TMq6wzmmk62yMdDDXEJlp3mQv4
Q6q+ONsjCYBeMS8Vjd/jFu1UYSgttex9OzIgGhHLQyGhBX0//2ceuAXXIBUZ1Vid
UEqctRG7DUaaQCkj4+YKv/7jLA5XSdx70E5+pSAwy8478fUwg57MTUfwYDJeEWEm
sG5WDM3AaHAoc3M8FWzHKtKpP5gW+wXKw+b2FEI6hNmvVVofnRePp5fZUud0ynfl
DrK3Jj3RAgMBAAECggEAFp5Lq6bObXi6YeHCHsCGXRV3rSa/Jm0aEpmHqsRf5y/9
6JOXlbnHMSHqd9bvDtraId2BWJGFYsXZGUhqv6zCnK0EHxKsGcnW859VjPFEHdtz
mlKHTyqv8nFxGprs+Jkphw0qEIqBsi5eCkl/3Vq8RiILhQXaOSoEkdoE9Q0KZJy6
jtmdq4DnYozQ5BSgXT4pqKiilg8M+TVXKaG1X8hBpE8HhsJAjJwLH0sGKgkjO46U
AS7SwJbYtF3uHsSOE0ZMXKWKteBmxc1BgrMamkWrQtauLCye0uRQ3hXuOWp1CT2j
5jJi67mwF23vQRcovNWKNlklOoCdlVfhEBRe+f/RCQKBgQD06fHuM0DsUuOX5Hr4
b/GMwhRLjh/v8dSaTpzhfeg3V9vhFjmY9FGpqhpU7Et683P9XVdjgzb9nC0oslkP
BRDM4H5QGxf6kMxIMp/rELLykgU9XzH5Rx7SPO/y+vHv7fIOoA1MxhICf9Q+Kmab
sh+faQx/OptE6JGtsNCX2nhOGQKBgQDz568ZLIgcaPS+sAXRl15RShNMfBAltcJ6
RmJpKoBpBpXphXcUKxgpt0cM3n1ZuvpiZn9T8+KqelwlFrhK8pFI+X+oHxBUCvH/
9xZZULbZJAsTW/1/js/Bd5Cca0uJwd/UlRWSEWXZOc4F3EXHrnR0rK8ce5A299Hf
LQwG6NZ0eQKBgQC568rr796uSHJcAWfUp25wU3kCrl7SUPv7NAhmKaWaNclGgw+w
bHB94xLgOw1FxgDcavqHIboiJmglx9ZRz5+kWBurhhXa8gcSG9RIp0GhYXY208hl
GzdrlDT3eMcnQ7QIpDnUeVx8pzuhAaEpOrxE0INbJktusTq950dCr+e6KQKBgQDj
TYNtHocqktWj8D87+Kk5cKNToDscKau4cGe+QpGxTyXenzc+YHsARYG9iIuhWBOI
KKV5A8y1u5qsJeRSVIT5USua7ng1Go41UXxOeF4vNtvristQWTNcxaTLYWLgWwHS
B642lmgobSqHY6TUVszI/zWigbUAxSudpUmUFuHlYQKBgFc4YEZ81WzwK3wGBJqL
8W49Y03JjoQRlTgrJnrH9rZeUeQnHl4VIQoyWecyH1uw0U7WsSfVcwAEoriVXQ72
+jYGDkLKE5g5bnSav+qdO1ma7QB1TcyCMLdOxwdexqpM/kJj0Rkms6+xa+Y9YjLd
jhtO/eFXEESMvhDW2AewTuW9
-----END PRIVATE KEY-----
`)

	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return nil, fmt.Errorf("parse PEM block: key not found")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %v", err)
	}

	privKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("type assertion to rsa.PrivateKey failed")
	}
	return privKey, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	publicKeyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load public key: %v", err)
	}

	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		return nil, fmt.Errorf("parse PEM block: key not found")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("type assertion to rsa.PublicKey failed")
	}
	return rsaPub, nil
}

// openssl genpkey -algorithm RSA -out ./keys/private_key.pem
// openssl rsa -pubout -in ./keys/private_key.pem -out ./keys/public_key.pem
