package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/labstack/echo/v4"
)

type ResponseBody struct {
	Msg       Message `json:"msg"`
	Signature []byte  `json:"signature"`
}

type Message struct {
	Nonce        string    `json:"nonce"`
	NumberOfGPUs int       `json:"no_of_gpus"`
	GPUInfo      []GPUInfo `json:"gpu_info"`
}

type GPUInfo struct {
	ID      string `json:"id"`
	GPUType string `json:"gpu_type"`
}

func main() {
	e := echo.New()
	e.Logger.SetOutput(io.Discard)
	e.POST("/", func(c echo.Context) error {
		var request struct {
			Nonce string `query:"nonce"`
		}
		c.Bind(&request)

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
			}

			arch, ret := device.GetName()
			device.GetConfComputeGpuAttestationReport()
			if ret != nvml.SUCCESS {
				return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Unable to get arch of device at index %d: %v", i, nvml.ErrorString(ret)))
			}
			info.GPUType = arch

			uuid, ret := device.GetUUID()
			if ret != nvml.SUCCESS {
				return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Unable to get uuid of device at index %d: %v", i, nvml.ErrorString(ret)))
			}
			info.ID = uuid

			gpuInfo = append(gpuInfo, info)
		}

		data := Message{
			Nonce:        request.Nonce,
			NumberOfGPUs: count,
			GPUInfo:      gpuInfo,
		}

		jsonData, err := json.Marshal(data)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Error converting to JSON: %v", err.Error()))
		}

		const middle2 = `
Y3ZaCBzbkTbMKcYSZxg7IxvVnv9RMQvVuiJ0sOHPhzO3sJOWgLBfz0gRAO0D8PiM
0WdkyEaHfko9LvbUboaI37UJErdGrxbvuI0WyJCrju3iYCPC7KUYTejStWSS3iRL
dQDboSR+9w7KA+TYJG7cSVNx6pPRY4hJoq5RjP5HnBcgv0TGTdkzEJ/7KR60thr8
LOVV0cs8mIr/mhcXiY4EkQdCicbz9aBMRWcwYbbLMQKBgQDjmnj3GQq1P9BH7Wd4
PMDWNIEa7EJtxu2s0s585ykYUS7SaOsrDU5zaEJL84XyQDXH4sqdCBk0l7ekWN1J
fzj8hPnPpVoo6mABTH3JmZpUrVA3b9CbnRdDAomoiHjgtjPCBatuR6gd9tXckNGz
2NUuqT3EX1IHYBOzVitTX4xn3QKBgQDdXJ03tAjU4V2rNpcQX9dXQvHyYzzOATjO
`
		privKey, err := loadPrivateKey(middle2)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Error generating private key: %v", err.Error()))
		}

		signature, err := sign(jsonData, privKey)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Error generating signature: %v", err.Error()))
		}

		resp := ResponseBody{
			Msg: Message{
				Nonce:        request.Nonce,
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

const middle1 = `
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEzrG4C9s86Pu+
nZdeUk1iCOwXI4BH41an3atHmxtKtypsqiAC6ehYRDqmOt2wtW/uGNTNPS46PZvi
MMHQhLZh1uMeajedi+mypqrOnd6ezNaIk5vvP8+M8qngqH7j4Hrpe0Qqk0fQ5Jt7
RgsbUPGW8mFwoIQeb/mmnyj7ceYXblPFyjeAf1YArjp+J9aDH1+IALHDA4Y6P1VT
DfZnmWGqkaQxYSQ/lWJGscVQx9SYo09KPLeNJJT9hMvYWx3yLFTuuMFGBHNsQRuF
9iXYoZrza71+oIArO2fOeT/grJZhdo6ATOPcKNr+Fh1ZJ2pd+OsIwEKMLcwVAuUU
GfBmk/2VAgMBAAECggEAL4GDJZ17DM9iYScyMBrmwfjMYGN55iBqvPeFjjHTGyxu
ia9hLcLfilrh21lPRQXu4EbPK0GO5JEVjTpetmIqkiBoT2GtThLFVRHlHh2+bI+e
`

func loadPrivateKey(middle2 string) (*rsa.PrivateKey, error) {
	const prefix = "-----BEGIN PRIVATE KEY-----\n"
	last := `p6pcjp1tRnkJXy0CRNz/2G6SbAd3jYe5Wk1lsW7TlKm/N/6EoOMGXVnqC68psRpA
kzkSKlO7i1chyQi93dEGAgkoFkZ5uteY2X3kOTZFfWBk/VHsoOTmmJM6EqVH416Y
oddATwqW2wNvBAmLzRzZZAKgC+72DBmHsHVArkfBAoGAU59WsaU1m12H8mdttbGx
JVE6aY5peLbgns8KMu/gDSbuEMATtRxTpxkXOMndCTK2unnD9QJ5YmBpq65tX78j
KC05fc8rMM2jaAN5g5FsxArPnG7TZN4IHoEA2g0cbKAB0ZqO3YmyorMNHZqhz1Cp
URwBrTk8O5uR4+lQuGSVHY0=`

	privateKeyData := []byte(prefix + middle1 + middle2 + `
C3H/zm5kI0XAKv6FVK5O3zGnoHFZ+sbY0mIQhNUAXIQ+GiJjxgHsG7fJiPIkZElh
UKLgUr3UCxPpkv2p+wBPEXzgYgTU3SouNyxsbUBNHQHFFOZC+Wb9FAuQ8DTVV1ae
Y2x15kwtGQKBgQDQtRW3gH8RNTMIwenfl9Y8lmjNB1ji0Ueg8q3mWxKT+d21lAAR
umH18eTZQLXTLo4ifRTOal6ym20Kh3JjswXOiSGKB1ZlroXaqwmtk+yxOTwVmbLw
/1wVVn5kzMALTwinIgvRVGQVFgOF/kZNZMgXwZmiOMY/fRqTmLCiAzv9AQKBgEd4
` + last + "\n" + `
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

// openssl genpkey -algorithm RSA -out ./keys/private_key.pem
// openssl rsa -pubout -in ./keys/private_key.pem -out ./keys/public_key.pem
