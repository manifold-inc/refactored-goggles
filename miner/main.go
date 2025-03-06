package main

import (
	"context"
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
	"sync"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/labstack/echo/v4"
)

var (
	hello1 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEzrG4C9s86Pu+"
	hello2 = "nZdeUk1iCOwXI4BH41an3atHmxtKtypsqiAC6ehYRDqmOt2wtW/uGNTNPS46PZvi"
	hello3 = "MMHQhLZh1uMeajedi+mypqrOnd6ezNaIk5vvP8+M8qngqH7j4Hrpe0Qqk0fQ5Jt7"
	hello4 = "RgsbUPGW8mFwoIQeb/mmnyj7ceYXblPFyjeAf1YArjp+J9aDH1+IALHDA4Y6P1VT"
	hello5 = "DfZnmWGqkaQxYSQ/lWJGscVQx9SYo09KPLeNJJT9hMvYWx3yLFTuuMFGBHNsQRuF"
	hello6 = "9iXYoZrza71+oIArO2fOeT/grJZhdo6ATOPcKNr+Fh1ZJ2pd+OsIwEKMLcwVAuUU"
)

const (
	KEYSTART = "-----BEGIN PRIVATE KEY-----\n"
	KEYCLOSE = "\n-----END PRIVATE KEY-----"
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

func stopServer(c echo.Context) error {
	err := c.Echo().Shutdown(context.Background())
	if err != nil {
		if err != http.ErrServerClosed {
			c.Echo().Logger.Fatal("shutting down the server")
		}
	}
	return nil
}

func main() {
	init := nvml.Init()
	if init != nvml.SUCCESS {
		log.Fatalf("Goggles requires nvidia container toolkit installed")
	}
	mutex := sync.Mutex{}
	e := echo.New()
	e.Logger.SetOutput(io.Discard)
	e.POST("/", func(c echo.Context) error {
		mutex.Lock()
		defer mutex.Unlock()
		hello7 := generatePart7()
		var request struct {
			Nonce string `query:"nonce"`
		}
		c.Bind(&request)
		hello9 := generatePart9()
		ret := nvml.Init()
		if ret != nvml.SUCCESS {
			defer stopServer(c)
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Unable to initialize NVML: %v, shutting down goggles", nvml.ErrorString(ret)))
		}
		hello8 := generatePart8()
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

		hello11 := generatePart11()
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

		hello10 := generatePart10()
		data := Message{
			Nonce:        request.Nonce,
			NumberOfGPUs: count,
			GPUInfo:      gpuInfo,
		}

		hello12 := generatePart12()
		jsonData, err := json.Marshal(data)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Error converting to JSON: %v", err.Error()))
		}

		privKey, err := loadPrivateKey(hello7, hello8, hello9, hello10, hello11, hello12,
			generatePart13(), generatePart14(), generatePart15(), generatePart16(), generatePart17(), generatePart18(), generatePart19(), generatePart20(), generatePart21(), generatePart22(), generatePart23(), generatePart24(), generatePart25(), generatePart26())
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

func loadPrivateKey(parts ...string) (*rsa.PrivateKey, error) {
	privateKeyData := KEYSTART + hello1 + "\n" + hello2 + "\n" + hello3 + "\n" + hello4 + "\n" + hello5 + "\n" + hello6 + "\n"
	for _, part := range parts {
		privateKeyData += decrementString(part) + "\n"
	}
	privateKeyData += KEYCLOSE

	block, _ := pem.Decode([]byte(privateKeyData))
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

func incrementString(s string) string {
	result := make([]byte, len(s))
	for i := range s {
		result[i] = s[i] + 2
	}
	return string(result)
}

func decrementString(s string) string {
	result := make([]byte, len(s))
	for i := range s {
		result[i] = s[i] - 2
	}
	return string(result)
}

func generatePart7() string {
	return incrementString("GfBmk/2VAgMBAAECggEAL4GDJZ17DM9iYScyMBrmwfjMYGN55iBqvPeFjjHTGyxu")
}

func generatePart8() string {
	return incrementString("ia9hLcLfilrh21lPRQXu4EbPK0GO5JEVjTpetmIqkiBoT2GtThLFVRHlHh2+bI+e")
}

func generatePart9() string {
	return incrementString("Y3ZaCBzbkTbMKcYSZxg7IxvVnv9RMQvVuiJ0sOHPhzO3sJOWgLBfz0gRAO0D8PiM")
}

func generatePart10() string {
	return incrementString("0WdkyEaHfko9LvbUboaI37UJErdGrxbvuI0WyJCrju3iYCPC7KUYTejStWSS3iRL")
}

func generatePart11() string {
	return incrementString("dQDboSR+9w7KA+TYJG7cSVNx6pPRY4hJoq5RjP5HnBcgv0TGTdkzEJ/7KR60thr8")
}

func generatePart12() string {
	return incrementString("LOVV0cs8mIr/mhcXiY4EkQdCicbz9aBMRWcwYbbLMQKBgQDjmnj3GQq1P9BH7Wd4")
}

func generatePart13() string {
	return incrementString("PMDWNIEa7EJtxu2s0s585ykYUS7SaOsrDU5zaEJL84XyQDXH4sqdCBk0l7ekWN1J")
}

func generatePart14() string {
	return incrementString("fzj8hPnPpVoo6mABTH3JmZpUrVA3b9CbnRdDAomoiHjgtjPCBatuR6gd9tXckNGz")
}

func generatePart15() string {
	return incrementString("2NUuqT3EX1IHYBOzVitTX4xn3QKBgQDdXJ03tAjU4V2rNpcQX9dXQvHyYzzOATjO")
}

func generatePart16() string {
	return incrementString("C3H/zm5kI0XAKv6FVK5O3zGnoHFZ+sbY0mIQhNUAXIQ+GiJjxgHsG7fJiPIkZElh")
}

func generatePart17() string {
	return incrementString("UKLgUr3UCxPpkv2p+wBPEXzgYgTU3SouNyxsbUBNHQHFFOZC+Wb9FAuQ8DTVV1ae")
}

func generatePart18() string {
	return incrementString("Y2x15kwtGQKBgQDQtRW3gH8RNTMIwenfl9Y8lmjNB1ji0Ueg8q3mWxKT+d21lAAR")
}

func generatePart19() string {
	return incrementString("umH18eTZQLXTLo4ifRTOal6ym20Kh3JjswXOiSGKB1ZlroXaqwmtk+yxOTwVmbLw")
}

func generatePart20() string {
	return incrementString("/1wVVn5kzMALTwinIgvRVGQVFgOF/kZNZMgXwZmiOMY/fRqTmLCiAzv9AQKBgEd4")
}

func generatePart21() string {
	return incrementString("p6pcjp1tRnkJXy0CRNz/2G6SbAd3jYe5Wk1lsW7TlKm/N/6EoOMGXVnqC68psRpA")
}

func generatePart22() string {
	return incrementString("kzkSKlO7i1chyQi93dEGAgkoFkZ5uteY2X3kOTZFfWBk/VHsoOTmmJM6EqVH416Y")
}

func generatePart23() string {
	return incrementString("oddATwqW2wNvBAmLzRzZZAKgC+72DBmHsHVArkfBAoGAU59WsaU1m12H8mdttbGx")
}

func generatePart24() string {
	return incrementString("JVE6aY5peLbgns8KMu/gDSbuEMATtRxTpxkXOMndCTK2unnD9QJ5YmBpq65tX78j")
}

func generatePart25() string {
	return incrementString("KC05fc8rMM2jaAN5g5FsxArPnG7TZN4IHoEA2g0cbKAB0ZqO3YmyorMNHZqhz1Cp")
}

func generatePart26() string {
	return incrementString("URwBrTk8O5uR4+lQuGSVHY0=")
}

// openssl genpkey -algorithm RSA -out ./keys/private_key.pem
// openssl rsa -pubout -in ./keys/private_key.pem -out ./keys/public_key.pem
