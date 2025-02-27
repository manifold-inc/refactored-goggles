package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/labstack/echo/v4"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

const (
	PrivateKey = "./keys/private_key.pem"
	PublicKey  = "./keys/public_key.pem"
)

type ResponseBody struct {
	Msg       Message `json:"msg"`
	Signature string  `json:"signature"`
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
	ret := nvml.Init()
	if ret != nvml.SUCCESS {
		log.Fatal(nvml.ErrorString(ret))
	}
	defer func() {
		ret := nvml.Shutdown()
		if ret != nvml.SUCCESS {
			log.Fatalf("Unable to shutdown NVML: %v", nvml.ErrorString(ret))
		}
	}()

	e.POST("/", func(c echo.Context) error {
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

		signature, err := signMessage(privKey, string(jsonData))
		if err != nil {
			return c.JSON(http.StatusInternalServerError, fmt.Sprintf("Error generating signature: %v", err.Error()))
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

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	seed := bip39.NewSeed(mnemonic, "green glass bar")

	masterPrivateKey, _ := bip32.NewMasterKey(seed)
	masterPublicKey := masterPrivateKey.PublicKey()
	publicKeyBytes, _ := masterPublicKey.Serialize()
	fmt.Printf("Public Key: %x\n", publicKeyBytes)
	ecdaPrivateKey := ethcrypto.ToECDSAUnsafe(masterPrivateKey.Key)
	return ecdaPrivateKey, nil
}

func signMessage(privateKey *ecdsa.PrivateKey, message string) (string, error) {
	messageHash := accounts.TextHash([]byte(message))

	signature, err := ethcrypto.Sign(messageHash, privateKey)
	if err != nil {
		return "", err
	}

	signature[ethcrypto.RecoveryIDOffset] += 27

	return hexutil.Encode(signature), nil
}
