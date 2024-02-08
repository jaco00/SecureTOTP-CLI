/*
 crypto.go

 GNU GENERAL PUBLIC LICENSE
 Version 3, 29 June 2007
 Copyright (C) 2024 Jack Ng <jack.ng.ca@gmail.com>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/> */

package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

const (
	Iterations   = 3
	MemorySizeKB = 64 * 1024
	Parallelism  = 1
	DefaultPwd   = "c81,T68#1af@77d96;6d"
)

func generateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

type HashParams struct {
	Key      []byte //hash value
	Salt     []byte
	HashType string
	Version  int32
	Para     string
}

func Gen256BitSecretKey(pwdTxt string, keyFile string, hashParams *HashParams) (HashParams, error) {
	hasher := sha3.New512()
	res := HashParams{}
	pwdTxt = DefaultPwd + pwdTxt
	if keyFile != "" {
		fileContent, err := os.ReadFile(keyFile)
		fmt.Printf("Please keep the keyfile[%s] secure as it has been utilized.\n", keyFile)
		if err != nil {
			return HashParams{}, err
		}

		hasher.Write(fileContent)
		if err != nil {
			return HashParams{}, err
		}
	}
	if pwdTxt != "" {
		_, err := hasher.Write([]byte(pwdTxt))
		if err != nil {
			return HashParams{}, err
		}
	}
	hash := hasher.Sum(nil)

	pm := MemorySizeKB
	pt := Iterations
	pp := Parallelism

	if hashParams == nil {
		var err error
		res.Salt, err = generateSalt()
		if err != nil {
			return HashParams{}, err
		}
		res.HashType = "argon2id"
		res.Version = argon2.Version
		res.Para = fmt.Sprintf("m=%d&t=%d&p=%d", pm, pt, pp)
	} else {
		res = *hashParams
		if res.HashType != "argon2id" {
			return HashParams{}, errors.New("Unsupported hash type")
		}
		params, err := url.ParseQuery(res.Para)
		if err != nil {
			return res, err
		}
		pm, _ = strconv.Atoi(params.Get("m"))
		pt, _ = strconv.Atoi(params.Get("t"))
		pp, _ = strconv.Atoi(params.Get("p"))
	}
	key := argon2.IDKey(hash, res.Salt, uint32(pt), uint32(pm), uint8(pp), 32)

	res.Key = key
	return res, nil
}

// Add PKCS7 padding to the data
func addPadding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Remove PKCS7 padding from the data
func removePadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("Bad data")
	}

	padding := int(data[len(data)-1])

	if padding <= 0 || padding > aes.BlockSize || padding > len(data) {
		return nil, errors.New("Bad padding data")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("Bad padding data")
		}
	}

	return data[:len(data)-padding], nil
}

func EncryptAES256(key, plaintext []byte, noPadding bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("bad key")
		return nil, err
	}

	if !noPadding {
		plaintext = addPadding(plaintext, aes.BlockSize)
	}

	// Generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	ciphertext = append(iv, ciphertext...)
	return ciphertext, nil
}

func DecryptAES256(key, ciphertext []byte, noPadding bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) <= aes.BlockSize {
		return nil, errors.New("Insufficient ciphertext length")
	}

	// Extract the IV from the ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	if noPadding {
		return plaintext, nil
	}
	plaintext, err = removePadding(plaintext)
	if err != nil {
		return nil, errors.New("Data corruption or incorrect credential")
	}
	return plaintext, nil
}
