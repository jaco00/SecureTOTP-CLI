/*
 totp.go

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

package core

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Algorithm int

func (a *Algorithm) ParseString(algoStr string) {
	switch strings.ToUpper(algoStr) {
	case "SHA1":
		*a = AlgorithmSHA1
	case "SHA256":
		*a = AlgorithmSHA256
	case "SHA512":
		*a = AlgorithmSHA512
	default:
		fmt.Printf("Unknown hash algorithm. using default [SHA1] !\n")
		*a = AlgorithmSHA1
	}
}

func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	}
	panic("unreached")
}

func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	}
	panic("unreached")
}

const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

const (
	DefaultPeriod    = 30
	DefaultDigits    = 6
	DefaultAlgorithm = AlgorithmSHA1
)

type TOTPConfig struct {
	Issuer    string
	Label     string
	Secret    string
	Period    int
	Digits    int
	Algorithm Algorithm
	Counter   int
}

func (c TOTPConfig) GenerateOTPAuthURL() string {
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   url.PathEscape(c.Issuer + ":" + c.Label),
	}

	params := url.Values{}
	params.Add("secret", c.Secret)
	params.Add("algorithm", c.Algorithm.String())
	params.Add("digits", fmt.Sprintf("%d", c.Digits))
	params.Add("period", fmt.Sprintf("%d", c.Period))

	u.RawQuery = params.Encode()

	return u.String()
}

func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func (c *TOTPConfig) ParseOTPAuthURL(authURL string) error {
	u, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	if strings.ToLower(u.Scheme) != "otpauth" {
		return fmt.Errorf("Bad scheme")
	}

	if u.Host != "totp" {
		return fmt.Errorf("Invalid auth type")
	}

	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), ":", 2)
	if len(parts) > 0 {
		c.Issuer = parts[0]
	}
	if len(parts) > 1 {
		c.Label = parts[1]
	}

	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return err
	}

	c.Secret = params.Get("secret")
	c.Algorithm.ParseString(params.Get("algorithm"))
	c.Digits = parseInt(params.Get("digits"))
	if c.Digits == 0 {
		c.Digits = DefaultDigits
	}
	c.Period = parseInt(params.Get("period"))
	fmt.Println("period", c.Period)
	if c.Period == 0 {
		c.Period = DefaultPeriod
	}
	return nil
}

func (t TOTPConfig) GetCodeRemainingTime() int {
	if t.Period <= 0 {
		t.Period = DefaultPeriod
	}
	return t.Period - int(time.Now().Unix()%int64(t.Period))
}

func (t TOTPConfig) GenerateTOTP() (string, error) {
	rawSecret := strings.TrimRight(strings.ToUpper(t.Secret), "=")
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(rawSecret)
	if err != nil {
		return "", err
	}
	timeCounter := time.Now().Unix() / int64(t.Period)
	timeBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		timeBytes[i] = byte(timeCounter & 0xff)
		timeCounter >>= 8
	}
	hmacSha1 := hmac.New(func() hash.Hash { return t.Algorithm.Hash() }, secret)
	hmacSha1.Write(timeBytes)
	hash := hmacSha1.Sum(nil)

	offset := hash[len(hash)-1] & 0x0F
	truncatedHash := hash[offset : offset+4]

	code := binary.BigEndian.Uint32(truncatedHash) & 0x7FFFFFFF

	if t.Digits == 8 {
		code = code % 1e8
		return fmt.Sprintf("%08d", code), nil
	} else {
		code = code % 1e6
		return fmt.Sprintf("%06d", code), nil
	}
}
