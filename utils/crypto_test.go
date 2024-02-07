/*
 crypto_test.go

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
	"encoding/hex"
	"testing"
)

func TestGenerateHash(t *testing.T) {
	salt := "test salt"
	para := "m=65536&t=10&p=4"
	testCases := []struct {
		input    string
		expected string
	}{
		{"hello", "5b2980d78eeeb932ec8cc94f24f7f4f5c978380237f68c367de2a9ecf49961b1"},
		{"world", "13d54a8cb5204a2f23b0d9b63f8826afa8ded77aa6951238bbcc8682564254f8"},
	}

	conf := HashParams{
		HashType: "argon2id",
		Salt:     []byte(salt),
		Para:     para,
	}

	for _, tc := range testCases {
		// 调用生成哈希的函数
		res, err := Gen256BitSecretKey(tc.input, "", &conf)
		if err != nil {
			t.Errorf("Gen256BitSecretKey failed:%s", err)
			return
		}
		result := hex.EncodeToString(res.Key)

		if result != tc.expected {
			t.Errorf("Gen256BitSecretKey failed! \ninput '%s' \nexpected '%s' \nbut got '%s'", tc.input, tc.expected, result)
		}
		if res.Para != para {
			t.Errorf("Gen256BitSecretKey failed! para:%s != %s", res.Para, para)
		}
	}
}
func TestGenerateHashAndSalt(t *testing.T) {
	testCases := []string{"hello", "world"}
	for _, tc := range testCases {
		res, err := Gen256BitSecretKey(tc, "", nil)
		if err != nil {
			t.Errorf("Gen256BitSecretKeyAndSalt failed:%s", err)
		}
		res2, err := Gen256BitSecretKey(tc, "", &res)
		if err != nil {
			t.Errorf("Gen256BitSecretKeyAndSalt failed:%s", err)
		}

		if !bytes.Equal(res.Key, res2.Key) {
			t.Errorf("Gen256BitSecretKeyAndSalt failed!\n The keys generated twice are inconsistent.\n 1st gen:%s, 2nd gen: %s",
				hex.EncodeToString(res.Key), hex.EncodeToString(res2.Key))
		}
	}
}
