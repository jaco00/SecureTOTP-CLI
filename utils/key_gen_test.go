/*
 key_gen_test.go

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
	"totp/utils"
)

func TestKeyGen(t *testing.T) {
	salt := "this_is_a_test_salt"
	para := "m=65536&t=10&p=4"
	expectedKey := "f2dd5d83d114089d052f88bfebf66f576c994b5f2ac1dc1e6e650ae735caa032"
	conf := utils.HashParams{
		HashType: "argon2id",
		Salt:     []byte(salt),
		Para:     para,
	}
	pwdstr := "abc"
	passwd = &pwdstr
	encHashInfo, key, err := KeyGen(utils.ToEncHashInfo(conf), EncFileVer)
	if err != nil {
	}
	if string(bytes.TrimRight(encHashInfo.Salt[:], "\x00")) != salt {
		t.Errorf("Key Gen failed, Salt not consistent, %s!=%s", string(encHashInfo.Salt[:]), salt)
	}
	if hex.EncodeToString(key) != expectedKey {
		t.Errorf("Key Gen failed, Key not consistent \ngen:%s \nexpected:%s", hex.EncodeToString(key), expectedKey)
	}
}
