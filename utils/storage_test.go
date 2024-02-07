/*
 storage_test.go

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
	"crypto/rand"
	"encoding/hex"
	"io"
	"path/filepath"
	"testing"
)

func TestEncrypedFile(t *testing.T) {
	keyLength := 32
	key := make([]byte, keyLength)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Errorf("Gen random key failed: %s\n", err)
		return
	}
	filePath := filepath.Join(t.TempDir(), "testfile.enc")
	t.Logf("Generate temp file [%s] for test.", filePath)

	fileData := "Hello totp"
	pwd := "test pwd"

	keyGen := func(info *EncHashInfo, ver uint32) (EncHashInfo, []byte, error) {
		curinfo := EncHashInfo{}
		var para *HashParams = nil
		if info != nil {
			para = info.ToHashParams()
		}
		genpara, err := Gen256BitSecretKey(pwd, "", para)
		if err != nil {
			t.Logf("Generate key failed, %s", err)
			return curinfo, key, err
		}
		return *ToEncHashInfo(genpara), key, nil
	}

	cf := EncFile{}
	err = cf.Init(2, keyGen)
	if err != nil {
		t.Errorf("Init file failed: %s", err)
		return
	}
	err = cf.WriteToFile(filePath, []byte(fileData))
	if err != nil {
		t.Errorf("Gen encryped file failed: %s", err)
		return
	}

	cf2 := EncFile{}
	err = cf2.LoadFromFile(filePath, keyGen)
	if !bytes.Equal(cf.Header.HParams.Salt[:], cf2.Header.HParams.Salt[:]) {
		t.Errorf("Salt inconsistent. \nGen:%s \nRead:%s", hex.EncodeToString(cf.Header.HParams.Salt[:]), hex.EncodeToString(cf2.Header.HParams.Salt[:]))
	}
	if err != nil {
		t.Errorf("Load encryped file failed: %s", err)
		return
	}
	t.Logf("Read from encryped file [%s]", string(cf2.Data))
	info := cf2.GetFileInfo()
	for _, v := range info {
		t.Logf("%s", v)
	}
	t.Logf("Decode data [%s]", cf2.Data)
	if !bytes.Equal(cf2.Data, cf.Data) {
		t.Errorf("Load encryped file failed, Data inconsistent!")
		return
	}
}
