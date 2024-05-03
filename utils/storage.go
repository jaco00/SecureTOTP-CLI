/*
 storage.go

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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	FileMagic = 0xB0C961D9
)

type EncHashInfo struct {
	Salt        [32]byte
	HashType    [16]byte
	HashVersion int32 // 0 means struct not init
	HashPara    [64]byte
}

func ToEncHashInfo(info HashParams) *EncHashInfo {
	e := EncHashInfo{}
	copy(e.Salt[:], info.Salt)
	copy(e.HashType[:], []byte(info.HashType))
	e.HashVersion = info.Version
	copy(e.HashPara[:], []byte(info.Para))
	return &e
}

func (e EncHashInfo) ToHashParams() *HashParams {
	hp := HashParams{}
	hp.Salt = e.Salt[:]
	hp.HashType = string(bytes.TrimRight(e.HashType[:], "\x00"))
	hp.Version = e.HashVersion
	hp.Para = string(bytes.TrimRight(e.HashPara[:], "\x00"))
	return &hp
}

type EncFileHeader struct {
	Magic     uint64
	Ver       uint32 //Enc version
	Preserved uint32
	Crc       uint64
	TimeStamp uint64
	DataLen   uint32
	Para      uint32 //preserved
	HParams   EncHashInfo
}

type EncFile struct {
	//data written to a file
	Header EncFileHeader
	Data   []byte
	//memory data during program execution
	Key []byte //32 bytes
}

// ver represents the version of the Key derivation logic
type KeyGenFn func(info *EncHashInfo, ver uint32) (EncHashInfo, []byte, error)

func (f *EncFile) Init(ver uint32, keyGen KeyGenFn) error {
	f.Header.Magic = FileMagic
	f.Header.Ver = ver
	f.Header.Preserved = 0
	f.Header.TimeStamp = uint64(time.Now().Unix())
	para, key, err := keyGen(nil, ver)
	f.Key = key
	f.Header.HParams = para
	if err != nil {
		return err
	}
	return nil
}

func (f *EncFile) GetFileInfo() []string {
	ctTime := fmt.Sprintf("File Modified Time: %s", time.Unix(int64(f.Header.TimeStamp), 0).Format(time.RFC3339))
	ver := fmt.Sprintf("KDF Version :%d", f.Header.Ver)
	salt := fmt.Sprintf("Salt: %s", hex.EncodeToString(f.Header.HParams.Salt[:]))
	hashType := fmt.Sprintf("Hash Type: %s", string(f.Header.HParams.HashType[:]))
	hashVer := fmt.Sprintf("Hash Version: %d", f.Header.HParams.HashVersion)
	hashPara := fmt.Sprintf("Hash Params: %s", f.Header.HParams.HashPara)
	return []string{ctTime, ver, salt, hashType, hashVer, hashPara}
}

func (f *EncFile) writeFile(filename string) error {
	f.Header.TimeStamp = uint64(time.Now().Unix())
	of, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer of.Close()
	cryptoData, err := EncryptAES256(f.Key, f.Data, false)
	if err != nil {
		return err
	}
	f.Header.Crc = GetCrcCode(cryptoData)
	f.Header.DataLen = uint32(len(cryptoData))

	err = binary.Write(of, binary.LittleEndian, f.Header)
	if err != nil {
		return err
	}

	_, err = of.Write(cryptoData)
	if err != nil {
		return err
	}
	return of.Sync()
}

func switchFile(filename, tempfile string, key []byte) error {
	nf := EncFile{}
	nf.Key = key
	if err := nf.LoadFromFile(tempfile, nil); err != nil {
		fmt.Printf("Verify failed :%v\n", err)
		return err
	}
	if _, err := os.Stat(filename); err == nil {
		if err := os.Remove(filename); err != nil {
			return err
		}
	} else {
		if !os.IsNotExist(err) {
			return err
		}
	}
	fmt.Printf("Verify ok, rename %s -> %s\n", tempfile, filename)
	return os.Rename(tempfile, filename)
}

func (f *EncFile) WriteToFile(filename string, data []byte) error {
	tempFile := filename + ".temp"
	f.Data = data
	if err := f.writeFile(tempFile); err != nil {
		return err
	}
	return switchFile(filename, tempFile, f.Key)
}

func (f *EncFile) LoadFromFile(filename string, keyGen KeyGenFn) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	err = binary.Read(file, binary.LittleEndian, &f.Header)
	if err != nil {
		return err
	}
	if f.Header.Magic != FileMagic {
		return errors.New("Bad file magic")
	}
	//f.Key, _, err = keyGen(f.Header.Salt[:], f.Header.Ver)
	if keyGen != nil {
		_, f.Key, err = keyGen(&f.Header.HParams, f.Header.Ver)
		if err != nil {
			return err
		}
	}
	if len(f.Key) == 0 {
		return errors.New("Key is empty")
	}
	currentOffset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	fileSize := fileInfo.Size()
	bytesToRead := fileSize - currentOffset

	data := make([]byte, bytesToRead)
	_, err = io.ReadFull(file, data)
	if err != nil {
		return err
	}
	if bytesToRead != int64(f.Header.DataLen) {
		return errors.New("Bad file length")
	}
	if GetCrcCode(data) != f.Header.Crc {
		return errors.New("Bad crc")
	}

	f.Data, err = DecryptAES256(f.Key, data, false)
	return err
}
