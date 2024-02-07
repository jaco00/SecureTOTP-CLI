/*
 key_gen.go

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
	"errors"
)

var (
	kgPasswd  = ""
	kgKeyfile = ""
)

const EncFileVer = 2 //The version number determines the encryption method

func SetPassword(pwd string) {
	kgPasswd = pwd
}
func SetKeyfile(kf string) {
	kgKeyfile = kf
}

func KeyGen(encInfo *EncHashInfo, ver uint32) (EncHashInfo, []byte, error) {
	var pwd string
	var err error
	genPass := false
	var hPara *HashParams = nil
	if encInfo == nil {
		genPass = true
	} else {
		hPara = encInfo.ToHashParams()
	}

	if len(kgPasswd) > 0 {
		pwd = kgPasswd
	} else {
		pwd, err = GetPassword(genPass)
		if err != nil {
			return EncHashInfo{}, nil, err
		}
	}

	switch ver {
	case EncFileVer:
		curPara, err := Gen256BitSecretKey(pwd, kgKeyfile, hPara)
		if err != nil {
			return EncHashInfo{}, nil, err
		}
		return *ToEncHashInfo(curPara), curPara.Key, nil

	default:
		return EncHashInfo{}, nil, errors.New("Unknown encrypted file version")
	}
}
