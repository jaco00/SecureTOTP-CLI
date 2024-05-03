/*
 misc.go

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
	"fmt"
	"hash/crc64"
	"syscall"

	"golang.org/x/term"
)

func GetPassword(newPwd bool) (string, error) {
	if newPwd {
		fmt.Print("Enter your \x1b[31mNew password:\x1b[0m")
	} else {
		fmt.Print("Enter your password: ")
	}
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Println()
	if !newPwd {
		return string(password), nil
	}

	fmt.Print("Re-enter your password: ")
	confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Println()

	if string(password) == string(confirmPassword) {
		fmt.Println("Passwords match!")
		return string(password), nil
	} else {
		return "", errors.New("Passwords do not match. Please try again.")
	}
}

func GetCrcCode(data []byte) uint64 {
	crcTable := crc64.MakeTable(crc64.ECMA)
	crc := crc64.New(crcTable)
	crc.Write(data)
	return crc.Sum64()
}
