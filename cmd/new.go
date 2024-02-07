/*
   new.go

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

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"totp/core"
)

func init() {
	RegCmd("New", "N", CmdNew)
}

func CmdNew(env *AppEnv) error {
	var totpConfig core.TOTPConfig
	var line string

	fmt.Print("Enter Secret or OTP URL:")
	fmt.Scanln(&line)

	if strings.HasPrefix(line, "otpauth://") {
		totpConfig.ParseOTPAuthURL(line)
	} else {
		totpConfig.Secret = line
		fmt.Print("Enter Period (default: ", core.DefaultPeriod, "): ")
		fmt.Scanln(&line)
		totpConfig.Period, _ = strconv.Atoi(line)
		if totpConfig.Period == 0 {
			totpConfig.Period = core.DefaultPeriod
		}

		fmt.Print("Enter Digits (default: ", core.DefaultDigits, "): ")
		fmt.Scanln(&line)
		totpConfig.Digits, _ = strconv.Atoi(line)
		if totpConfig.Digits == 0 {
			totpConfig.Digits = core.DefaultDigits
		}

		fmt.Print("Enter Algorithm (SHA1/SHA256/SHA512, default: SHA1): ")
		var algorithm string
		fmt.Scanln(&algorithm)
		if algorithm == "" {
			totpConfig.Algorithm = core.DefaultAlgorithm
		} else {
			totpConfig.Algorithm.ParseString(algorithm)
		}
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter Issuer: ")
		totpConfig.Issuer, _ = reader.ReadString('\n')
		totpConfig.Issuer = strings.TrimRight(totpConfig.Issuer, "\r\n")

		fmt.Print("Enter Label(Account name): ")
		totpConfig.Label, _ = reader.ReadString('\n')
		totpConfig.Label = strings.TrimRight(totpConfig.Label, "\r\n")
	}

	env.RuntimeData.TotpList = append(env.RuntimeData.TotpList, totpConfig)
	fmt.Println("TOTP Configuration added successfully.")

	return nil
}
