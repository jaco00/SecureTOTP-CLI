/*
 update.go

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
	"strings"
)

func init() {
	RegCmd("Update", "U", CmdUpdate)
}

func CmdUpdate(env *AppEnv) error {
	config, _ := getConf(env)
	if config == nil {
		fmt.Println("Configuration not found")
		return nil
	}
	fmt.Printf("1. Update Secret: [%s]\n", shadowSecret(config.Secret))
	fmt.Printf("2. Update Period: [%d]\n", config.Period)
	fmt.Printf("3. Update Digits: [%d]\n", config.Digits)
	fmt.Printf("4. Update Algorithm: [%s]\n", config.Algorithm.String())
	fmt.Printf("5. Update Issuer: [%s]\n", config.Issuer)
	fmt.Printf("6. Update Label(Account name): [%s]\n", config.Label)
	fmt.Printf("0. Cancel Update\n")

	var updateChoice int
	fmt.Print("Enter your update choice: ")
	fmt.Scanln(&updateChoice)

	reader := bufio.NewReader(os.Stdin)
	switch updateChoice {
	case 1:
		fmt.Print("Enter new Secret: ")
		fmt.Scanln(&config.Secret)
	case 2:
		fmt.Print("Enter new Period: ")
		fmt.Scanln(&config.Period)
	case 3:
		fmt.Print("Enter new Digits: ")
		fmt.Scanln(&config.Digits)
	case 4:
		fmt.Print("Enter new Algorithm (SHA1/SHA256/SHA512): ")
		var algorithm string
		fmt.Scanln(&algorithm)
		config.Algorithm.ParseString(algorithm)
	case 5:
		fmt.Print("Enter new Issuer: ")
		config.Issuer, _ = reader.ReadString('\n')
		config.Issuer = strings.TrimRight(config.Issuer, "\r\n")
	case 6:
		fmt.Print("Enter new Label(Account name): ")
		config.Label, _ = reader.ReadString('\n')
		config.Label = strings.TrimRight(config.Label, "\r\n")
	default:
		fmt.Println("Update canceled.")
		return nil
	}
	fmt.Println("TOTP Configuration updated successfully.")
	return nil
}
