/*
 list.go

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
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"totp/core"
)

func init() {
	RegCmd("List", "L", CmdList)
}

func CmdList(env *AppEnv) error {
	fmt.Println("List of TOTP Configurations:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "Index\tIssuer\tAccount\tPeriod\tDigits\tAlgorithm\tSecret")
	for i, config := range env.RuntimeData.TotpList {
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%s\t%s\n", i+1, config.Issuer, config.Label,
			config.Period, config.Digits, config.Algorithm.String(), shadowSecret(config.Secret))
	}
	w.Flush()
	return nil
}

func getConf(env *AppEnv) (*core.TOTPConfig, int) {
	if len(env.RuntimeData.TotpList) == 0 {
		fmt.Println("No configurations found.")
		return nil, -1
	}
	CmdList(env)
	fmt.Print("Enter the number of the configuration: ")
	var input string
	fmt.Scanln(&input)

	num, err := strconv.Atoi(input)
	if err != nil || num < 1 || num > len(env.RuntimeData.TotpList) {
		fmt.Println("Invalid input.")
		return nil, 0 - 1
	}

	return &env.RuntimeData.TotpList[num-1], num - 1
}
