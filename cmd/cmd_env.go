/*
 cmd_env.go

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
	"flag"
	"fmt"
	"strings"

	"totp/core"
	"totp/utils"
)

const AppDataVersion = "1.0"

type AppMetaInfo struct {
	Version   string //This is json data version
	Timestamp string
}

type AppData struct {
	Meta     AppMetaInfo
	TotpList []core.TOTPConfig
}

type AppEnv struct {
	RuntimeData    AppData
	LoadedTotpList []core.TOTPConfig
}

var (
	cmdMap = make(map[string]*AppCmd)
	appEnv AppEnv

	encFile    utils.EncFile
	passwd     = flag.String("p", "", "Passphrase")
	keyFile    = flag.String("k", "", "Using a key file as part of the encryption key")
	dataFile   = flag.String("f", "", "Totp config file (If not specified, The default file is \"~/.securetotp-cli/mytotp.vault\" in homedir)")
	mainSecret []byte
)

type CmdFunc func(env *AppEnv) error

type AppCmd struct {
	Name     string
	ShortCut string
	Fn       CmdFunc
}

func printCmd() {
	cmdList := "NDLFAUIECSQO"
	fmt.Printf("| ")
	for _, ch := range cmdList {
		cmd, found := cmdMap[string(ch)]
		if found {
			fmt.Printf("%s ", strings.Replace(cmd.Name, cmd.ShortCut, "\033[4;32m"+cmd.ShortCut+"\033[0m", 1))
		} else {
			fmt.Printf("Error: shortcht [%c] not found!", ch)
		}
	}
	fmt.Printf("|\n")
}

func shadowSecret(sec string) string {
	if len(sec) > 3 {
		return sec[:3] + "***"
	}
	return "***"
}

func RunCLI() {
	if err := LoadConfigFromFile(&appEnv); err != nil {
		fmt.Printf("Load config data from file failed [%s]\n", err)
		return
	}
	for {
		printCmd()
		var choice string
		fmt.Print("Enter your choice: ")
		fmt.Scanln(&choice)
		choice = strings.ToUpper(choice)
		cmd, found := cmdMap[choice]
		if found {
			cmd.Fn(&appEnv)
		} else {
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func RegCmd(name string, shortCut string, fn CmdFunc) {
	cmd := AppCmd{
		Name:     name,
		ShortCut: shortCut,
		Fn:       fn,
	}
	cmdMap[strings.ToUpper(shortCut)] = &cmd
}
