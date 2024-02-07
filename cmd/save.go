/*
 save.go

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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"totp/core"
	"totp/utils"
)

func init() {
	RegCmd("Save", "S", CmdSave)
	RegCmd("Quit", "Q", CmdQuit)
	RegCmd("ChPassword", "C", CmdChPwd)
}

const defautEncFileName = ".securetotp-cli/mytotp.vault"

func getEncFileName() string {
	encFileName := *dataFile
	if len(encFileName) == 0 {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("Failed to get the home directory: %s\n", err)
			os.Exit(0)
		}
		encFileName = filepath.Join(homeDir, defautEncFileName)
	}
	return encFileName
}

func CmdSave(env *AppEnv) error {
	jsonData, err := json.MarshalIndent(appEnv.RuntimeData, "", "    ")
	if err != nil {
		fmt.Printf("Encoding JSON failed: %s", err)
		return err
	}
	err = encFile.WriteToFile(getEncFileName(), jsonData)
	if err != nil {
		fmt.Printf("Write data file failed: %s", err)
		return err
	}
	env.LoadedTotpList = make([]core.TOTPConfig, len(env.RuntimeData.TotpList))
	copy(env.LoadedTotpList, env.RuntimeData.TotpList)
	fmt.Printf("Data has been encrypted and saved to [%s]\nYou can make a backup if necessary.\n", getEncFileName())
	return nil
}

func CmdChPwd(env *AppEnv) error {
	utils.SetPassword("")
	err := encFile.Init(utils.EncFileVer, utils.KeyGen)
	if err != nil {
		fmt.Printf("Init new encrypted file failed:%s\n", err)
		return err
	}
	return CmdSave(env)
}

func CmdQuit(env *AppEnv) error {
	if isTotpListModified(env) {
		fmt.Print("TOTP data has been modified, do you want to save? (y/n): ")
		var line string
		fmt.Scanln(&line)
		line = strings.ToUpper(line)
		if line != "N" {
			CmdSave(env)
		}
	}
	os.Exit(0)
	return nil
}

func isTotpListModified(env *AppEnv) bool {
	if len(env.RuntimeData.TotpList) != len(env.LoadedTotpList) {
		return true
	}
	for i := range env.LoadedTotpList {
		if env.LoadedTotpList[i] != env.RuntimeData.TotpList[i] {
			fmt.Println("data", i)
			return true
		}
	}
	return false
}

func LoadConfigFromFile(env *AppEnv) error {
	utils.SetPassword(*passwd)
	utils.SetKeyfile(*keyFile)

	dirPath := filepath.Dir(getEncFileName())
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}

	_, err = os.Stat(getEncFileName())
	if err != nil {
		fmt.Printf("Data file not found, Set up a new password for data file [%s]\n", getEncFileName())
		err = encFile.Init(utils.EncFileVer, utils.KeyGen)

		env.RuntimeData.Meta.Version = AppDataVersion
		env.RuntimeData.Meta.Timestamp = time.Now().UTC().Format(time.RFC3339)
		return err
	}

	err = encFile.LoadFromFile(getEncFileName(), utils.KeyGen)
	if err != nil {
		return err
	}
	err = json.Unmarshal(encFile.Data, &env.RuntimeData)
	if err != nil {
		return err
	}
	env.LoadedTotpList = make([]core.TOTPConfig, len(env.RuntimeData.TotpList))
	copy(env.LoadedTotpList, env.RuntimeData.TotpList)
	return nil
}
