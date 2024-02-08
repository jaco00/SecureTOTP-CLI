/*
 transfer.go

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
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"totp/core"
)

func init() {
	RegCmd("Import", "I", CmdImport)
	RegCmd("Export", "E", CmdExport)
}

func CmdImport(env *AppEnv) error {
	var importFile string
	fmt.Print("Enter export filename[json or csv]: ")
	fmt.Scanln(&importFile)

	fileContent, err := os.ReadFile(importFile)
	if err != nil {
		fmt.Printf("Read file [%s] failed : %s\n", importFile, err)
		return err
	}

	trimFunc := func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
	trimmedData := bytes.TrimLeftFunc(fileContent, trimFunc)
	if len(trimmedData) < 20 {
		fmt.Println("File size is not enough")
		return nil
	}
	var importedData []core.TOTPConfig
	if trimmedData[0] == '[' {
		importedData, err = importConfigFromJson(fileContent)
		if err != nil {
			fmt.Printf("Import failed: [%s]\n", err)
			return err
		}
		fmt.Println("Import Json data")
	}
	if strings.ToUpper(string(trimmedData[:5])) == "ISSUE" {
		importedData, err = importConfigFromCsv(fileContent)
		if err != nil {
			fmt.Printf("Import failed: [%s]\n", err)
			return err
		}
		fmt.Println("Import CSV data")
	}

	updateed := 0
	inserted := 0
	for _, importedConfig := range importedData {
		existingIndex := findExistingConfig(importedConfig, env.RuntimeData.TotpList)
		if existingIndex == -1 {
			env.RuntimeData.TotpList = append(env.RuntimeData.TotpList, importedConfig)
			inserted++
		} else {
			env.RuntimeData.TotpList[existingIndex] = importedConfig
			updateed++
		}
	}
	fmt.Printf("Import new record:%d\n", inserted)
	fmt.Printf("Update current record:%d\n", updateed)
	return nil
}

func CmdExport(env *AppEnv) error {
	var exportFile string
	fmt.Print("Enter export filename: ")
	fmt.Scanln(&exportFile)

	_, err := os.Stat(exportFile)
	if !os.IsNotExist(err) {
		fmt.Println("File already exists, Aborting export.")
		return err
	}

	var choice int
	fmt.Printf("1. Export in csv format\n")
	fmt.Printf("2. Export in json format\n")
	fmt.Print("Enter your export choice: ")
	fmt.Scanln(&choice)

	switch choice {
	case 1:
		err = exportConfigToCSV(exportFile, env.RuntimeData.TotpList)
	case 2:
		err = exportConfigToJson(exportFile, env.RuntimeData.TotpList)
	default:
		fmt.Printf("Export canceled\n")
	}
	if err == nil {
		fmt.Println("Configuration exported successfully.")
	} else {
		fmt.Printf("Export failed : [%s]\n", err)
	}
	return nil
}

func findExistingConfig(rec core.TOTPConfig, list []core.TOTPConfig) int {
	for i, config := range list {
		if config.Issuer == rec.Issuer && config.Label == rec.Label {
			return i
		}
	}
	return -1
}

func importConfigFromCsv(data []byte) ([]core.TOTPConfig, error) {
	var list []core.TOTPConfig
	reader := csv.NewReader(strings.NewReader(string(data)))
	title, err := reader.Read()
	if err != nil {
		return nil, err
	}
	if len(title) < 7 || strings.ToUpper(title[0]) != "ISSUER" {
		return nil, errors.New("Bad csv format,Wrong fields or missing columns")
	}

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		totp := core.TOTPConfig{}
		totp.Issuer = record[0]
		totp.Label = record[1]
		totp.Secret = record[2]
		totp.Period, _ = strconv.Atoi(record[3])
		totp.Digits, _ = strconv.Atoi(record[4])
		totp.Algorithm.ParseString(record[5])
		totp.Counter, _ = strconv.Atoi(record[6])
		list = append(list, totp)
	}
	return list, nil
}

func importConfigFromJson(data []byte) ([]core.TOTPConfig, error) {
	var list []core.TOTPConfig
	err := json.Unmarshal(data, &list)
	return list, err
}

func exportConfigToCSV(file string, data []core.TOTPConfig) error {
	outputFile, err := os.Create(file)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	csvWriter := csv.NewWriter(outputFile)
	defer csvWriter.Flush()

	csvWriter.Write([]string{"Issuer", "Label", "Secret", "Period", "Digits", "Algorithm", "Counter"})

	for _, totp := range data {
		csvWriter.Write([]string{totp.Issuer, totp.Label, totp.Secret, strconv.Itoa(totp.Period), strconv.Itoa(totp.Digits),
			totp.Algorithm.String(), strconv.Itoa(totp.Counter)})
	}
	return csvWriter.Error()
}

func exportConfigToJson(file string, data []core.TOTPConfig) error {
	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(file, jsonData, 0644)
	return err
}
