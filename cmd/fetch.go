/*
 fetch.go

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
	"time"
	"totp/core"
	"totp/utils"
)

func init() {
	RegCmd("Fetch", "F", CmdFetch)
	RegCmd("FetchAll", "A", CmdFetchAll)
}

func CmdFetch(env *AppEnv) error {
	config, _ := getConf(env)
	if config == nil {
		fmt.Println("Configuration not found")
		return nil
	}
	fmt.Printf("Secret: %s\nPeriod: %d\nDigits: %d\nAlgorithm: %s\nIssuer: %s\nLabel: %s\n",
		shadowSecret(config.Secret), config.Period, config.Digits, config.Algorithm, config.Issuer, config.Label)
	fmt.Printf("OTP Auth URL: %s\n", config.GenerateOTPAuthURL())
	showCode(*config)
	return nil
}

func CmdFetchAll(env *AppEnv) error {
	done := make(chan bool)
	num := len(env.RuntimeData.TotpList)
	cnt := 0
	span := 100 * time.Millisecond
	chars := []string{"-", "\\", "|", "/"}
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(span):
				if cnt > 0 {
					bk := fmt.Sprintf("\r\033[%dA", num+1)
					fmt.Printf(bk)
				}
				for i, config := range env.RuntimeData.TotpList {
					code, err := config.GenerateTOTP()
					if err != nil {
						fmt.Printf("%d FAILED [%s,%s], error:%s\n", i+1, config.Label, config.Issuer, err)
					} else {
						fmt.Printf("%d OK [%s,%s] Code [%s] %d Sec\n", i+1, config.Issuer, config.Label, code, config.GetCodeRemainingTime())
					}
				}
				fmt.Printf("%s Press Enter to cancel code refresh.\n", chars[cnt%len(chars)])
				cnt++
			}
		}
	}()
	var input string
	fmt.Scanln(&input)
	close(done)
	return nil
}

func showCode(conf core.TOTPConfig) {
	if conf.Period <= 0 {
		conf.Period = core.DefaultPeriod
	}
	pb := utils.ProgressBar{Width: 10, MaxVal: conf.Period, AlertVal: 10}
	done := make(chan bool)
	fmt.Println("Press Enter to cancel code refresh.")
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(100 * time.Millisecond):
				code, err := conf.GenerateTOTP()
				if err != nil {
					fmt.Println("Error generating TOTP:", err)
					return
				}
				left := conf.GetCodeRemainingTime()
				prefix := fmt.Sprintf("One-time code: [%s] ", code)
				postfix := fmt.Sprintf(" %02d Sec", left)
				pb.Update(left, prefix, postfix)
			}
		}
	}()
	var input string
	fmt.Scanln(&input)
	close(done)
}
