/*
 bar.go

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
	"fmt"
	"strings"
)

type ProgressBar struct {
	Width    int
	MaxVal   int
	AlertVal int
}

func (pb *ProgressBar) Update(progress int, prefix string, postfix string) {
	if progress < 0 {
		progress = 0
	} else if progress > pb.MaxVal {
		progress = pb.MaxVal
	}

	numChars := pb.Width * progress / pb.MaxVal
	bar := fmt.Sprintf("%-"+fmt.Sprint(pb.Width)+"s", strings.Repeat("█", numChars))
	if progress <= pb.AlertVal {
		fmt.Printf("\r%s \033[47;31m%s\033[0m %s", prefix, bar, postfix)
	} else {
		fmt.Printf("\r%s \033[47;32m%s\033[0m %s", prefix, bar, postfix)
	}

}
