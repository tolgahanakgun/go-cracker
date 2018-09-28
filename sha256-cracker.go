package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var constantString = "potplantspw"
var passFilePath = os.Args[1]
var hashFilePath = "hashes.txt"
var foundPassFilePath = "found"
var founfPassFile *os.File
var index uint64
var delimiter = '\t'
var specialCharacters = ",.*=!+-@$?&%'/\\"
var waitGroup sync.WaitGroup
var coreToUse = 2

//var speacialCharacters = []ch{'!', '^'}

func main() {
	//	passFilePath := flag.String("passList", "words", "Password list to try")
	//	coreToUse := flag.Int("core", 8, "How many cores do you want to use ?")
	//	passFilePath := &passFilePath
	//	coreToUse := &coreToUse
	// the number of cores can be limited
	runtime.GOMAXPROCS(coreToUse)

	// open password list file
	passFile, err := os.Open(passFilePath)
	defer passFile.Close()
	if err != nil {
		panic(err)
	}
	fmt.Println("Password List -> " + passFilePath)

	// open hash list file
	hashFile, err := os.Open(hashFilePath)
	defer hashFile.Close()
	if err != nil {
		panic(err)
	}

	// create a file for storing cracked hashes
	founfPassFile, err = os.OpenFile(foundPassFilePath,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	defer founfPassFile.Close()
	if err != nil {
		panic(err)
	}

	log.Println("Cracking started")
	start := time.Now()

	passFileScanner := bufio.NewScanner(passFile)
	hashFileReader := csv.NewReader(bufio.NewReader(hashFile))
	hashFileReader.Comma = delimiter

	// optimize slice size
	sliceSize := 0
	lineCount, err := lineCounter(passFile)
	if err != nil {
		panic("While trying to count lines on pass file sth went wrong!!!")
	}
	// after counting lines, rewind the file
	passFile.Seek(0, 0)

	if lineCount <= 1000 {
		sliceSize = 0
	} else if lineCount <= 10010 {
		sliceSize = 1000
	} else if lineCount <= 100010 {
		sliceSize = 10000
	} else if lineCount <= 1000010 {
		sliceSize = 100000
	} else {
		sliceSize = 1000000
	}

	var lines []string
	// print progress
	go print()
	if sliceSize != 0 {
		for passFileScanner.Scan() {
			lines = append(lines, passFileScanner.Text())
			if len(lines) == sliceSize {
				//fmt.Println("$$$$$$$$$$$ -> " + len(lines))
				for {
					row, err := hashFileReader.Read()
					// Stop at EOF.
					if err == io.EOF {
						break
					}
					waitGroup.Add(1)
					go attempt(lines, row)
				}
				// clean local variable
				lines = []string{}
				// rewind
				hashFile.Seek(0, 0)
			}
		}
		// if leftover slice size is smaller than the sliceSize variable
		// then send the small array to the function
		for {
			row, err := hashFileReader.Read()
			// Stop at EOF.
			if err == io.EOF {
				break
			}
			waitGroup.Add(1)
			go attempt(lines, row)
		}
	} else {
		for passFileScanner.Scan() {
			lines = append(lines, passFileScanner.Text())
		}
		for {
			row, err := hashFileReader.Read()
			// Stop at EOF.
			if err == io.EOF {
				break
			}
			waitGroup.Add(1)
			go attempt(lines, row)
		}
	}
	waitGroup.Wait()
	elapsed := time.Since(start)
	log.Printf("Cracking took %s, Total password attempt -> %d", elapsed, index)
}

func attempt(str []string, hashRow []string) {
	hasher := sha256.New()
	bytes := []byte{}
	//////////////////////////////////////////
	// SPECIAL CHARACTERS AND NUMBERS
	//////////////////////////////////////////
	for k := 0; k < len(specialCharacters); k++ {
		for j := 0; j < 10; j++ {
			for i := 0; i < len(str); i++ {
				// NORMAL
				hasher.Reset()
				hasher.Write([]byte(constantString + string(specialCharacters[k]) + str[i] + strconv.Itoa(j) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + str[i] + strconv.Itoa(j))
					founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + str[i] + strconv.Itoa(j) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + string(specialCharacters[k]) + strconv.Itoa(j) + str[i] + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + strconv.Itoa(j) + str[i])
					founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + strconv.Itoa(j) + str[i] + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + str[i] + strconv.Itoa(j) + string(specialCharacters[k]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + str[i] + strconv.Itoa(j) + string(specialCharacters[k]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + str[i] + strconv.Itoa(j) + string(specialCharacters[k]) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + str[i] + string(specialCharacters[k]) + strconv.Itoa(j) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + str[i] + string(specialCharacters[k]) + strconv.Itoa(j))
					founfPassFile.WriteString(hashRow[0] + " $-> " + str[i] + string(specialCharacters[k]) + strconv.Itoa(j) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strconv.Itoa(j) + str[i] + string(specialCharacters[k]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + str[i] + string(specialCharacters[k]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + str[i] + string(specialCharacters[k]) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strconv.Itoa(j) + string(specialCharacters[k]) + str[i] + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + string(specialCharacters[k]) + str[i])
					founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + string(specialCharacters[k]) + str[i] + "\n")
				}
				index++

				//UPPER
				hasher.Reset()
				hasher.Write([]byte(constantString + string(specialCharacters[k]) + strings.ToUpper(str[i]) + strconv.Itoa(j) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToUpper(str[i]) + strconv.Itoa(j))
					founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToUpper(str[i]) + strconv.Itoa(j) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + string(specialCharacters[k]) + strconv.Itoa(j) + strings.ToUpper(str[i]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + strconv.Itoa(j) + strings.ToUpper(str[i]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + strconv.Itoa(j) + strings.ToUpper(str[i]) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strings.ToUpper(str[i]) + strconv.Itoa(j) + string(specialCharacters[k]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strings.ToUpper(str[i]) + strconv.Itoa(j) + string(specialCharacters[k]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToUpper(str[i]) + strconv.Itoa(j) + string(specialCharacters[k]) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strings.ToUpper(str[i]) + string(specialCharacters[k]) + strconv.Itoa(j) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strings.ToUpper(str[i]) + string(specialCharacters[k]) + strconv.Itoa(j))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToUpper(str[i]) + string(specialCharacters[k]) + strconv.Itoa(j) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strconv.Itoa(j) + strings.ToUpper(str[i]) + string(specialCharacters[k]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToUpper(str[i]) + string(specialCharacters[k]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToUpper(str[i]) + string(specialCharacters[k]) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strconv.Itoa(j) + string(specialCharacters[k]) + strings.ToUpper(str[i]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + string(specialCharacters[k]) + strings.ToUpper(str[i]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + string(specialCharacters[k]) + strings.ToUpper(str[i]) + "\n")
				}
				index++

				//LOWER
				hasher.Reset()
				hasher.Write([]byte(constantString + string(specialCharacters[k]) + strings.ToLower(str[i]) + strconv.Itoa(j) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToLower(str[i]) + strconv.Itoa(j))
					founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToLower(str[i]) + strconv.Itoa(j) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + string(specialCharacters[k]) + strconv.Itoa(j) + strings.ToLower(str[i]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + strconv.Itoa(j) + strings.ToLower(str[i]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + strconv.Itoa(j) + strings.ToLower(str[i]) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strings.ToLower(str[i]) + strconv.Itoa(j) + string(specialCharacters[k]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strings.ToLower(str[i]) + strconv.Itoa(j) + string(specialCharacters[k]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToLower(str[i]) + strconv.Itoa(j) + string(specialCharacters[k]) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strings.ToLower(str[i]) + string(specialCharacters[k]) + strconv.Itoa(j) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strings.ToLower(str[i]) + string(specialCharacters[k]) + strconv.Itoa(j))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToLower(str[i]) + string(specialCharacters[k]) + strconv.Itoa(j) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strconv.Itoa(j) + strings.ToLower(str[i]) + string(specialCharacters[k]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToLower(str[i]) + string(specialCharacters[k]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToLower(str[i]) + string(specialCharacters[k]) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strconv.Itoa(j) + string(specialCharacters[k]) + strings.ToLower(str[i]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + string(specialCharacters[k]) + strings.ToLower(str[i]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + string(specialCharacters[k]) + strings.ToLower(str[i]) + "\n")
				}
				index++

				//TITLE
				hasher.Reset()
				hasher.Write([]byte(constantString + string(specialCharacters[k]) + strings.ToTitle(str[i]) + strconv.Itoa(j) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToTitle(str[i]) + strconv.Itoa(j))
					founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToTitle(str[i]) + strconv.Itoa(j) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + string(specialCharacters[k]) + strconv.Itoa(j) + strings.ToTitle(str[i]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + strconv.Itoa(j) + strings.ToTitle(str[i]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + strconv.Itoa(j) + strings.ToTitle(str[i]) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strings.ToTitle(str[i]) + strconv.Itoa(j) + string(specialCharacters[k]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strings.ToTitle(str[i]) + strconv.Itoa(j) + string(specialCharacters[k]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToTitle(str[i]) + strconv.Itoa(j) + string(specialCharacters[k]) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strings.ToTitle(str[i]) + string(specialCharacters[k]) + strconv.Itoa(j) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strings.ToTitle(str[i]) + string(specialCharacters[k]) + strconv.Itoa(j))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToTitle(str[i]) + string(specialCharacters[k]) + strconv.Itoa(j) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strconv.Itoa(j) + strings.ToTitle(str[i]) + string(specialCharacters[k]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToTitle(str[i]) + string(specialCharacters[k]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToTitle(str[i]) + string(specialCharacters[k]) + "\n")
				}
				index++

				hasher.Reset()
				hasher.Write([]byte(constantString + strconv.Itoa(j) + string(specialCharacters[k]) + strings.ToTitle(str[i]) + hashRow[1]))
				bytes = hasher.Sum(nil)
				if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
					fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + string(specialCharacters[k]) + strings.ToTitle(str[i]))
					founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + string(specialCharacters[k]) + strings.ToTitle(str[i]) + "\n")
				}
				index++
			}
		}
	}

	/////////////////////////////////////
	// ONLY NUMBERS [0-9] 1 DIGIT
	/////////////////////////////////////
	for j := 0; j < 10; j++ {
		for i := 0; i < len(str); i++ {
			// NORMAL
			hasher.Reset()
			hasher.Write([]byte(constantString + strconv.Itoa(j) + str[i] + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + str[i])
				founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + str[i] + "\n")
			}
			index++

			hasher.Reset()
			hasher.Write([]byte(constantString + str[i] + strconv.Itoa(j) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + str[i] + strconv.Itoa(j))
				founfPassFile.WriteString(hashRow[0] + " $-> " + str[i] + strconv.Itoa(j) + "\n")
			}
			index++

			//UPPER
			hasher.Reset()
			hasher.Write([]byte(constantString + strconv.Itoa(j) + strings.ToUpper(str[i]) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToUpper(str[i]))
				founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToUpper(str[i]) + "\n")
			}
			index++

			hasher.Reset()
			hasher.Write([]byte(constantString + strings.ToUpper(str[i]) + strconv.Itoa(j) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + strings.ToUpper(str[i]) + strconv.Itoa(j))
				founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToUpper(str[i]) + strconv.Itoa(j) + "\n")
			}
			index++

			//LOWER
			hasher.Reset()
			hasher.Write([]byte(constantString + strconv.Itoa(j) + strings.ToLower(str[i]) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToLower(str[i]))
				founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToLower(str[i]) + "\n")
			}
			index++

			hasher.Reset()
			hasher.Write([]byte(constantString + strings.ToLower(str[i]) + strconv.Itoa(j) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + strings.ToLower(str[i]) + strconv.Itoa(j))
				founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToLower(str[i]) + strconv.Itoa(j) + "\n")
			}
			index++

			//TITLE
			hasher.Reset()
			hasher.Write([]byte(constantString + strconv.Itoa(j) + strings.ToTitle(str[i]) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToTitle(str[i]))
				founfPassFile.WriteString(hashRow[0] + " $-> " + strconv.Itoa(j) + strings.ToTitle(str[i]) + "\n")
			}
			index++

			hasher.Reset()
			hasher.Write([]byte(constantString + strings.ToTitle(str[i]) + strconv.Itoa(j) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + strings.ToTitle(str[i]) + strconv.Itoa(j))
				founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToTitle(str[i]) + strconv.Itoa(j) + "\n")
			}
			index++
		}
	}

	/////////////////////////////////////
	// ONLY SPECIAL CHARACTERS
	/////////////////////////////////////
	for k := 0; k < len(specialCharacters); k++ {
		for i := 0; i < len(str); i++ {
			// NORMAL
			hasher.Reset()
			hasher.Write([]byte(constantString + string(specialCharacters[k]) + str[i] + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + str[i])
				founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + str[i] + "\n")
			}
			index++

			hasher.Reset()
			hasher.Write([]byte(constantString + str[i] + string(specialCharacters[k]) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + str[i] + string(specialCharacters[k]))
				founfPassFile.WriteString(hashRow[0] + " $-> " + str[i] + string(specialCharacters[k]) + "\n")
			}
			index++

			//UPPER
			hasher.Reset()
			hasher.Write([]byte(constantString + string(specialCharacters[k]) + strings.ToUpper(str[i]) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToUpper(str[i]))
				founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToUpper(str[i]) + "\n")
			}
			index++

			hasher.Reset()
			hasher.Write([]byte(constantString + strings.ToUpper(str[i]) + string(specialCharacters[k]) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + strings.ToUpper(str[i]) + string(specialCharacters[k]))
				founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToUpper(str[i]) + string(specialCharacters[k]) + "\n")
			}
			index++

			//LOWER
			hasher.Reset()
			hasher.Write([]byte(constantString + string(specialCharacters[k]) + strings.ToLower(str[i]) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToLower(str[i]))
				founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToLower(str[i]) + "\n")
			}
			index++

			hasher.Reset()
			hasher.Write([]byte(constantString + strings.ToLower(str[i]) + string(specialCharacters[k]) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + strings.ToLower(str[i]) + string(specialCharacters[k]))
				founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToLower(str[i]) + string(specialCharacters[k]) + "\n")
			}
			index++

			//TITLE
			hasher.Reset()
			hasher.Write([]byte(constantString + string(specialCharacters[k]) + strings.ToTitle(str[i]) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToTitle(str[i]))
				founfPassFile.WriteString(hashRow[0] + " $-> " + string(specialCharacters[k]) + strings.ToTitle(str[i]) + "\n")
			}
			index++

			hasher.Reset()
			hasher.Write([]byte(constantString + strings.ToTitle(str[i]) + string(specialCharacters[k]) + hashRow[1]))
			bytes = hasher.Sum(nil)
			if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
				fmt.Println(hashRow[0] + " $-> " + strings.ToTitle(str[i]) + string(specialCharacters[k]))
				founfPassFile.WriteString(hashRow[0] + " $-> " + strings.ToTitle(str[i]) + string(specialCharacters[k]) + "\n")
			}
			index++
		}
	}

	//////////////////////////////////
	// ONLY ENTRIES IN PASSWORD LIST
	//////////////////////////////////
	for i := 0; i < len(str); i++ {
		// NORMAL
		hasher.Reset()
		hasher.Write([]byte(constantString + str[i] + hashRow[1]))
		bytes = hasher.Sum(nil)
		if hex.EncodeToString(bytes[:])[0:32] == hashRow[2] {
			fmt.Println(hashRow[0] + " $-> " + str[i])
			founfPassFile.WriteString(hashRow[0] + " $-> " + str[i] + "\n")
		}
		index++
	}

	waitGroup.Done()
}

// print progress
func print() {
	start := time.Now()
	for {
		time.Sleep(5 * time.Second)
		elapsed := time.Since(start)
		fmt.Print("Tried ", index/1000000, " Million passwords!!!,")
		fmt.Printf(" elapsed %.2f sec\n", elapsed.Seconds())
	}
}

// count lines and determine optimum slice size
func lineCounter(r io.Reader) (int, error) {
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := r.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count, nil

		case err != nil:
			return count, err
		}
	}
}
