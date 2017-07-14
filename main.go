package main

import "os"

func main() {
	e := convert(os.Stdin, os.Stdout)
	if e != nil {
		panic(e)
	}
}
