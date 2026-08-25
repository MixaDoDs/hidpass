package main

import (
	"fmt"
	"os"

	"hidpass/internal/app"
)

func main() {
	a, err := app.Default()
	if err == nil {
		err = a.Run(os.Args[1:])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hidpass:", err)
		os.Exit(1)
	}
}
