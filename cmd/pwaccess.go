/*
   Copyright © 2019, 2020 M.Watermann, 10247 Berlin, Germany
                   All rights reserved
                EMail : <support@mwat.de>
*/

package main

//lint:file-ignore ST1017 - I prefer Yoda conditions

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mwat56/passlist"
)

type (
	// `tArgumentList` is the list type returned by `getArguments()`
	// to deliver the actual commandline arguments back to the caller.
	tArgumentList map[string]string
)

// `getArguments()` reads the commandline arguments and returns a list of them.
func getArguments() tArgumentList {
	var (
		fileStr, addStr, chkStr, delStr, updStr string
		lstBool, quietBool                      bool
	)

	flag.StringVar(&addStr, "add", "",
		"<username> name of the user to add to the file (prompting for the password)")
	flag.StringVar(&chkStr, "chk", "",
		"<username> name of the user whose pass to check (prompting for the password)")
	flag.StringVar(&delStr, "del", "",
		"<username> name of the user to remove from the file")
	flag.StringVar(&fileStr, "file", "pwaccess.db",
		"<filename> name of the passwordfile to use")
	flag.BoolVar(&lstBool, "lst", false,
		"list all current usernames from the list")
	flag.BoolVar(&quietBool, "q", false,
		"whether to be quiet or not (suppress screen output)")
	flag.StringVar(&updStr, "upd", "",
		"<username> name of the user to update in the file (prompting for the password)")

	flag.Usage = showHelp
	flag.Parse()

	result := make(tArgumentList)
	if 0 < len(fileStr) {
		fileStr, _ = filepath.Abs(fileStr)
		result["filename"] = fileStr
	}
	if 0 < len(addStr) {
		result["add"] = addStr
	}
	if 0 < len(chkStr) {
		result["chk"] = chkStr
	}
	if 0 < len(delStr) {
		result["del"] = delStr
	}
	if lstBool {
		result["lst"] = "true"
	}
	if quietBool {
		result["quiet"] = "true"
	}
	if 0 < len(updStr) {
		result["upd"] = updStr
	}
	return result
} // getArguments()

// run is the main program, externalised for easier testing.
func run(aArgs tArgumentList) {
	if q, ok := aArgs["quiet"]; ok {
		passlist.Verbose = ("true" != q)
	}
	fn := aArgs["filename"]

	if adduser, ok := aArgs["add"]; ok {
		passlist.AddUser(adduser, fn)
	}

	if chkuser, ok := aArgs["chk"]; ok {
		passlist.CheckUser(chkuser, fn)
	}

	if deluser, ok := aArgs["del"]; ok {
		passlist.DeleteUser(deluser, fn)
	}

	if lst, ok := aArgs["lst"]; ok && ("true" == lst) {
		passlist.ListUsers(fn)
	}

	if upduser, ok := aArgs["upd"]; ok {
		passlist.UpdateUser(upduser, fn)
	}
} // run()

// showHelp lists the commandline options to `Stderr`.
func showHelp() {
	fmt.Fprintf(os.Stderr, "\nUsage: %s [OPTIONS]\n\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, "\n")
} // showHelp()

// Application main routine …
func main() {
	run(getArguments())

	// Reaching this point of execution means:
	// there haven't been enough cmdline options.
	showHelp()
} // main()

/* _EoF_ */
