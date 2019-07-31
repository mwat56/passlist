/**
    Copyright © 2019  M.Watermann, 10247 Berlin, Germany
                All rights reserved
            EMail : <support@mwat.de>
**/

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mwat56/passlist"
	"golang.org/x/crypto/ssh/terminal"
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
		"whether to be quiet or not (suppress non-essential messages)")
	flag.StringVar(&updStr, "upd", "",
		"<username> name of the user to update in the file (prompting for the password)")

	flag.Usage = showHelp
	flag.Parse()

	result := make(tArgumentList)
	if 0 < len(fileStr) {
		fileStr, _ := filepath.Abs(fileStr)
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

// `readPassword()` asks the user to input a password on the commandline.
func readPassword(aRepeat, aQuiet bool) (rPass string) {
	var (
		pw1, pw2 string
	)
	for {
		fmt.Print("\n password: ")
		if bPW, err := terminal.ReadPassword(int(syscall.Stdin)); err == nil {
			if 0 < len(bPW) {
				pw1 = string(bPW)
			} else {
				if !aQuiet {
					fmt.Println("\n\tempty password not accepted")
				}
				continue
			}
		}
		if aRepeat {
			fmt.Print("\nrepeat pw: ")
			if bPW, err := terminal.ReadPassword(int(syscall.Stdin)); err == nil {
				if 0 < len(bPW) {
					pw2 = string(bPW)
				} else {
					if !aQuiet {
						fmt.Println("\n\tempty password not accepted")
					}
					continue
				}
			}
		} else {
			pw2 = pw1
		}
		if pw1 == pw2 {
			break
		}
		fmt.Fprintln(os.Stderr, "\n\tthe two passwords don't match")
	}
	fmt.Print("\n")

	return pw1
} // readPassword()

// run is the main program, externalised for easier testing.
func run(aArgs tArgumentList) (rExit bool) {
	var (
		quiet bool
	)
	if q, ok := aArgs["quiet"]; ok {
		quiet = ("true" == q)
	}

	fn, ok := aArgs["filename"]
	if !ok {
		fmt.Fprintln(os.Stderr, "'filename' argument missing")
		return
	}

	ul := passlist.NewList(fn)
	if nil == ul {
		fmt.Fprintln(os.Stderr, "can't create userlist")
		return
	}

	if _, ok := aArgs["lst"]; ok {
		if err := ul.Load(); nil != err {
			fmt.Fprintf(os.Stderr, "\n\tcan't load list '%s'", fn)
			return
		}
		fmt.Fprintln(os.Stdout, strings.Join(ul.List(), "\n"))

		return true
	}

	if adduser, ok := aArgs["add"]; ok {
		_ = ul.Load() // ignore error since the file might not exist yet
		if ok := ul.Exists(adduser); ok {
			fmt.Fprintf(os.Stderr, "\n\t'%s' already exists in list\n", adduser)
			return
		}
		pw := readPassword(true, quiet)
		if err := ul.Add(adduser, pw); nil != err {
			fmt.Fprintf(os.Stderr, "\n\tcan't add '%s' to list: %v\n", adduser, err)
			return
		}
		if _, err := ul.Store(); nil != err {
			fmt.Fprintf(os.Stderr, "\n\tcan't store modified list: %v\n", err)
			return
		}
		if !quiet {
			fmt.Printf("\tadded '%s' to list\n\n", adduser)
		}
		return true
	}

	if chkuser, ok := aArgs["chk"]; ok {
		if err := ul.Load(); nil != err {
			fmt.Fprintf(os.Stderr, "\n\tcan't load list '%s'\n", fn)
			return
		}
		pw := readPassword(false, quiet)
		ok := ul.Matches(chkuser, pw)
		if !quiet {
			if ok {
				pw = "successful"
			} else {
				pw = "failed"
			}
			fmt.Printf("\n\t'%s' password check %s\n\n", chkuser, pw)
		}
		return true
	}

	if deluser, ok := aArgs["del"]; ok {
		if err := ul.Load(); nil != err {
			fmt.Fprintf(os.Stderr, "\n\tcan't load list '%s'\n", fn)
			return
		}
		if ok := ul.Exists(deluser); !ok {
			fmt.Fprintf(os.Stderr, "\n\tcan't find '%s' in list\n", deluser)
			return
		}
		if _, err := ul.Remove(deluser).Store(); nil != err {
			fmt.Fprintf(os.Stderr, "\n\tcan't store modified list: %v\n", err)
			return
		}
		if !quiet {
			fmt.Printf("\n\tremoved '%s' from list\n\n", deluser)
		}
		return true
	}

	if upduser, ok := aArgs["upd"]; ok {
		if err := ul.Load(); nil != err {
			fmt.Fprintf(os.Stderr, "\n\tcan't load list '%s'\n", fn)
			return
		}
		if ok := ul.Exists(upduser); !ok {
			fmt.Fprintf(os.Stderr, "\n\tcan't find '%s' in list\n", upduser)
			return
		}
		pw := readPassword(true, quiet)
		if err := ul.Add(upduser, pw); nil != err {
			fmt.Fprintf(os.Stderr, "\n\tcan't update '%s': %v\n", upduser, err)
			return
		}
		if _, err := ul.Store(); nil != err {
			fmt.Fprintf(os.Stderr, "\n\tcan't store modified list: %v\n", err)
			return
		}
		if !quiet {
			fmt.Printf("\tupdated user '%s' in list\n\n", upduser)
		}
		return true
	}

	return
} // run()

// showHelp lists the commandline options to `Stderr`.
func showHelp() {
	fmt.Fprintf(os.Stderr, "\nUsage: %s [OPTIONS]\n\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, "\n")
} // showHelp()

// Application main routine …
func main() {
	if run(getArguments()) {
		os.Exit(0)
	}

	// Reaching this point of execution means:
	// there haven't been enough cmdline options.
	showHelp()
} // main()

/* _EoF_ */
