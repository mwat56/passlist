/*
Copyright © 2019, 2025 M.Watermann, 10247 Berlin, Germany

	    All rights reserved
	EMail : <support@mwat.de>
*/
package passlist

/*
 * This file provides functions to maintain the user/password list
 * from the commandline.
 */

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

//lint:file-ignore ST1017 - I prefer Yoda conditions

var (
	// `Verbose` determines whether or not to print some output
	// when executing the commandline functions.
	Verbose = true
)

// --------------------------------------------------------------------------

// `AddUser()` reads a password for `aUser` from the commandline and adds
// it to `aFilename`.
//
// NOTE: This function does not return but terminates the program with
// error code `0` (zero) if successful, or `1` (one) otherwise.
//
// Parameters:
//   - `aUser`: The username to add to the password file.
//   - `aFilename`: The name of the password file to use.
func AddUser(aUser, aFilename string) {
	if aUser = strings.TrimSpace(aUser); "" == aUser {
		if Verbose {
			fmt.Fprintf(os.Stderr, "can't add empty username to list\n")
		}
		os.Exit(1)
	}
	if aFilename = strings.TrimSpace(aFilename); "" == aFilename {
		if Verbose {
			fmt.Fprintf(os.Stderr, "missing/empty file name\n")
		}
		os.Exit(1)
	}

	ul := New(aFilename) // never `nil` since `aFilename` is not empty now
	_ = ul.Load()        // ignore error since the file might not exist yet
	if ul.Exists(aUser) {
		if Verbose {
			fmt.Fprintf(os.Stderr, "\n\t'%s' already exists in list\n", aUser)
		}
		os.Exit(1)
	}

	pw := readPassword(true)
	err := ul.Add(aUser, pw)
	if nil != err {
		if Verbose {
			fmt.Fprintf(os.Stderr, "\n\tcan't add '%s' to list: %v\n", aUser, err)
		}
		os.Exit(1)
	}

	if _, err = ul.Store(); nil != err {
		if Verbose {
			fmt.Fprintf(os.Stderr, "\n\tcan't store modified list: %v\n", err)
		}
		os.Exit(1)
	}

	if Verbose {
		fmt.Printf("\tadded '%s' to list\n\n", aUser)
	}

	os.Exit(0)
} // AddUser()

// `CheckUser()` reads a password for `aUser` from the commandline and
// compares it with the one stored in `aFilename`.
//
// NOTE: This function does not return but terminates the program with
// error code `0` (zero) if successful, or `1` (one) otherwise.
//
// Parameters:
//   - `aUser`: The username to check with the password file.
//   - `aFilename`: The name of the password file to use.
func CheckUser(aUser, aFilename string) {
	ul := readUser(aUser, aFilename)
	pw := readPassword(false)
	exitCode := 0

	if ul.Matches(aUser, pw) {
		pw = "successful"
	} else {
		exitCode, pw = 1, "failed"
	}

	if Verbose {
		fmt.Printf("\n\t'%s' password check %s\n\n", aUser, pw)
	}

	os.Exit(exitCode)
} // CheckUser()

// `DeleteUser()` removes the entry for `aUser` from the password list
// in `aFilename`.
//
// NOTE: This function does not return but terminates the program with
// error code `0` (zero) if successful, or `1` (one) otherwise.
//
// Parameters:
//   - `aUser`: The username to delete from the password file.
//   - `aFilename`: The name of the password file to use.
func DeleteUser(aUser, aFilename string) {
	ul := readUser(aUser, aFilename)

	if _, err := ul.Remove(aUser).Store(); nil != err {
		if Verbose {
			fmt.Fprintf(os.Stderr, "\n\tcan't store modified list: %v\n", err)
		}
		os.Exit(1)
	}

	if Verbose {
		fmt.Printf("\n\tremoved '%s' from list\n\n", aUser)
	}

	os.Exit(0)
} // DeleteUser()

// `ListUsers()` reads `aFilename` and lists all users stored in there.
//
// NOTE: This function does not return but terminates the program with
// error code `0` (zero) if successful, or `1` (one) otherwise.
//
// Parameters:
//   - `aFilename`: The name of the password file to use.
func ListUsers(aFilename string) {
	ul := loadList(aFilename)
	list := ul.List()
	if 0 == len(list) {
		if Verbose {
			fmt.Fprintf(os.Stderr, "no users found in password list '%s'\n", aFilename)
		}
		os.Exit(1)
	}
	fmt.Println(strings.Join(list, "\n") + "\n")

	os.Exit(0)
} // ListUsers()

// `loadList()` returns a new `TPassList` instance.
//
// NOTE: This function terminates in case of errors and only returns
// with a valid `TPassList` instance.
//
// Parameters:
//   - `aFilename`: The name of the password file to use.
//
// Returns:
//   - `*TPassList`: A new `TPassList` instance
func loadList(aFilename string) (ul *TPassList) {
	if aFilename = strings.TrimSpace(aFilename); "" == aFilename {
		if Verbose {
			fmt.Fprintf(os.Stderr, "missing/empty file name\n")
		}
		os.Exit(1)
	}

	ul, err := LoadPasswords(aFilename)
	if nil != err {
		if Verbose {
			fmt.Fprint(os.Stderr, "can't open/create password list »", aFilename, "«\n")
		}
		os.Exit(1)
	}

	return ul
} // loadList()

// `readPassword()` asks the user to input a password on the commandline.
//
// Parameters:
//   - `aRepeat`: Decide whether to ask for a password repeat or not.
//
// Returns:
//   - `string`: The user's new password.
func readPassword(aRepeat bool) (rPass string) {
	var ( // re-use variables within the loop below
		bPW []byte
		err error
		pw2 string
	)

	for {
		fmt.Print("\n password: ")
		if bPW, err = term.ReadPassword(syscall.Stdin); nil == err {
			if bPW = []byte(strings.TrimSpace(string(bPW))); 0 == len(bPW) {
				fmt.Println("\n\tempty password not accepted")
				continue
			}
			rPass = string(bPW)
		}

		if aRepeat {
			fmt.Print("\nrepeat pw: ")
			if bPW, err = term.ReadPassword(syscall.Stdin); nil == err {
				if bPW = []byte(strings.TrimSpace(string(bPW))); 0 == len(bPW) {
					fmt.Println("\n\tempty password not accepted")
					continue
				}
				pw2 = string(bPW)
			}
		} else {
			break
		}
		if rPass == pw2 {
			break
		}

		fmt.Fprintln(os.Stderr, "\n\tthe two passwords don't match")
	}
	fmt.Print("\n")

	return
} // readPassword()

// `readUser()` checks whether `aUser` exists in the password list
// `aFilename` and returns the list if so.
//
// NOTE: If `aUser` doesn't exist the function terminates the program
// with error code `1` (one).
//
// Parameters:
//   - `aUser`: The username to check with the password file.
//   - `aFilename`: The name of the password file to use.
//
// Returns:
//   - `*TPassList`: The password list.
func readUser(aUser, aFilename string) *TPassList {
	ul := loadList(aFilename)
	if !ul.Exists(aUser) {
		if Verbose {
			fmt.Fprintf(os.Stderr, "\n\tcan't find '%s' in list\n", aUser)
		}
		os.Exit(1)
	}

	return ul
} // readUser()

// `UpdateUser()` reads a password for `aUser` from the commandline and
// updates the entry in the password list `aFilename`.
//
// NOTE: This function does not return but terminates the program with
// error code `0` (zero) if successful, or `1` (one) otherwise.
//
// Parameters:
//   - `aUser`: The username to update in the password file.
//   - `aFilename`: The name of the password file to use.
func UpdateUser(aUser, aFilename string) {
	ul := readUser(aUser, aFilename)
	pw := readPassword(true)
	err := ul.Add(aUser, pw)
	if nil != err {
		if Verbose {
			fmt.Fprintf(os.Stderr, "\n\tcan't update '%s': %v\n", aUser, err)
		}
		os.Exit(1)
	}

	if _, err = ul.Store(); nil != err {
		if Verbose {
			fmt.Fprintf(os.Stderr, "\n\tcan't store modified list: %v\n", err)
		}
		os.Exit(1)
	}

	if Verbose {
		fmt.Printf("\tupdated user '%s' in list\n\n", aUser)
	}

	os.Exit(0)
} // UpdateUser()

/* _EoF_ */
