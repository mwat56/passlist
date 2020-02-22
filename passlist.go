/*
   Copyright © 2019 M.Watermann, 10247 Berlin, Germany
                   All rights reserved
               EMail : <support@mwat.de>
*/

package passlist

//lint:file-ignore ST1017 - I prefer Yoda conditions

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Deny sends an "Unauthorised" notice to the remote host.
//
//	`aRealm` is the symbolic name of the host/domain to protect.
//
//	`aWriter` is used by an HTTP handler to construct an HTTP response.
func Deny(aRealm string, aWriter http.ResponseWriter) {
	if 0 == len(aRealm) {
		aRealm = "Default"
	}
	aWriter.Header().Set("WWW-Authenticate", "Basic realm=\""+aRealm+"\"")
	http.Error(aWriter, "401 Unauthorised", http.StatusUnauthorized)
} // Deny()

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

var (
	// Default value to pepper the passwords.
	pwPepper = "github.com/mwat56/passlist"
)

// Pepper returns the value used for peppering passwords.
func Pepper() string {
	return pwPepper
} // Pepper()

// SetPepper changes the value used for peppering passwords.
//
// If the given `aPepper` value is an empty string it is ignored
// and the current pepper value remains unchanged.
//
//	`aPepper` is the new pepper value to use.
func SetPepper(aPepper string) {
	if 0 < len(aPepper) {
		pwPepper = aPepper
	}
} // SetPepper()

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

type (
	// `tUserMap` is a password list indexed by username
	tUserMap map[string]string

	// `tPassList` is the container for user map and filename.
	tPassList struct {
		filename string   // name of passwd file
		usermap  tUserMap // list of user/password pairs
	}
)

// TPassList holds the list of username/password values.
type TPassList tPassList

// Add inserts `aUser` with `aPassword` into the list.
//
// Before storing `aPassword` it gets peppered and hashed.
//
//	`aUser` is the username to use.
//
//	`aPassword` is the user's password to store.
func (ul *TPassList) Add(aUser, aPassword string) error {
	if 0 == len(aUser) {
		return errors.New("TPassList.Add(): missing username")
	}
	if 0 == len(aPassword) {
		return errors.New("TPassList.Add(): missing password")
	}
	//NOTE: the greater the cost factor below the slower it becomes
	hash, err := bcrypt.GenerateFromPassword([]byte(aPassword+pwPepper), 6)
	if nil == err {
		ul.usermap[aUser] = string(hash)
	}

	return err
} // Add()

// `add0()` inserts `aUser` with `aHashedPW` into the list.
//
//	`aUser` is the username to use.
//
//	`aHashedPW` is the user's hashed password to store.
func (ul *TPassList) add0(aUser, aHashedPW string) *TPassList {
	ul.usermap[aUser] = aHashedPW

	return ul
} // add0()

// Clear empties the internal data structure.
func (ul *TPassList) Clear() *TPassList {
	for user := range ul.usermap {
		delete(ul.usermap, user)
	}

	return ul
} // Clear()

// Exists returns `true` if `aUser` exists in the list,
// or `false` if not found.
//
//	`aUser` is the username to lookup.
func (ul *TPassList) Exists(aUser string) (rOK bool) {
	_, rOK = ul.usermap[aUser]

	return
} // Exists()

// Find returns the hashed password of `aUser` and `true`,
// or an empty string and `false` if not found.
//
//	`aUser` is the username to lookup.
func (ul *TPassList) Find(aUser string) (rHash string, rOK bool) {
	rHash, rOK = ul.usermap[aUser]

	return
} // Find()

// IsAuthenticated checks `aRequest` for authentication data,
// returning `nil` for successful authentication, or an `error` otherwise.
//
// On success the username/password are stored in the `aRequest.URL.User`
// structure to allow for other handlers checking its existence and act
// accordingly.
//
//	`aRequest` is an HTTP request received by a server.
func (ul *TPassList) IsAuthenticated(aRequest *http.Request) error {
	user, pass, ok := aRequest.BasicAuth()
	if !ok {
		return errors.New(`IsAuthenticated: missing authentication data`)
	}
	pwHash, ok := ul.Find(user)
	if !ok {
		return errors.New(`IsAuthenticated: unknown user`)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(pass+pwPepper)); nil != err {
		return fmt.Errorf(`IsAuthenticated: %w`, err)
	}

	// Store the user info so others can check for it
	aRequest.URL.User = url.UserPassword(user, pwHash)

	return nil
} // IsAuthenticated()

// Len returns the actual length of the userlist.
func (ul *TPassList) Len() int {
	return len(ul.usermap)
} // Len()

// List returns a list of all usernames in the list.
func (ul *TPassList) List() (rList []string) {
	if 0 == len(ul.usermap) {
		return
	}
	for user := range ul.usermap {
		rList = append(rList, user)
	}
	sort.Slice(rList, func(i, j int) bool {
		return (rList[i] < rList[j]) // ascending
	})

	return
} // List()

// Load reads the password file named in `LoadPasswords()` or
// `NewList()` replacing any older list's contents with the file's.
func (ul *TPassList) Load() error {
	if 0 == len(ul.filename) {
		return errors.New("Load: missing filename")
	}

	file, err := os.Open(ul.filename)
	if nil != err {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	_, err = ul.Clear().read(scanner)

	return err
} // Load()

// Matches checks whether `aPassword` of `aUser` matches
// the stored password.
//
//	`aUser` the username to lookup.
//
//	`aPassword` the (unhashed) password to check.
func (ul *TPassList) Matches(aUser, aPassword string) (rOK bool) {
	hash1, ok := ul.usermap[aUser]
	if !ok {
		return
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash1), []byte(aPassword))

	return (nil == err)
} // Matches()

// `read()` parses the a file using `aScanner`, returning
// the number of bytes read and a possible error.
//
// This method reads one line of the file at a time skipping both
// empty lines and comments (identified by '#' or ';' at line start).
func (ul *TPassList) read(aScanner *bufio.Scanner) (rRead int, rErr error) {
	for lineRead := aScanner.Scan(); lineRead; lineRead = aScanner.Scan() {
		line := aScanner.Text()
		rRead += len(line) + 1 // add trailing LF

		line = strings.TrimSpace(line)
		if 0 == len(line) {
			// Skip blank lines
			continue
		}
		if ';' == line[0] || '#' == line[0] {
			// Skip comment lines
			continue
		}

		if parts := strings.SplitN(line, ":", 2); 2 == len(parts) {
			ul.add0(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	rErr = aScanner.Err()

	return
} // read()

// Remove deletes `aUser` from the list.
//
//	`aUser` is the username to remove.
func (ul *TPassList) Remove(aUser string) *TPassList {
	delete(ul.usermap, aUser)

	return ul
} // Remove()

// Store writes the list to `aFilename`, truncating the file
// if it already exists.
//
// The method returns the number of bytes written and an error, if any.
func (ul *TPassList) Store() (int, error) {
	if 0 == len(ul.filename) {
		return 0, errors.New("TPassList.Store(): missing filename")
	}
	// To keep the file-open time as small as possible we
	// prepare the data to write beforehand:
	s := []byte(ul.String())

	file, err := os.OpenFile(ul.filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0660) // #nosec G302
	if err != nil {
		return 0, err
	}
	defer file.Close()

	return file.Write(s)
} // Store()

// String returns the list as a single, LF-separated string.
func (ul *TPassList) String() string {
	if 0 == len(ul.usermap) {
		return ""
	}
	var list []string
	for name, pass := range ul.usermap {
		list = append(list, name+":"+pass)
	}
	sort.Slice(list, func(i, j int) bool {
		return (list[i] < list[j])
	})

	return strings.Join(list, "\n") + "\n"
} // String()

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

type (
	// TAuthDecider is an interface deciding whether a given URL
	// needs authentication or not.
	TAuthDecider interface {
		// NeedAuthentication returns `true` if authentication
		// is required, or `false` otherwise.
		//
		//	`aRequest` holds the URL to check.
		NeedAuthentication(aRequest *http.Request) bool
	}

	// TAuthSkipper provides a `TAuthDecider` implementation
	// always returning `false`.
	TAuthSkipper int

	// TAuthNeeder provides a `TAuthDecider` implementation
	// always returning `true`.
	TAuthNeeder int
)

// NeedAuthentication returns `false` thus skipping any authentication.
func (ad TAuthSkipper) NeedAuthentication(aRequest *http.Request) bool {
	return false
} // NeedAuthentication

// NeedAuthentication returns `true` thus requiring authentication
// for any URL.
func (ad TAuthNeeder) NeedAuthentication(aRequest *http.Request) bool {
	return true
} // NeedAuthentication

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// LoadPasswords reads the given `aFilename` returning a `TUserList`
// instance filled with data read from the password file and a possible
// error condition.
//
// This function reads one line at a time of the password file skipping
// both empty lines and comments (identified by `#` or `;` at line start).
//
//	`aFilename` is the name of the password file to read.
func LoadPasswords(aFilename string) (*TPassList, error) {
	ul := NewList(aFilename)

	return ul, ul.Load()
} // LoadPasswords()

// NewList returns a new `TUserList` instance.
//
//	`aFilename` is the name of the password file to use for
// `Load()` and `Store()`
func NewList(aFilename string) (rList *TPassList) {
	if 0 < len(aFilename) {
		rList = &TPassList{
			filename: aFilename,
			usermap:  make(tUserMap, 64),
		}
	}

	return
} // NewList()

// Wrap returns a handler function that includes authentication,
// wrapping the given `aHandler` and calling it internally.
//
//	`aHandler` responds to the actual HTTP request; this is
// the handler to be called after successful authentication.
//
//	`aRealm` is the symbolic name of the domain/host to protect.
//
//	`aPasswdFile` is the name of the password file to use.
func Wrap(aHandler http.Handler, aRealm, aPasswdFile string, aAuthDecider TAuthDecider) http.Handler {
	ul, err := LoadPasswords(aPasswdFile)
	if nil != err {
		log.Printf("passlist.Wrap(): %v\nAUTHENTICATION DISABLED!", err)
		// we can't do anything about it, so we skip
		// the whole authentication procedure
		return aHandler
	}

	return http.HandlerFunc(
		func(aWriter http.ResponseWriter, aRequest *http.Request) {
			if aAuthDecider.NeedAuthentication(aRequest) {
				if err := ul.IsAuthenticated(aRequest); nil != err {
					Deny(aRealm, aWriter)
					return
				}
			}
			// call the original handler
			aHandler.ServeHTTP(aWriter, aRequest)
		})
} // Wrap()

/* _EoF_ */
