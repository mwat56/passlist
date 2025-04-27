/*
Copyright © 2019, 2025  M.Watermann, 10247 Berlin, Germany

	    All rights reserved
	EMail : <support@mwat.de>
*/
package passlist

import (
	"bufio"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	se "github.com/mwat56/sourceerror"
	"golang.org/x/crypto/bcrypt"
)

//lint:file-ignore ST1017 - I prefer Yoda conditions

// `Deny()` sends an "Unauthorised" notice to the remote host.
//
// Parameters:
//   - `aRealm`: The symbolic name of the host/domain to protect.
//   - `aWriter`: Used by an HTTP handler to construct an HTTP response.
func Deny(aRealm string, aWriter http.ResponseWriter) {
	if aRealm = strings.TrimSpace(aRealm); "" == aRealm {
		aRealm = "Default"
	}

	aWriter.Header().Set("WWW-Authenticate", "Basic realm=\""+aRealm+"\"")
	http.Error(aWriter, "401 Unauthorised", http.StatusUnauthorized)
} // Deny()

// --------------------------------------------------------------------------

const (
	// Cost factor used for hashing passwords.
	pwCost = 6
)

var (
	// Default value to pepper the passwords.
	pwPepper = "github.com/mwat56/passlist" //#nosec G101
)

// Pepper returns the value used for peppering passwords.
//
// Returns:
//   - `string`: The uses pepper.
func Pepper() string {
	return pwPepper
} // Pepper()

// `SetPepper()` changes the value used for peppering passwords.
//
// If the given `aPepper` value is an empty string it is ignored
// and the current pepper value remains unchanged.
//
// Parameters:
//   - `aPepper`: The new pepper value to use.
func SetPepper(aPepper string) {
	if 0 < len(aPepper) {
		pwPepper = aPepper
	}
} // SetPepper()

// --------------------------------------------------------------------------

type (
	// `tUserMap` is a password list indexed by username.
	tUserMap map[string]string

	// `tPassList` is the container for user map and filename.
	tPassList struct {
		filename string   // name of passwd file
		usermap  tUserMap // list of user/password pairs
	}

	// TPassList holds the list of username/password values.
	TPassList tPassList
)

// --------------------------------------------------------------------------
// Constructor functions

// `LoadPasswords()` reads the given `aFilename` returning a `TUserList`
// instance filled with data read from the password file and a
// possible error condition.
//
// This function reads one line at a time of the password file
// skipping both empty lines and comments (identified by `#` or
// `;` at a line's start).
//
// Parameters:
//   - `aFilename`: The name of the password file to use for [Load] and [Store].
//
// Returns:
//   - `*TPassList`: A new `TUserList` instance
//   - `error`: A possible error during processing the request.
func LoadPasswords(aFilename string) (*TPassList, error) {
	if 0 == len(aFilename) {
		return nil, se.New(errors.New(`missing file name`), 2)
	}
	ul := New(aFilename)

	return ul, ul.Load()
} // LoadPasswords()

// `New()` returns a new `TUserList` instance.
//
// Parameters:
//   - `aFilename` The name of the password file to use for [Load] and [Store].
//
// Returns:
//   - `*TPassList`: A new `TUserList` instance
func New(aFilename string) *TPassList {
	if 0 == len(aFilename) {
		return nil
	}

	return &TPassList{
		filename: aFilename,
		usermap:  make(tUserMap, 64),
	}
} // New()

// `NewList()` returns a new `TUserList` instance.
//
// Deprecated: Use [New] instead.
func NewList(aFilename string) *TPassList {
	return New(aFilename)
} // NewList()

// --------------------------------------------------------------------------
// TPosting methods

// `Add()` inserts `aUser` with `aPassword` into the list.
//
// Before storing `aPassword` it gets peppered and hashed.
//
// Parameters:
//   - `aUser`: The new user's name to use.
//   - `aPassword`: The user's password to store.
//
// Returns:
//   - `error`: A possible error during processing the request.
func (ul *TPassList) Add(aUser, aPassword string) error {
	if 0 == len(aUser) {
		return se.New(errors.New("missing username"), 1)
	}
	if 0 == len(aPassword) {
		return se.New(errors.New("missing password"), 1)
	}

	//NOTE: the greater the cost factor below the slower it becomes
	hash, err := bcrypt.GenerateFromPassword([]byte(aPassword+pwPepper), pwCost)
	if nil != err {
		return se.New(err, 2)
	}
	ul.usermap[aUser] = string(hash)

	return nil
} // Add()

// `add0()` inserts `aUser` with `aHashedPW` into the list.
//
// Parameters:
//   - `aUser` The username to use.
//   - `aHashedPW` The user's password hash to store.
//
// Returns:
//   - `*TPassList`: The update list.
func (ul *TPassList) add0(aUser, aHashedPW string) *TPassList {
	ul.usermap[aUser] = aHashedPW

	return ul
} // add0()

// `Clear()` empties the internal data structure.
//
// Returns:
//   - `*TPassList`: The cleaned list.
func (ul *TPassList) Clear() *TPassList {
	for user := range ul.usermap {
		delete(ul.usermap, user)
	}

	return ul
} // Clear()

// `Exists()` returns `true` if `aUser` exists in the list,
// or `false` if not found.
//
// Parameters:
//   - `aUser`: The username to lookup.
//
// Returns:
//   - `bool`: `true` if the user as was found, or `false` otherwise.
func (ul *TPassList) Exists(aUser string) bool {
	_, ok := ul.usermap[aUser]

	return ok
} // Exists()

// `Find()` returns the hashed password of `aUser` and `nil`,
// or an error if not found.
//
// Parameters:
//   - `aUser`: The username to lookup.
//
// Returns:
//   - `string`: The user's password hash.
//   - `error`: `nil` if the user as was found, or an error otherwise.
func (ul *TPassList) Find(aUser string) (string, error) {
	hash, ok := ul.usermap[aUser]
	if !ok {
		return "", se.New(errors.New("unknown user"), 2)
	}

	return hash, nil
} // Find()

// `IsAuthenticated()` checks `aRequest` for authentication data,
// returning `nil` for successful authentication, or an `error` otherwise.
//
// On success the username/password are stored in the `aRequest.URL.User`
// structure to allow for other handlers checking its existence and act
// accordingly.
//
// Parameters:
//   - `aRequest` The HTTP request received by a server.
//
// Returns:
//   - `error`: A possible error during processing the request.
func (ul *TPassList) IsAuthenticated(aRequest *http.Request) error {
	user, pass, ok := aRequest.BasicAuth()
	if !ok {
		return se.New(errors.New(`missing authentication data`), 2)
	}

	pwHash, err := ul.Find(user)
	if nil != err {
		return err // already wrapped
	}

	if err = bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(pass+pwPepper)); nil != err {
		return se.New(err, 1)
	}

	// Store the user info so others can check for it
	aRequest.URL.User = url.UserPassword(user, pwHash)

	return nil
} // IsAuthenticated()

// `Len()` returns the number of entries in the user list.
//
// Returns:
//   - `int`: The list's number of entries.
func (ul *TPassList) Len() int {
	return len(ul.usermap)
} // Len()

// `List()` returns a list of all usernames in the list.
//
// Returns:
//   - `[]string`: The users stored in this list.
func (ul *TPassList) List() []string {
	lLen := len(ul.usermap)
	if 0 == lLen {
		return []string{}
	}

	list := make([]string, 0, lLen)
	for user := range ul.usermap {
		list = append(list, user)
	}

	slices.Sort(list) // ascending

	return list
} // List()

// `Load()` reads the password file named in `[LoadPasswords]` or
// `[New]` replacing any older list's contents with that file's.
//
// Returns:
//   - `error`: A possible error during processing the request.
func (ul *TPassList) Load() error {
	if 0 == len(ul.filename) {
		return se.New(errors.New("missing filename"), 1)
	}

	file, err := os.Open(ul.filename)
	if nil != err {
		return se.New(err, 2)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	_, err = ul.Clear().read(scanner)

	return err // already wrapped
} // Load()

// `Matches()` checks whether `aPassword` of `aUser` matches
// the stored user/password pair.
//
// Parameters:
//   - `aUser`: The username to lookup.
//   - `aPassword`: The (unhashed) password to check.
//
// Returns:
//   - `bool`: `true` if a match was found, or `false` otherwise.
func (ul *TPassList) Matches(aUser, aPassword string) bool {
	pwHash, ok := ul.usermap[aUser]
	if !ok {
		return ok
	}
	err := bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(aPassword+pwPepper))

	return (nil == err)
} // Matches()

// `read()` parses the a file using `aScanner`, returning
// the number of bytes read and a possible error.
//
// This method reads one line of the file at a time skipping both
// empty lines and comments (identified by '#' or ';' at line start).
//
// Parameters:
//   - `aScanner`: The text scanner using the contents of the user file.
//
// Returns:
//   - `int`: The number of bytes read.
//   - `error`: A possible error during processing the request.
func (ul *TPassList) read(aScanner *bufio.Scanner) (rRead int, rErr error) {
	for next := aScanner.Scan(); next; next = aScanner.Scan() {
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
	if rErr = aScanner.Err(); nil != rErr {
		rErr = se.New(rErr, 1)
	}

	return
} // read()

// `Remove()` deletes `aUser` from the list.
//
// Parameters:
//   - `aUser`: The username to remove.
//
// Returns:
//   - `*TPassList`: The updated list.
func (ul *TPassList) Remove(aUser string) *TPassList {
	delete(ul.usermap, aUser)

	return ul
} // Remove()

// `Store()` writes the list to a file, truncating the file
// if it already exists.
//
// The method uses the filename given to the [LoadPasswords] or
// [New] function.
//
// Returns:
//   - `int`: The number of bytes written.
//   - `error`: A possible error during processing the request.
func (ul *TPassList) Store() (int, error) {
	if 0 == len(ul.filename) {
		return 0, se.New(errors.New("missing filename"), 1)
	}
	// To keep the file-open time as small as possible we
	// prepare the data to write beforehand:
	s := []byte(ul.String())

	file, err := os.OpenFile(ul.filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0660) // #nosec G302
	if nil != err {
		return 0, se.New(err, 2)
	}
	defer file.Close()

	return file.Write(s)
} // Store()

// `String()` returns the list as a single, LF-separated string.
//
// Returns:
//   - `string`: A stringified representation of the list.
func (ul *TPassList) String() string {
	if 0 == len(ul.usermap) {
		return ""
	}

	list := make([]string, 0, len(ul.usermap))
	for name, pass := range ul.usermap {
		list = append(list, name+":"+pass)
	}
	slices.Sort(list)

	return strings.Join(list, "\n") + "\n"
} // String()

// --------------------------------------------------------------------------

type (
	// `IAuthDecider` is an interface aiming to decide whether a given
	// URL needs authentication or not.
	IAuthDecider interface {
		// `NeedAuthentication()` returns `true` if authentication
		// is required, or `false` otherwise.
		//
		// Parameters:
		//   - `aRequest` holds the URL to check.
		//
		// Returns:
		//   - `bool`: `true` if authentication is required. or `false` otherwise.
		NeedAuthentication(aRequest *http.Request) bool
	}

	// `TAuthNeeder` provides an `IAuthDecider` implementation
	// always returning `true`.
	TAuthNeeder struct{}

	// `TAuthSkipper` provides an `IAuthDecider` implementation
	// always returning `false`.
	TAuthSkipper struct{}
)

// `NeedAuthentication()` returns `true` thus requiring authentication
// for any URL.
//
// Parameters:
//   - `aRequest`: holds the URL to check.
//
// Returns:
//   - `bool`: `true` (always).
func (an TAuthNeeder) NeedAuthentication(aRequest *http.Request) bool {
	return true
} // NeedAuthentication

// `NeedAuthentication()` returns `false` thus skipping any authentication.
//
// Parameters:
//   - `aRequest` holds the URL to check.
//
// Returns:
//   - `bool`: `false` (always).
func (as TAuthSkipper) NeedAuthentication(aRequest *http.Request) bool {
	return false
} // NeedAuthentication

// --------------------------------------------------------------------------

// `Wrap ()`returns a handler function that includes authentication,
// wrapping the given `aNext` and calling it internally.
//
// Parameters:
//   - `aNext`: The handler to be called after successful authentication.
//   - `aRealm`: The symbolic name of the domain/host to protect.
//   - `aPasswdFile`: The name of the password file to use.
//   - `aAuthDecider`:
func Wrap(aNext http.Handler, aRealm, aPasswdFile string, aAuthDecider IAuthDecider) http.Handler {
	if 0 == len(aPasswdFile) {
		log.Print("passlist.Wrap(): missing password file\nAUTHENTICATION DISABLED!\n")
		// Without a password file we can't do authentication.
		return aNext
	}

	if nil == aAuthDecider {
		log.Print("passlist.Wrap(): missing AuthDecider\nAUTHENTICATION DISABLED!\n")
		// Without a decider we skip the authentication procedure.
		return aNext
	}

	ul, err := LoadPasswords(aPasswdFile)
	if nil != err {
		log.Printf("passlist.Wrap(): %v\nAUTHENTICATION DISABLED!\n", err)
		// We can't do anything w/o password file, so we skip
		// the whole authentication procedure.
		return aNext
	}

	if aRealm = strings.TrimSpace(aRealm); "" == aRealm {
		aRealm = `<unknown>`
	}

	newHandler := func(aWriter http.ResponseWriter, aRequest *http.Request) {
		if aAuthDecider.NeedAuthentication(aRequest) {
			// `ul` and `aRealm` are defined in the embedding closure (above).
			if err := ul.IsAuthenticated(aRequest); nil != err {
				Deny(aRealm, aWriter)
				return
			}
		}

		// Call the previous/original handler:
		aNext.ServeHTTP(aWriter, aRequest)
	}

	return http.HandlerFunc(newHandler)
} // Wrap()

/* _EoF_ */
