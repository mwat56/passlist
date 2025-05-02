/*
Copyright © 2019, 2025 M.Watermann, 10247 Berlin, Germany

	    All rights reserved
	EMail : <support@mwat.de>
*/
package passlist

import (
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func prepDB() *TPassList {
	fn, _ := filepath.Abs("./.testlist.db") // #nosec G304

	return New(fn)
} // prepDB()

// xxHash is an internal test helper
func xxHash(aPassword string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(aPassword+pwPepper), pwCost)

	return string(hash)
} // xxHash()

func Test_LoadPasswords(t *testing.T) {
	u1, p1 := "username1", xxHash("password1")
	u2, p2 := "username2", xxHash("password2")
	u3, p3 := "username3", xxHash("password3")
	ul := prepDB().add0(u1, p1).add0(u2, p2).add0(u3, p3)

	_, _ = ul.Store()
	defer func() {
		_ = os.Remove(ul.filename)
	}()

	wl1 := &TPassList{
		ul.filename,
		tUserMap{
			u1: p1,
			u2: p2,
			u3: p3,
		},
	}
	type tArgs struct {
		aFilename string
	}
	tests := []struct {
		name    string
		args    tArgs
		want    *TPassList
		wantErr bool
	}{
		{" 1", tArgs{ul.filename}, wl1, false},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadPasswords(tt.args.aFilename)
			if (nil != err) != tt.wantErr {
				t.Errorf("LoadPasswords() error = '%v', wantErr '%v'",
					err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadPasswords() =\n'%v'\nwant\n'%v'",
					got, tt.want)
			}
		})
	}
} // Test_LoadPasswords()

func Test_New(t *testing.T) {
	ul := prepDB()

	type tArgs struct {
		aFilename string
	}
	tests := []struct {
		name     string
		args     tArgs
		wantList *TPassList
	}{
		{" 1", tArgs{ul.filename}, ul},
		{" 2", tArgs{"   "}, nil},
		{" 3", tArgs{""}, nil},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotRList := New(tt.args.aFilename); !reflect.DeepEqual(gotRList, tt.wantList) {
				t.Errorf("New() =\n'%v'\nwant\n'%v'",
					gotRList, tt.wantList)
			}
		})
	}
} // Test_New()

func Test_TPassList_Add(t *testing.T) {
	ul := prepDB()
	defer func() {
		_ = os.Remove(ul.filename)
	}()

	u1, p1 := "newuser", "new-password"
	u2, p2 := "", "password"
	u3, p3 := "user3", "   "

	type tArgs struct {
		aUser     string
		aPassword string
	}
	tests := []struct {
		name    string
		ul      *TPassList
		args    tArgs
		wantErr bool
	}{
		{" 1", ul, tArgs{u1, p1}, false},
		{" 2", ul, tArgs{u2, p2}, true}, // empty username
		{" 3", ul, tArgs{u3, p3}, true}, // empty password
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ul.Add(tt.args.aUser, tt.args.aPassword)
			if (nil != err) != tt.wantErr {
				t.Errorf("TPassList.Add() error = '%v', wantErr '%v'",
					err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify user was added
				if !tt.ul.Exists(tt.args.aUser) {
					t.Errorf("TPassList.Add() user %q was not added",
						tt.args.aUser)
				}
				// Verify password matches
				if !tt.ul.Matches(tt.args.aUser, tt.args.aPassword) {
					t.Errorf("TPassList.Add() password for user %q doesn't match", tt.args.aUser)
				}
			}
		})
	}
} // Test_TPassList_Add()

func Test_TUserList_add0(t *testing.T) {
	ul := prepDB()
	u1, p1 := "username1", "password1"
	wl1 := &TPassList{
		ul.filename,
		tUserMap{
			u1: p1,
		},
	}

	u2, p2 := "username2", "password2"
	wl2 := &TPassList{
		ul.filename,
		tUserMap{
			u1: p1,
			u2: p2,
		},
	}

	type tArgs struct {
		aUser     string
		aHashedPW string
	}
	tests := []struct {
		name string
		ul   *TPassList
		args tArgs
		want *TPassList
	}{
		{" 1", ul, tArgs{u1, p1}, wl1},
		{" 2", ul, tArgs{u2, p2}, wl2},
		{" 3", ul, tArgs{u1, ""}, nil},
		{" 4", ul, tArgs{"", p2}, nil},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.add0(tt.args.aUser, tt.args.aHashedPW); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TUserList.Add() =\n%v\nwant\n%v",
					got, tt.want)
			}
		})
	}
} // Test_TUserList_add0()

func Test_TUserList_Clear(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul := prepDB().add0(u1, xxHash(p1)).add0(u2, xxHash(p2))

	wl1 := &TPassList{
		ul.filename,
		make(tUserMap, 8),
	}
	tests := []struct {
		name string
		ul   *TPassList
		want *TPassList
	}{
		{" 1", ul, wl1},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.Clear(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TUserList.Clear() =\n{%v}\nwant\n{%v}",
					got, tt.want)
			}
		})
	}
} // Test_TUserList_Clear()

func Test_TPassList_Exists(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul := prepDB().add0(u1, xxHash(p1)).add0(u2, xxHash(p2))

	tests := []struct {
		name string
		ul   *TPassList
		user string
		want bool
	}{
		{" 1", ul, u1, true},
		{" 2", ul, u2, true},
		{" 3", ul, "", false},
		{" 4", ul, "nobody", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.Exists(tt.user); got != tt.want {
				t.Errorf("TPassList.Exists() = '%v', want '%v'",
					got, tt.want)
			}
		})
	}
} // Test_TPassList_Exists()

func Test_TUserList_Find(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul := prepDB().add0(u1, p1).add0(u2, p2)

	tests := []struct {
		name    string
		ul      *TPassList
		user    string
		wantStr string
		wantErr bool
	}{
		{" 1", ul, u1, p1, false},
		{" 2", ul, u2, p2, false},
		{" 3", ul, "", "", true},
		{" 4", ul, "nobody", "", true},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStr, err := tt.ul.Find(tt.user)
			if (nil != err) != tt.wantErr {
				t.Errorf("TUserList.Find() got = '%v', want '%v'",
					err, tt.wantErr)
			}

			if gotStr != tt.wantStr {
				t.Errorf("TUserList.Find() got =\n%q\nwant\n%q",
					gotStr, tt.wantStr)
			}
		})
	}
} // Test_TUserList_Find()

func Test_TPassList_IsAuthenticated(t *testing.T) {
	u1, p1 := "username1", "password1"
	ul := prepDB().add0(u1, xxHash(p1))

	req1, _ := http.NewRequest("GET", "http://example.com", nil)
	req1.SetBasicAuth(u1, p1)

	req2, _ := http.NewRequest("GET", "http://example.com", nil)

	req3, _ := http.NewRequest("GET", "http://example.com", nil)
	req3.SetBasicAuth(u1, "wrongpassword")

	req4, _ := http.NewRequest("GET", "http://example.com", nil)
	req4.SetBasicAuth("nonexistentuser", p1)

	tests := []struct {
		name    string
		ul      *TPassList
		req     *http.Request
		wantErr bool
	}{
		{" 1", ul, req1, false},
		{" 2", ul, req2, true}, // missing auth data
		{" 3", ul, req3, true}, // wrong password
		{" 4", ul, req4, true}, // unknown user
		{" 5", ul, nil, true},  // missing request
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ul.IsAuthenticated(tt.req)
			if (nil != err) != tt.wantErr {
				t.Errorf("TPassList.IsAuthenticated() error = '%v', wantErr '%v'",
					err, tt.wantErr)
			}
			if nil == err {
				// Check that user info was stored in request URL
				if nil == tt.req.URL.User {
					t.Errorf("TPassList.IsAuthenticated() did not store user info in request URL")
				}
			}
		})
	}
} // Test_TPassList_IsAuthenticated()

func Test_TUserList_Len(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul1 := prepDB().add0(u1, p1).add0(u2, p2)

	ul2 := prepDB()
	tests := []struct {
		name    string
		ul      *TPassList
		wantInt int
	}{
		{" 1", ul1, 2},
		{" 2", ul2, 0},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.Len(); got != tt.wantInt {
				t.Errorf("TUserList.Len() = %d, want %d",
					got, tt.wantInt)
			}
		})
	}
} // Test_TUserList_Len()

func Test_TUserList_List(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	u3, p3 := "username3", "password3"
	ul1 := prepDB().add0(u1, p1).add0(u2, p2)

	ul2 := prepDB().add0(u1, p1).add0(u2, p2).add0(u3, p3)
	wl1 := []string{
		u1,
		u2,
	}
	wl2 := []string{
		u1,
		u2,
		u3,
	}

	tests := []struct {
		name     string
		fields   TPassList
		wantList []string
	}{
		{" 1", *ul1, wl1},
		{" 2", *ul2, wl2},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ul := tt.fields
			if gotRList := ul.List(); !reflect.DeepEqual(gotRList, tt.wantList) {
				t.Errorf("TUserList.List() =\n%v\nwant\n%v",
					gotRList, tt.wantList)
			}
		})
	}
} // Test_TUserList_List()

func Test_TUserList_Load(t *testing.T) {
	u1, p1 := "username1", xxHash("password1")
	u2, p2 := "username2", xxHash("password2")
	u3, p3 := "username3", xxHash("password3")
	ul := prepDB().add0(u1, p1).add0(u2, p2).add0(u3, p3)

	_, _ = ul.Store()
	defer func() {
		_ = os.Remove(ul.filename)
	}()

	tests := []struct {
		name    string
		ul      *TPassList
		wantErr bool
	}{
		{" 1", ul, false},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ul.Load()
			if (nil != err) != tt.wantErr {
				t.Errorf("TUserList.Load() error = '%v', wantErr '%v'",
					err, tt.wantErr)
				return
			}
		})
	}
} // Test_TUserList_Load()

func Test_TPassList_Matches(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul := prepDB().add0(u1, xxHash(p1)).add0(u2, xxHash(p2))

	type tArgs struct {
		aUser     string
		aPassword string
	}
	tests := []struct {
		name string
		ul   *TPassList
		args tArgs
		want bool
	}{
		{" 1", ul, tArgs{u1, p1}, true},
		{" 2", ul, tArgs{u2, p2}, true},
		{" 3", ul, tArgs{u1, p2}, false},
		{" 4", ul, tArgs{u2, p1}, false},
		{" 5", ul, tArgs{"nobody", p1}, false},
		{" 6", ul, tArgs{u2, "wrongpass"}, false},
		{" 7", ul, tArgs{"   ", p1}, false},
		{" 8", ul, tArgs{u2, "   "}, false},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.Matches(tt.args.aUser, tt.args.aPassword); got != tt.want {
				t.Errorf("TPassList.Matches() = '%v', want '%v'",
					got, tt.want)
			}
		})
	}
} // Test_TPassList_Matches()

func Test_TUserList_Remove(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul := prepDB().add0(u1, p1).add0(u2, p2)

	wl1 := &TPassList{
		ul.filename,
		tUserMap{
			u1: p1,
			u2: p2},
	}
	wl2 := &TPassList{
		ul.filename,
		tUserMap{
			u2: p2},
	}
	wl3 := prepDB()

	tests := []struct {
		name string
		ul   *TPassList
		user string
		want *TPassList
	}{
		{" 1", ul, "nobody", wl1},
		{" 2", ul, u1, wl2},
		{" 3", ul, u2, wl3},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.Remove(tt.user); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TUserList.Remove() =\n%v\nwant\n%v",
					got, tt.want)
			}
		})
	}
} // Test_TUserList_Remove()

func Test_TUserList_Store(t *testing.T) {
	u1, p1 := "username1", "password1" // incl. ":" and "\n": 20 bytes
	u2, p2 := "username2", "password2"
	u3, p3 := "username3", "password3"

	ul1 := prepDB().add0(u1, p1)
	ul1.filename = "./.testlist1.db"

	ul2 := prepDB().add0(u2, p2).add0(u1, p1)
	ul2.filename = "./.testlist2.db"

	ul3 := prepDB().add0(u2, p2).add0(u3, p3).add0(u1, p1)
	ul3.filename = "./.testlist3.db"

	defer func() {
		_ = os.Remove(ul1.filename)
		_ = os.Remove(ul2.filename)
		_ = os.Remove(ul3.filename)
	}()

	tests := []struct {
		name     string
		ul       *TPassList
		filename string
		want     int
		wantErr  bool
	}{
		{" 1", ul1, ul1.filename, 20, false},
		{" 2", ul2, ul2.filename, 40, false},
		{" 3", ul3, ul3.filename, 60, false},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ul.Store()
			if (nil != err) != tt.wantErr {
				t.Errorf("TUserList.Store() error = '%v', wantErr '%v'",
					err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("TUserList.Store() = %d, want %d",
					got, tt.want)
			}
		})
	}
} // Test_TUserList_Store()

func Test_TUserList_String(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	u3, p3 := "username3", "password3"

	ul1 := prepDB().add0(u1, p1)
	ul2 := prepDB().add0(u1, p1).add0(u2, p2)
	ul3 := prepDB().add0(u1, p1).add0(u2, p2).add0(u3, p3)

	w1 := u1 + ":" + p1 + "\n"
	w2 := w1 + u2 + ":" + p2 + "\n"
	w3 := w2 + u3 + ":" + p3 + "\n"

	tests := []struct {
		name string
		ul   *TPassList
		want string
	}{
		{" 1", ul1, w1},
		{" 2", ul2, w2},
		{" 3", ul3, w3},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.String(); got != tt.want {
				t.Errorf("TUserList.String() =\n%q\nwant\n%q",
					got, tt.want)
			}
		})
	}
} // Test_TUserList_String()
/* _EoF_ */
