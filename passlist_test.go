/*
   Copyright © 2019, 2020 M.Watermann, 10247 Berlin, Germany
                   All rights reserved
               EMail : <support@mwat.de>
*/

package passlist

import (
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func prepDB() *TPassList {
	fn1, _ := filepath.Abs("./testlist.db")
	return &TPassList{
		filename: fn1,
		usermap:  make(tUserMap),
	}
} // prepDB()

func TestNewList(t *testing.T) {
	wl1 := prepDB()
	type args struct {
		aFilename string
	}
	tests := []struct {
		name      string
		args      args
		wantRList *TPassList
	}{
		// TODO: Add test cases.
		{" 1", args{wl1.filename}, wl1},
		{" 2", args{""}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotRList := NewList(tt.args.aFilename); !reflect.DeepEqual(gotRList, tt.wantRList) {
				t.Errorf("NewList() = %v, want %v", gotRList, tt.wantRList)
			}
		})
	}
} // TestNewList()

// xxHash is an internal test helper
func xxHash(aPassword string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(aPassword+pwPepper), 6)
	return string(hash)
} // xxHash()

func TestTUserList_Add(t *testing.T) {
	ul1 := prepDB()
	u1, p1 := "username1", "password1"
	type args struct {
		aUser     string
		aPassword string
	}
	tests := []struct {
		name    string
		ul      *TPassList
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{" 1", ul1, args{u1, p1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ul := tt.ul
			if err := ul.Add(tt.args.aUser, tt.args.aPassword); (err != nil) != tt.wantErr {
				t.Errorf("TUserList.Add() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
} // TestTUserList_Add()

func TestTUserList_add0(t *testing.T) {
	ul1 := prepDB()
	u1, p1 := "username1", "password1"
	wl1 := &TPassList{
		ul1.filename,
		tUserMap{
			u1: p1,
		},
	}
	u2, p2 := "username2", "password2"
	wl2 := &TPassList{
		ul1.filename,
		tUserMap{
			u1: p1,
			u2: p2,
		},
	}
	type args struct {
		aUser     string
		aHashedPW string
	}
	tests := []struct {
		name string
		ul   *TPassList
		args args
		want *TPassList
	}{
		// TODO: Add test cases.
		{" 1", ul1, args{u1, p1}, wl1},
		{" 2", ul1, args{u2, p2}, wl2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.add0(tt.args.aUser, tt.args.aHashedPW); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TUserList.Add() = {%v}, want {%v}", got, tt.want)
			}
		})
	}
} // TestTUserList_add0()

func TestTUserList_Clear(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul1 := prepDB().add0(u1, p1).add0(u2, p2)
	wl1 := &TPassList{
		ul1.filename,
		make(tUserMap),
	}
	tests := []struct {
		name string
		ul   *TPassList
		want *TPassList
	}{
		// TODO: Add test cases.
		{" 1", ul1, wl1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.Clear(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TUserList.Clear() = {%v}, want {%v}", got, tt.want)
			}
		})
	}
} // TestTUserList_Clear()

func TestTUserList_Find(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul1 := prepDB().add0(u1, p1).add0(u2, p2)
	type args struct {
		aUser string
	}
	tests := []struct {
		name  string
		ul    *TPassList
		args  args
		want  string
		want1 bool
	}{
		// TODO: Add test cases.
		{" 1", ul1, args{u1}, p1, true},
		{" 2", ul1, args{u2}, p2, true},
		{" 3", ul1, args{""}, "", false},
		{" 4", ul1, args{"nobody"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := tt.ul.Find(tt.args.aUser)
			if got != tt.want {
				t.Errorf("TUserList.Find() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("TUserList.Find() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
} // TestTUserList_Find()

func TestTUserList_Len(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul1 := prepDB().add0(u1, p1).add0(u2, p2)
	ul2 := prepDB()
	tests := []struct {
		name string
		ul   *TPassList
		want int
	}{
		// TODO: Add test cases.
		{" 1", ul1, 2},
		{" 2", ul2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.Len(); got != tt.want {
				t.Errorf("TUserList.Len() = %v, want %v", got, tt.want)
			}
		})
	}
} // TestTUserList_Len()

func TestTUserList_List(t *testing.T) {
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
		name      string
		fields    TPassList
		wantRList []string
	}{
		// TODO: Add test cases.
		{" 1", *ul1, wl1},
		{" 2", *ul2, wl2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ul := tt.fields
			if gotRList := ul.List(); !reflect.DeepEqual(gotRList, tt.wantRList) {
				t.Errorf("TUserList.List() = %v, want %v", gotRList, tt.wantRList)
			}
		})
	}
} // TestTUserList_List()

func TestTUserList_Remove(t *testing.T) {
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul1 := prepDB().add0(u1, p1).add0(u2, p2)
	wl1 := &TPassList{
		ul1.filename,
		tUserMap{
			u1: p1,
			u2: p2},
	}
	wl2 := &TPassList{
		ul1.filename,
		tUserMap{
			u2: p2},
	}
	wl3 := prepDB()
	type args struct {
		aUser string
	}
	tests := []struct {
		name string
		ul   *TPassList
		args args
		want *TPassList
	}{
		// TODO: Add test cases.
		{" 1", ul1, args{"nobody"}, wl1},
		{" 2", ul1, args{u1}, wl2},
		{" 3", ul1, args{u2}, wl3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.Remove(tt.args.aUser); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TUserList.Remove() = %v, want %v", got, tt.want)
			}
		})
	}
} // TestTUserList_Remove()

func TestTUserList_Store(t *testing.T) {
	u1, p1 := "username1", "password1" // incl. ":" and "\n": 20 bytes
	u2, p2 := "username2", "password2"
	u3, p3 := "username3", "password3"
	ul1 := prepDB().add0(u1, p1)
	ul2 := prepDB().add0(u2, p2).add0(u1, p1)
	ul3 := prepDB().add0(u2, p2).add0(u3, p3).add0(u1, p1)
	type args struct {
		aFilename string
	}
	tests := []struct {
		name    string
		ul      *TPassList
		args    args
		want    int
		wantErr bool
	}{
		// TODO: Add test cases.
		{" 1", ul1, args{ul1.filename}, 20, false},
		{" 2", ul2, args{ul2.filename}, 40, false},
		{" 3", ul3, args{ul3.filename}, 60, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ul.Store()
			if (err != nil) != tt.wantErr {
				t.Errorf("TUserList.Store() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("TUserList.Store() = %v, want %v", got, tt.want)
			}
		})
	}
} // TestTUserList_Store()

func TestTUserList_String(t *testing.T) {
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
		// TODO: Add test cases.
		{" 1", ul1, w1},
		{" 2", ul2, w2},
		{" 3", ul3, w3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ul.String(); got != tt.want {
				t.Errorf("TUserList.String() = %v, want %v", got, tt.want)
			}
		})
	}
} // TestTUserList_String()

func TestTUserList_Load(t *testing.T) {
	u1, p1 := "username1", xxHash("password1")
	u2, p2 := "username2", xxHash("password2")
	u3, p3 := "username3", xxHash("password3")
	ul1 := prepDB().add0(u1, p1).add0(u2, p2).add0(u3, p3)
	ul1.Store()
	tests := []struct {
		name    string
		ul      *TPassList
		wantErr bool
	}{
		// TODO: Add test cases.
		{" 1", ul1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ul.Load()
			if (err != nil) != tt.wantErr {
				t.Errorf("TUserList.Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
} // TestTUserList_Load()

func TestLoadPasswords(t *testing.T) {
	u1, p1 := "username1", xxHash("password1")
	u2, p2 := "username2", xxHash("password2")
	u3, p3 := "username3", xxHash("password3")
	ul1 := prepDB().add0(u1, p1).add0(u2, p2).add0(u3, p3)
	ul1.Store()
	wl1 := &TPassList{
		ul1.filename,
		tUserMap{
			u1: p1,
			u2: p2,
			u3: p3,
		},
	}
	type args struct {
		aFilename string
	}
	tests := []struct {
		name    string
		args    args
		want    *TPassList
		wantErr bool
	}{
		// TODO: Add test cases.
		{" 1", args{ul1.filename}, wl1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadPasswords(tt.args.aFilename)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPasswords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadPasswords() = %v, want %v", got, tt.want)
			}
		})
	}
} // TestLoadPasswords()
