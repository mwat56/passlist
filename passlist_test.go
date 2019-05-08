package passlist

import (
	"reflect"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestNewList(t *testing.T) {
	fn1 := "./testlist.db"
	wl1 := &TPassList{
		/* um: */ make(tUserMap),
		/* filename: */ fn1,
	}
	type args struct {
		aFilename string
	}
	tests := []struct {
		name      string
		args      args
		wantRList *TPassList
	}{
		// TODO: Add test cases.
		{" 1", args{fn1}, wl1},
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
	hash, _ := bcrypt.GenerateFromPassword([]byte(aPassword), 6)
	return string(hash)
} // xxHash()

func Benchmark_xxHash(b *testing.B) {
	for n := 0; n < b.N; n++ {
		if 0 > len(xxHash("password")) {
			continue
		}
	}
} // Benchmark_xxHash()
func Benchmark_TUserList_Add(b *testing.B) {
	fn1 := "./testlist.db"
	ul1 := NewList(fn1)
	u1, p1 := "username1", "password1"
	for n := 0; n < b.N; n++ {
		if err := ul1.Add(u1, p1); nil != err {
			continue
		}
	}
} // Benchmark_TUserList_Add()

func TestTUserList_Add(t *testing.T) {
	fn1 := "./testlist.db"
	ul1 := NewList(fn1)
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
	fn1 := "./testlist.db"
	ul1 := NewList(fn1)
	u1, p1 := "username1", "password1"
	wl1 := &TPassList{
		tUserMap{
			u1: p1,
		},
		fn1,
	}
	u2, p2 := "username2", "password2"
	wl2 := &TPassList{
		tUserMap{
			u1: p1,
			u2: p2,
		},
		fn1,
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
	fn1 := "./testlist.db"
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul1 := NewList(fn1).add0(u1, p1).add0(u2, p2)
	wl1 := &TPassList{
		make(tUserMap),
		fn1,
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
	fn1 := "./testlist.db"
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul1 := NewList(fn1).add0(u1, p1).add0(u2, p2)
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
	fn1 := "./testlist.db"
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul1 := NewList(fn1).add0(u1, p1).add0(u2, p2)
	ul2 := NewList(fn1)
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
	fn1 := "./testlist.db"
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	u3, p3 := "username3", "password3"
	ul1 := NewList(fn1).add0(u1, p1).add0(u2, p2)
	ul2 := NewList(fn1).add0(u1, p1).add0(u2, p2).add0(u3, p3)
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
	fn1 := "./testlist.db"
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	ul1 := NewList(fn1).add0(u1, p1).add0(u2, p2)
	wl1 := &TPassList{
		tUserMap{
			u1: p1,
			u2: p2},
		fn1,
	}
	wl2 := &TPassList{
		tUserMap{
			u2: p2},
		fn1,
	}
	wl3 := NewList(fn1)
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
		{" 1", ul1, args{"nodody"}, wl1},
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
	fn1 := "./testlist.db"
	u1, p1 := "username1", "password1" // incl. ":" and "\n": 20 bytes
	u2, p2 := "username2", "password2"
	u3, p3 := "username3", "password3"
	ul1 := NewList(fn1).add0(u1, p1)
	ul2 := NewList(fn1).add0(u2, p2).add0(u1, p1)
	ul3 := NewList(fn1).add0(u2, p2).add0(u3, p3).add0(u1, p1)
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
		{" 1", ul1, args{fn1}, 20, false},
		{" 2", ul2, args{fn1}, 40, false},
		{" 3", ul3, args{fn1}, 60, false},
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
	fn1 := "./testlist.db"
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	u3, p3 := "username3", "password3"
	ul1 := NewList(fn1).add0(u1, p1)
	ul2 := NewList(fn1).add0(u1, p1).add0(u2, p2)
	ul3 := NewList(fn1).add0(u1, p1).add0(u2, p2).add0(u3, p3)
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

func Benchmark_TUserList_String(b *testing.B) {
	fn1 := "./testlist.db"
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	u3, p3 := "username3", "password3"
	ul1 := NewList(fn1).add0(u1, p1).add0(u2, p2).add0(u3, p3)
	for n := 0; n < b.N; n++ {
		if 0 > len(ul1.String()) {
			continue
		}
	}
} // Benchmark_TUserList_String()

func TestTUserList_Load(t *testing.T) {
	fn1 := "./testlist.db"
	u1, p1 := "username1", xxHash("password1")
	u2, p2 := "username2", xxHash("password2")
	u3, p3 := "username3", xxHash("password3")
	ul1 := NewList(fn1).add0(u1, p1).add0(u2, p2).add0(u3, p3)
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

func TestLoadPWfile(t *testing.T) {
	fn1 := "./testlist.db"
	u1, p1 := "username1", xxHash("password1")
	u2, p2 := "username2", xxHash("password2")
	u3, p3 := "username3", xxHash("password3")
	ul1 := NewList(fn1).add0(u1, p1).add0(u2, p2).add0(u3, p3)
	ul1.Store()
	wl1 := &TPassList{
		tUserMap{
			u1: p1,
			u2: p2,
			u3: p3,
		},
		fn1,
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
		{" 1", args{fn1}, wl1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadPasswords(tt.args.aFilename)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPWfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadPWfile() = %v, want %v", got, tt.want)
			}
		})
	}
} // TestLoadPWfile()
