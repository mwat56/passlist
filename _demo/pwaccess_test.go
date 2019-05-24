package main

import (
	"testing"

	"github.com/mwat56/passlist"
)

func Test_run(t *testing.T) {
	fn := "./testlist.db"
	u1, p1 := "username1", "password1"
	u2, p2 := "username2", "password2"
	u3, p3 := "username3", "password3"
	ul := passlist.NewList(fn)
	ul.Add(u1, p1)
	ul.Add(u2, p2)
	ul.Add(u3, p3)
	ul.Store()
	al1 := tArgumentList{}
	al2 := tArgumentList{
		"filename": fn,
	}
	al3 := tArgumentList{
		"filename": fn,
		"add":      u1,
	}
	al4 := tArgumentList{
		"filename": fn,
		"chk":      u1,
	}
	al5 := tArgumentList{
		"filename": fn,
		"del":      u2,
	}
	al6 := tArgumentList{
		"filename": fn,
		"upd":      u3,
	}
	type args struct {
		aArgs tArgumentList
	}
	tests := []struct {
		name      string
		args      args
		wantRExit bool
	}{
		// TODO: Add test cases.
		{" 1", args{al1}, false},
		{" 2", args{al2}, false},
		{" 3", args{al3}, false},
		{" 4", args{al4}, true},
		{" 5", args{al5}, true},
		{" 6", args{al6}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotRExit := run(tt.args.aArgs); gotRExit != tt.wantRExit {
				t.Errorf("run() = %v, want %v", gotRExit, tt.wantRExit)
			}
		})
	}
} // Test_run()
