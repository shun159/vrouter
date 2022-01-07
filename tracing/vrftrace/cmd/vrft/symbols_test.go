package main

import "testing"

func TestNewSymsDB(t *testing.T) {
	symsdb, _ := NewSymsDB()
	if ok := symsdb.Availfuncs["__bridge_table_dump"]; !ok {
		t.Errorf("__bridge_table_dump should be exist as Availfuncs")
	}
}
