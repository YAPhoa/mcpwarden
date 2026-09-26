//go:build !flowtest

package main

import "testing"

// Release builds carry no test routes.
func TestNoTestRoutesWithoutFlowtestTag(t *testing.T) {
	if testRoutes != nil {
		t.Fatal("test routes are registered without the flowtest tag")
	}
}
