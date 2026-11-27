//go:build windows

package main

// matchOwnership is a no-op on Windows, where file ACLs are inherited.
func matchOwnership(reference, file string) {}
