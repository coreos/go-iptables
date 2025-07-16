// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestProto(t *testing.T) {
	ipt, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if ipt.Proto() != ProtocolIPv4 {
		t.Fatalf("Expected default protocol IPv4, got %v", ipt.Proto())
	}

	ip4t, err := NewWithProtocol(ProtocolIPv4)
	if err != nil {
		t.Fatalf("NewWithProtocol(ProtocolIPv4) failed: %v", err)
	}
	if ip4t.Proto() != ProtocolIPv4 {
		t.Fatalf("Expected protocol IPv4, got %v", ip4t.Proto())
	}

	ip6t, err := NewWithProtocol(ProtocolIPv6)
	if err != nil {
		t.Fatalf("NewWithProtocol(ProtocolIPv6) failed: %v", err)
	}
	if ip6t.Proto() != ProtocolIPv6 {
		t.Fatalf("Expected protocol IPv6, got %v", ip6t.Proto())
	}
}

func TestTimeout(t *testing.T) {
	ipt, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if ipt.timeout != 0 {
		t.Fatalf("Expected timeout 0 (wait forever), got %v", ipt.timeout)
	}

	ipt2, err := New(Timeout(5))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if ipt2.timeout != 5 {
		t.Fatalf("Expected timeout 5, got %v", ipt.timeout)
	}

}

// force usage of -legacy or -nft commands and check that they're detected correctly
func TestLegacyDetection(t *testing.T) {
	testCases := []struct {
		in   string
		mode string
		err  bool
	}{
		{
			"iptables-legacy",
			"legacy",
			false,
		},
		{
			"ip6tables-legacy",
			"legacy",
			false,
		},
		{
			"iptables-nft",
			"nf_tables",
			false,
		},
		{
			"ip6tables-nft",
			"nf_tables",
			false,
		},
	}

	for i, tt := range testCases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			ipt, err := New(Path(tt.in))
			if err == nil && tt.err {
				t.Fatal("expected err, got none")
			} else if err != nil && !tt.err {
				t.Fatalf("unexpected err %s", err)
			}

			if !strings.Contains(ipt.path, tt.in) {
				t.Fatalf("Expected path %s in %s", tt.in, ipt.path)
			}
			if ipt.mode != tt.mode {
				t.Fatalf("Expected %s iptables, but got %s", tt.mode, ipt.mode)
			}
		})
	}
}

func randChain(t *testing.T) string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		t.Fatalf("Failed to generate random chain name: %v", err)
	}

	return "TEST-" + n.String()
}

func contains(list []string, value string) bool {
	for _, val := range list {
		if val == value {
			return true
		}
	}
	return false
}

// mustTestableIptables returns a list of ip(6)tables handles with various
// features enabled & disabled, to test compatibility.
// We used to test noWait as well, but that was removed as of iptables v1.6.0
func mustTestableIptables() []*IPTables {
	ipt, err := New()
	if err != nil {
		panic(fmt.Sprintf("New failed: %v", err))
	}
	ip6t, err := NewWithProtocol(ProtocolIPv6)
	if err != nil {
		panic(fmt.Sprintf("NewWithProtocol(ProtocolIPv6) failed: %v", err))
	}
	ipts := []*IPTables{ipt, ip6t}

	// ensure we check one variant without built-in checking
	if ipt.hasCheck {
		i := *ipt
		i.hasCheck = false
		ipts = append(ipts, &i)

		i6 := *ip6t
		i6.hasCheck = false
		ipts = append(ipts, &i6)
	} else {
		panic("iptables on this machine is too old -- missing -C")
	}
	return ipts
}

func TestChain(t *testing.T) {
	for i, ipt := range mustTestableIptables() {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			runChainTests(t, ipt)
		})
	}
}

func runChainTests(t *testing.T, ipt *IPTables) {
	t.Logf("testing %s (hasWait=%t, hasCheck=%t)", ipt.path, ipt.hasWait, ipt.hasCheck)

	chain := randChain(t)

	// Saving the list of chains before executing tests
	originalListChain, err := ipt.ListChains("filter")
	if err != nil {
		t.Fatalf("ListChains of Initial failed: %v", err)
	}

	// chain shouldn't exist, this will create new
	err = ipt.ClearChain("filter", chain)
	if err != nil {
		t.Fatalf("ClearChain (of missing) failed: %v", err)
	}

	// chain should be in listChain
	listChain, err := ipt.ListChains("filter")
	if err != nil {
		t.Fatalf("ListChains failed: %v", err)
	}
	if !contains(listChain, chain) {
		t.Fatalf("ListChains doesn't contain the new chain %v", chain)
	}

	// ChainExists should find it, too
	exists, err := ipt.ChainExists("filter", chain)
	if err != nil {
		t.Fatalf("ChainExists for existing chain failed: %v", err)
	} else if !exists {
		t.Fatalf("ChainExists doesn't find existing chain")
	}

	// chain now exists
	err = ipt.ClearChain("filter", chain)
	if err != nil {
		t.Fatalf("ClearChain (of empty) failed: %v", err)
	}

	// put a simple rule in
	err = ipt.Append("filter", chain, "-s", "0/0", "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// can't delete non-empty chain
	err = ipt.DeleteChain("filter", chain)
	if err == nil {
		t.Fatalf("DeleteChain of non-empty chain did not fail")
	}
	e, ok := err.(*Error)
	if ok && e.IsNotExist() {
		t.Fatal("DeleteChain of non-empty chain returned IsNotExist")
	}

	err = ipt.ClearChain("filter", chain)
	if err != nil {
		t.Fatalf("ClearChain (of non-empty) failed: %v", err)
	}

	// rename the chain
	newChain := randChain(t)
	err = ipt.RenameChain("filter", chain, newChain)
	if err != nil {
		t.Fatalf("RenameChain failed: %v", err)
	}

	// chain empty, should be ok
	err = ipt.DeleteChain("filter", newChain)
	if err != nil {
		t.Fatalf("DeleteChain of empty chain failed: %v", err)
	}

	// check that chain is fully gone and that state similar to initial one
	listChain, err = ipt.ListChains("filter")
	if err != nil {
		t.Fatalf("ListChains failed: %v", err)
	}
	if !reflect.DeepEqual(originalListChain, listChain) {
		t.Fatalf("ListChains mismatch: \ngot  %#v \nneed %#v", originalListChain, listChain)
	}

	// ChainExists must not find it anymore
	exists, err = ipt.ChainExists("filter", chain)
	if err != nil {
		t.Fatalf("ChainExists for non-existing chain failed: %v", err)
	} else if exists {
		t.Fatalf("ChainExists finds non-existing chain")
	}

	// test ClearAndDelete
	err = ipt.NewChain("filter", chain)
	if err != nil {
		t.Fatalf("NewChain failed: %v", err)
	}
	err = ipt.Append("filter", chain, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	err = ipt.ClearAndDeleteChain("filter", chain)
	if err != nil {
		t.Fatalf("ClearAndDelete failed: %v", err)
	}
	exists, err = ipt.ChainExists("filter", chain)
	if err != nil {
		t.Fatalf("ChainExists failed: %v", err)
	}
	if exists {
		t.Fatalf("ClearAndDelete didn't delete the chain")
	}
	err = ipt.ClearAndDeleteChain("filter", chain)
	if err != nil {
		t.Fatalf("ClearAndDelete failed for non-existing chain: %v", err)
	}
}

func TestRules(t *testing.T) {
	for i, ipt := range mustTestableIptables() {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			runRulesTests(t, ipt)
		})
	}
}

func runRulesTests(t *testing.T, ipt *IPTables) {
	t.Logf("testing %s (hasWait=%t, hasCheck=%t)", getIptablesCommand(ipt.Proto()), ipt.hasWait, ipt.hasCheck)

	formatInvert := func(sd, addr string) []string {
		ret := make([]string, 0)
		if addr[0] == '!' {
			ret = append(ret, "!")
			addr = addr[1:]
		}
		ret = append(ret, sd, addr)
		return ret
	}

	spec := func(parts ...[]string) []string {
		ret := make([]string, 0)

		for _, part := range parts {
			for _, sub := range part {
				ret = append(ret, sub)
			}
		}

		return ret
	}

	var address1, address2, address3, address4, subnet1, subnet2, subnet3, subnet4 string
	if ipt.Proto() == ProtocolIPv6 {
		address1 = "2001:db8::1/128"
		address2 = "2001:db8::2/128"
		address3 = "2001:db8::3/128"
		address4 = "!2001:db8::4/128"
		subnet1 = "2001:db8:a::/48"
		subnet2 = "2001:db8:b::/48"
		subnet3 = "2001:db8:c::/48"
		subnet4 = "2001:db8:d::/48"
	} else {
		address1 = "203.0.113.1/32"
		address2 = "203.0.113.2/32"
		address3 = "203.0.113.3/32"
		address4 = "!203.0.113.4/32"
		subnet1 = "192.0.2.0/24"
		subnet2 = "198.51.100.0/24"
		subnet3 = "198.51.101.0/24"
		subnet4 = "198.51.102.0/24"
	}

	chain := randChain(t)

	// chain shouldn't exist, this will create new
	err := ipt.ClearChain("filter", chain)
	if err != nil {
		t.Fatalf("ClearChain (of missing) failed: %v", err)
	}

	err = ipt.Append("filter", chain,
		spec(formatInvert("-s", subnet1), formatInvert("-d", address1), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	err = ipt.AppendUnique("filter", chain,
		spec(formatInvert("-s", subnet1), formatInvert("-d", address1), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("AppendUnique failed: %v", err)
	}

	err = ipt.Append("filter", chain,
		spec(formatInvert("-s", subnet2), formatInvert("-d", address1), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	err = ipt.Insert("filter", chain, 2,
		spec(formatInvert("-s", subnet2), formatInvert("-d", address2), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	err = ipt.InsertUnique("filter", chain, 2,
		spec(formatInvert("-s", subnet2), formatInvert("-d", address2), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	err = ipt.Insert("filter", chain, 1,
		spec(formatInvert("-s", subnet1), formatInvert("-d", address2), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	err = ipt.Delete("filter", chain,
		spec(formatInvert("-s", subnet1), formatInvert("-d", address2), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	err = ipt.Insert("filter", chain, 1,
		spec(formatInvert("-s", subnet1), formatInvert("-d", address2), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	err = ipt.Replace("filter", chain, 1,
		spec(formatInvert("-s", subnet2), formatInvert("-d", address2), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Replace failed: %v", err)
	}

	err = ipt.Delete("filter", chain,
		spec(formatInvert("-s", subnet2), formatInvert("-d", address2), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	err = ipt.Append("filter", chain,
		spec(formatInvert("-s", address1), formatInvert("-d", subnet2), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	rules, err := ipt.List("filter", chain)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Verify DeleteById functionality by adding two new rules and removing second last
	ruleCount1 := len(rules)
	err = ipt.Append("filter", chain,
		spec(formatInvert("-s", address3), formatInvert("-d", subnet3), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	err = ipt.Append("filter", chain,
		spec(formatInvert("-s", address4), formatInvert("-d", subnet4), []string{"-j", "ACCEPT"})...)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	err = ipt.DeleteById("filter", chain, ruleCount1)
	if err != nil {
		t.Fatalf("DeleteById failed: %v", err)
	}
	rules, err = ipt.List("filter", chain)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	expected := []string{
		"-N " + chain,
		"-A " + chain + " " + strings.Join(formatInvert("-s", subnet1), " ") +
			" " + strings.Join(formatInvert("-d", address1), " ") + " -j ACCEPT",
		"-A " + chain + " " + strings.Join(formatInvert("-s", subnet2), " ") +
			" " + strings.Join(formatInvert("-d", address2), " ") + " -j ACCEPT",
		"-A " + chain + " " + strings.Join(formatInvert("-s", subnet2), " ") +
			" " + strings.Join(formatInvert("-d", address1), " ") + " -j ACCEPT",
		"-A " + chain + " " + strings.Join(formatInvert("-s", address1), " ") +
			" " + strings.Join(formatInvert("-d", subnet2), " ") + " -j ACCEPT",
		"-A " + chain + " " + strings.Join(formatInvert("-s", address4), " ") +
			" " + strings.Join(formatInvert("-d", subnet4), " ") + " -j ACCEPT",
	}

	if !reflect.DeepEqual(rules, expected) {
		t.Fatalf("List mismatch: \ngot  %#v \nneed %#v", rules, expected)
	}

	rules, err = ipt.ListWithCounters("filter", chain)
	if err != nil {
		t.Fatalf("ListWithCounters failed: %v", err)
	}

	makeExpected := func(suffix string) []string {
		return []string{
			"-N " + chain,
			"-A " + chain + " " + strings.Join(formatInvert("-s", subnet1), " ") +
				" " + strings.Join(formatInvert("-d", address1), " ") + " " + suffix,
			"-A " + chain + " " + strings.Join(formatInvert("-s", subnet2), " ") +
				" " + strings.Join(formatInvert("-d", address2), " ") + " " + suffix,
			"-A " + chain + " " + strings.Join(formatInvert("-s", subnet2), " ") +
				" " + strings.Join(formatInvert("-d", address1), " ") + " " + suffix,
			"-A " + chain + " " + strings.Join(formatInvert("-s", address1), " ") +
				" " + strings.Join(formatInvert("-d", subnet2), " ") + " " + suffix,
			"-A " + chain + " " + strings.Join(formatInvert("-s", address4), " ") +
				" " + strings.Join(formatInvert("-d", subnet4), " ") + " " + suffix,
		}
	}
	// older nf_tables returned the second order
	if !reflect.DeepEqual(rules, makeExpected("-c 0 0 -j ACCEPT")) &&
		!reflect.DeepEqual(rules, makeExpected("-j ACCEPT -c 0 0")) {
		t.Fatalf("ListWithCounters mismatch: \ngot  %#v \nneed %#v", rules, makeExpected("<-c 0 0 and -j ACCEPT in either order>"))
	}

	stats, err := ipt.Stats("filter", chain)
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}

	opt := "--"
	prot := "0"
	if ipt.proto == ProtocolIPv6 &&
		ipt.v1 == 1 && (ipt.v2 < 8 || (ipt.v2 == 8 && ipt.v3 < 9)) {
		// this is fixed in iptables 1.8.9 via iptables/6e41c2d874
		opt = "  "
		// this is fixed in iptables 1.8.9 via iptables/da8ecc62dd
		prot = "all"
	}
	if ipt.proto == ProtocolIPv4 &&
		ipt.v1 == 1 && (ipt.v2 < 8 || (ipt.v2 == 8 && ipt.v3 < 9)) {
		// this is fixed in iptables 1.8.9 via iptables/da8ecc62dd
		prot = "all"
	}

	expectedStats := [][]string{
		{"0", "0", "ACCEPT", prot, opt, "*", "*", subnet1, address1, ""},
		{"0", "0", "ACCEPT", prot, opt, "*", "*", subnet2, address2, ""},
		{"0", "0", "ACCEPT", prot, opt, "*", "*", subnet2, address1, ""},
		{"0", "0", "ACCEPT", prot, opt, "*", "*", address1, subnet2, ""},
		{"0", "0", "ACCEPT", prot, opt, "*", "*", address4, subnet4, ""},
	}

	if !reflect.DeepEqual(stats, expectedStats) {
		t.Fatalf("Stats mismatch: \ngot  %#v \nneed %#v", stats, expectedStats)
	}

	structStats, err := ipt.StructuredStats("filter", chain)
	if err != nil {
		t.Fatalf("StructuredStats failed: %v", err)
	}

	// It's okay to not check the following errors as they will be evaluated
	// in the subsequent usage
	address1IPNet, _ := ParseInvertibleNet(address1)
	address2IPNet, _ := ParseInvertibleNet(address2)
	address4IPNet, _ := ParseInvertibleNet(address4)
	subnet1IPNet, _ := ParseInvertibleNet(subnet1)
	subnet2IPNet, _ := ParseInvertibleNet(subnet2)
	subnet4IPNet, _ := ParseInvertibleNet(subnet4)

	expectedStructStats := []Stat{
		{0, 0, "ACCEPT", prot, opt, "*", "*", subnet1IPNet, address1IPNet, ""},
		{0, 0, "ACCEPT", prot, opt, "*", "*", subnet2IPNet, address2IPNet, ""},
		{0, 0, "ACCEPT", prot, opt, "*", "*", subnet2IPNet, address1IPNet, ""},
		{0, 0, "ACCEPT", prot, opt, "*", "*", address1IPNet, subnet2IPNet, ""},
		{0, 0, "ACCEPT", prot, opt, "*", "*", address4IPNet, subnet4IPNet, ""},
	}

	if !reflect.DeepEqual(structStats, expectedStructStats) {
		t.Fatalf("StructuredStats mismatch: \ngot  %#v \nneed %#v",
			structStats, expectedStructStats)
	}

	for i, stat := range expectedStats {
		stat, err := ipt.ParseStat(stat)
		if err != nil {
			t.Fatalf("ParseStat failed: %v", err)
		}
		if !reflect.DeepEqual(stat, expectedStructStats[i]) {
			t.Fatalf("ParseStat mismatch: \ngot  %#v \nneed %#v",
				stat, expectedStructStats[i])
		}
	}

	err = ipt.DeleteIfExists("filter", chain, "-s", address1, "-d", subnet2, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("DeleteIfExists failed for existing rule: %v", err)
	}
	err = ipt.DeleteIfExists("filter", chain, "-s", address1, "-d", subnet2, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("DeleteIfExists failed for non-existing rule: %v", err)
	}

	// Clear the chain that was created.
	err = ipt.ClearChain("filter", chain)
	if err != nil {
		t.Fatalf("Failed to clear test chain: %v", err)
	}

	// Delete the chain that was created
	err = ipt.DeleteChain("filter", chain)
	if err != nil {
		t.Fatalf("Failed to delete test chain: %v", err)
	}
}

// TestError checks that we're OK when iptables fails to execute
func TestError(t *testing.T) {
	ipt, err := New()
	if err != nil {
		t.Fatalf("failed to init: %v", err)
	}

	chain := randChain(t)
	_, err = ipt.List("filter", chain)
	if err == nil {
		t.Fatalf("no error with invalid params")
	}
	switch e := err.(type) {
	case *Error:
		// OK
	default:
		t.Fatalf("expected type iptables.Error, got %t", e)
	}

	// Now set an invalid binary path
	ipt.path = "/does-not-exist"

	_, err = ipt.ListChains("filter")

	if err == nil {
		t.Fatalf("no error with invalid ipt binary")
	}

	switch e := err.(type) {
	case *os.PathError:
		// OK
	default:
		t.Fatalf("expected type os.PathError, got %t", e)
	}
}

func TestIsNotExist(t *testing.T) {
	ipt, err := New()
	if err != nil {
		t.Fatalf("failed to init: %v", err)
	}
	// Create a chain, add a rule
	chainName := randChain(t)
	err = ipt.NewChain("filter", chainName)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := ipt.ClearChain("filter", chainName); err != nil {
			t.Fatal(err)
		}
		if err := ipt.DeleteChain("filter", chainName); err != nil {
			t.Fatal(err)
		}
	}()

	err = ipt.Append("filter", chainName, "-p", "tcp", "-j", "DROP")
	if err != nil {
		t.Fatal(err)
	}

	// Delete rule twice
	err = ipt.Delete("filter", chainName, "-p", "tcp", "-j", "DROP")
	if err != nil {
		t.Fatal(err)
	}

	err = ipt.Delete("filter", chainName, "-p", "tcp", "-j", "DROP")
	if err == nil {
		t.Fatal("delete twice got no error...")
	}

	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("Got wrong error type, expected iptables.Error, got %T", err)
	}

	if !e.IsNotExist() {
		t.Fatal("IsNotExist returned false, expected true")
	}

	// Delete chain
	err = ipt.DeleteChain("filter", chainName)
	if err != nil {
		t.Fatal(err)
	}

	err = ipt.DeleteChain("filter", chainName)
	if err == nil {
		t.Fatal("deletechain twice got no error...")
	}

	e, ok = err.(*Error)
	if !ok {
		t.Fatalf("Got wrong error type, expected iptables.Error, got %T", err)
	}

	if !e.IsNotExist() {
		t.Fatal("IsNotExist returned false, expected true")
	}

	// iptables may add more logs to the errors msgs
	e.msg = "Another app is currently holding the xtables lock; waiting (1s) for it to exit..." + e.msg
	if !e.IsNotExist() {
		t.Fatal("IsNotExist returned false, expected true")
	}

}

func TestIsNotExistForIPv6(t *testing.T) {
	ipt, err := NewWithProtocol(ProtocolIPv6)
	if err != nil {
		t.Fatalf("failed to init: %v", err)
	}
	// Create a chain, add a rule
	chainName := randChain(t)
	err = ipt.NewChain("filter", chainName)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := ipt.ClearChain("filter", chainName); err != nil {
			t.Fatal(err)
		}
		if err := ipt.DeleteChain("filter", chainName); err != nil {
			t.Fatal(err)
		}
	}()

	err = ipt.Append("filter", chainName, "-p", "tcp", "-j", "DROP")
	if err != nil {
		t.Fatal(err)
	}

	// Delete rule twice
	err = ipt.Delete("filter", chainName, "-p", "tcp", "-j", "DROP")
	if err != nil {
		t.Fatal(err)
	}

	err = ipt.Delete("filter", chainName, "-p", "tcp", "-j", "DROP")
	if err == nil {
		t.Fatal("delete twice got no error...")
	}

	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("Got wrong error type, expected iptables.Error, got %T", err)
	}

	if !e.IsNotExist() {
		t.Fatal("IsNotExist returned false, expected true")
	}

	// Delete chain
	err = ipt.DeleteChain("filter", chainName)
	if err != nil {
		t.Fatal(err)
	}

	err = ipt.DeleteChain("filter", chainName)
	if err == nil {
		t.Fatal("deletechain twice got no error...")
	}

	e, ok = err.(*Error)
	if !ok {
		t.Fatalf("Got wrong error type, expected iptables.Error, got %T", err)
	}

	if !e.IsNotExist() {
		t.Fatal("IsNotExist returned false, expected true")
	}

	// iptables may add more logs to the errors msgs
	e.msg = "Another app is currently holding the xtables lock; waiting (1s) for it to exit..." + e.msg
	if !e.IsNotExist() {
		t.Fatal("IsNotExist returned false, expected true")
	}
}

func TestFilterRuleOutput(t *testing.T) {
	testCases := []struct {
		name string
		in   string
		out  string
	}{
		{
			"legacy output",
			"-A foo1 -p tcp -m tcp --dport 1337 -j ACCEPT",
			"-A foo1 -p tcp -m tcp --dport 1337 -j ACCEPT",
		},
		{
			"nft output",
			"[99:42] -A foo1 -p tcp -m tcp --dport 1337 -j ACCEPT",
			"-A foo1 -p tcp -m tcp --dport 1337 -j ACCEPT -c 99 42",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			actual := filterRuleOutput(tt.in)
			if actual != tt.out {
				t.Fatalf("expect %s actual %s", tt.out, actual)
			}
		})
	}
}

func TestExtractIptablesVersion(t *testing.T) {
	testCases := []struct {
		in         string
		v1, v2, v3 int
		mode       string
		err        bool
	}{
		{
			"iptables v1.8.0 (nf_tables)",
			1, 8, 0,
			"nf_tables",
			false,
		},
		{
			"iptables v1.8.0 (legacy)",
			1, 8, 0,
			"legacy",
			false,
		},
		{
			"iptables v1.6.2",
			1, 6, 2,
			"legacy",
			false,
		},
	}

	for i, tt := range testCases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			v1, v2, v3, mode, err := extractIptablesVersion(tt.in)
			if err == nil && tt.err {
				t.Fatal("expected err, got none")
			} else if err != nil && !tt.err {
				t.Fatalf("unexpected err %s", err)
			}

			if v1 != tt.v1 || v2 != tt.v2 || v3 != tt.v3 || mode != tt.mode {
				t.Fatalf("expected %d %d %d %s, got %d %d %d %s",
					tt.v1, tt.v2, tt.v3, tt.mode,
					v1, v2, v3, mode)
			}
		})
	}
}

func TestListById(t *testing.T) {
	testCases := []struct {
		in       string
		id       int
		out      string
		expected bool
	}{
		{
			"-i lo -p tcp -m tcp --dport 3000 -j DNAT --to-destination 127.0.0.1:3000",
			1,
			"-A PREROUTING -i lo -p tcp -m tcp --dport 3000 -j DNAT --to-destination 127.0.0.1:3000",
			true,
		},
		{
			"-i lo -p tcp -m tcp --dport 3000 -j DNAT --to-destination 127.0.0.1:3001",
			2,
			"-A PREROUTING -i lo -p tcp -m tcp --dport 3000 -j DNAT --to-destination 127.0.0.1:3001",
			true,
		},
		{
			"-i lo -p tcp -m tcp --dport 3000 -j DNAT --to-destination 127.0.0.1:3002",
			3,
			"-A PREROUTING -i lo -p tcp -m tcp --dport 3000 -j DNAT --to-destination 127.0.0.1:3003",
			false,
		},
	}

	ipt, err := New()
	if err != nil {
		t.Fatalf("failed to init: %v", err)
	}
	// ensure to test in a clear environment
	err = ipt.ClearChain("nat", "PREROUTING")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = ipt.ClearChain("nat", "PREROUTING")
		if err != nil {
			t.Fatal(err)
		}
	}()

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("Checking rule with id %d", tt.id), func(t *testing.T) {
			err = ipt.Append("nat", "PREROUTING", strings.Split(tt.in, " ")...)
			if err != nil {
				t.Fatal(err)
			}
			rule, err := ipt.ListById("nat", "PREROUTING", tt.id)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Println(rule)
			test_result := false
			if rule == tt.out {
				test_result = true
			}
			if test_result != tt.expected {
				t.Fatal("Test failed")
			}
		})
	}
}
