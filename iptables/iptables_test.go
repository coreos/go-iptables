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
	"net"
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

func TestRestore(t *testing.T) {
	for i, ipt := range mustTestableIptables() {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			runRestoreTests(t, ipt)
		})
	}
}

func runRestoreTests(t *testing.T, ipt *IPTables) {
	t.Logf("testing %s (hasWait=%t, hasCheck=%t)", ipt.path, ipt.hasWait, ipt.hasCheck)
	var address1, address2, subnet1, subnet2 string
	if ipt.Proto() == ProtocolIPv6 {
		address1 = "2001:db8::1"
		address2 = "2001:db8::2"
		subnet1 = "2001:db8:a::/48"
		subnet2 = "2001:db8:b::/48"
	} else {
		address1 = "203.0.113.1"
		address2 = "203.0.113.2"
		subnet1 = "192.0.2.0/24"
		subnet2 = "198.51.100.0/24"
	}

	chain := randChain(t)
	rule1 := []string{"-d", subnet1, "-p", "tcp", "-m", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:80", address1)}
	rule2 := []string{"-d", subnet2, "-p", "tcp", "-m", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:80", address2)}

	x := map[string][][]string{
		chain: {rule1, rule2},
	}
	err := ipt.Restore("nat", x)
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	rules, err := ipt.List("nat", chain)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	expected := []string{
		"-N " + chain,
		"-A " + chain + " -d " + subnet2 + " -p tcp -m tcp --dport 80 -j DNAT --to-destination " + fmt.Sprintf("%s:80", address2),
		"-A " + chain + " -d " + subnet1 + " -p tcp -m tcp --dport 80 -j DNAT --to-destination " + fmt.Sprintf("%s:80", address1),
	}

	if !reflect.DeepEqual(rules, expected) {
		t.Fatalf("List mismatch: \ngot  %#v \nneed %#v", rules, expected)
	}

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

	var address1, address2, subnet1, subnet2 string
	if ipt.Proto() == ProtocolIPv6 {
		address1 = "2001:db8::1/128"
		address2 = "2001:db8::2/128"
		subnet1 = "2001:db8:a::/48"
		subnet2 = "2001:db8:b::/48"
	} else {
		address1 = "203.0.113.1/32"
		address2 = "203.0.113.2/32"
		subnet1 = "192.0.2.0/24"
		subnet2 = "198.51.100.0/24"
	}

	chain := randChain(t)

	// chain shouldn't exist, this will create new
	err := ipt.ClearChain("filter", chain)
	if err != nil {
		t.Fatalf("ClearChain (of missing) failed: %v", err)
	}

	err = ipt.Append("filter", chain, "-s", subnet1, "-d", address1, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	err = ipt.AppendUnique("filter", chain, "-s", subnet1, "-d", address1, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("AppendUnique failed: %v", err)
	}

	err = ipt.Append("filter", chain, "-s", subnet2, "-d", address1, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	err = ipt.Insert("filter", chain, 2, "-s", subnet2, "-d", address2, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	err = ipt.InsertUnique("filter", chain, 2, "-s", subnet2, "-d", address2, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	err = ipt.Insert("filter", chain, 1, "-s", subnet1, "-d", address2, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	err = ipt.Delete("filter", chain, "-s", subnet1, "-d", address2, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	err = ipt.Insert("filter", chain, 1, "-s", subnet1, "-d", address2, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	err = ipt.Replace("filter", chain, 1, "-s", subnet2, "-d", address2, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Replace failed: %v", err)
	}

	err = ipt.Delete("filter", chain, "-s", subnet2, "-d", address2, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	err = ipt.Append("filter", chain, "-s", address1, "-d", subnet2, "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	rules, err := ipt.List("filter", chain)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	expected := []string{
		"-N " + chain,
		"-A " + chain + " -s " + subnet1 + " -d " + address1 + " -j ACCEPT",
		"-A " + chain + " -s " + subnet2 + " -d " + address2 + " -j ACCEPT",
		"-A " + chain + " -s " + subnet2 + " -d " + address1 + " -j ACCEPT",
		"-A " + chain + " -s " + address1 + " -d " + subnet2 + " -j ACCEPT",
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
			"-A " + chain + " -s " + subnet1 + " -d " + address1 + " " + suffix,
			"-A " + chain + " -s " + subnet2 + " -d " + address2 + " " + suffix,
			"-A " + chain + " -s " + subnet2 + " -d " + address1 + " " + suffix,
			"-A " + chain + " -s " + address1 + " -d " + subnet2 + " " + suffix,
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
	_, address1CIDR, _ := net.ParseCIDR(address1)
	_, address2CIDR, _ := net.ParseCIDR(address2)
	_, subnet1CIDR, _ := net.ParseCIDR(subnet1)
	_, subnet2CIDR, _ := net.ParseCIDR(subnet2)

	expectedStructStats := []Stat{
		{0, 0, "ACCEPT", prot, opt, "*", "*", subnet1CIDR, address1CIDR, ""},
		{0, 0, "ACCEPT", prot, opt, "*", "*", subnet2CIDR, address2CIDR, ""},
		{0, 0, "ACCEPT", prot, opt, "*", "*", subnet2CIDR, address1CIDR, ""},
		{0, 0, "ACCEPT", prot, opt, "*", "*", address1CIDR, subnet2CIDR, ""},
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
