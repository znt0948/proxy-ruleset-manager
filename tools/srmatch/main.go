// srmatch matches names and addresses against rule sets with sing-box's own
// rule engine (the version clients run), for the differential tests.
//
// usage: srmatch set1.json set2.srs ... < probes
//
// Each input line is a domain name or an IP address; each output line lists
// the indexes (0-based, in argument order) of the rule sets that match it,
// comma-separated, empty when none does. .json files are read as source
// rule sets, .srs as compiled ones.
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

func load(path string) ([]adapter.HeadlessRule, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var compat option.PlainRuleSetCompat
	if filepath.Ext(path) == ".srs" {
		compat, err = srs.Read(bytes.NewReader(content), false)
	} else {
		compat, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	plain, err := compat.Upgrade()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	rules := make([]adapter.HeadlessRule, 0, len(plain.Rules))
	for i, options := range plain.Rules {
		r, err := rule.NewHeadlessRule(context.Background(), options)
		if err != nil {
			return nil, fmt.Errorf("%s: rules[%d]: %w", path, i, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: srmatch set.json|set.srs ... < probes")
		os.Exit(2)
	}
	var sets [][]adapter.HeadlessRule
	for _, path := range os.Args[1:] {
		rules, err := load(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		sets = append(sets, rules)
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for scanner.Scan() {
		probe := strings.TrimSpace(scanner.Text())
		var metadata adapter.InboundContext
		if address := M.ParseAddr(probe); address.IsValid() {
			metadata.Destination = M.SocksaddrFrom(address, 0)
		} else {
			metadata.Domain = probe
		}
		var matched []string
		for i, rules := range sets {
			for _, r := range rules {
				metadata.ResetRuleCache()
				if r.Match(&metadata) {
					matched = append(matched, strconv.Itoa(i))
					break
				}
			}
		}
		fmt.Fprintln(out, strings.Join(matched, ","))
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
