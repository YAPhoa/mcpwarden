package policy

import (
	"fmt"
	"path"

	"github.com/yaphoa/mcpwarden/internal/config"
)

type Policy struct{ cfg config.Policy }

func New(cfg config.Policy) (*Policy, error) {
	for _, r := range cfg.Rules {
		if _, err := path.Match(r.Match, "sample"); err != nil {
			return nil, fmt.Errorf("policy pattern %q: %w", r.Match, err)
		}
	}
	return &Policy{cfg}, nil
}
func (p *Policy) Allow(name string) bool {
	for _, r := range p.cfg.Rules {
		match, _ := path.Match(r.Match, name)
		if match {
			return r.Action == "allow"
		}
	}
	return p.cfg.Default != "deny"
}
