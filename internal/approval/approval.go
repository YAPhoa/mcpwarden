package approval

import "context"

type Request struct{ Tool, Upstream, ArgsHash string }
type Approver interface {
	Approve(context.Context, Request) (bool, error)
}
type None struct{}

func (None) Approve(context.Context, Request) (bool, error) { return true, nil }
