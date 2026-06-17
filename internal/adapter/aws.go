package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"idctl/internal/model"
	"idctl/internal/sys"
)

type AWS struct{}

func (AWS) Name() string { return "aws" }

func (AWS) Read(ctx context.Context, id *model.Identity) {
	a := &id.AWS
	a.Present = sys.Has("aws")
	if p := os.Getenv("AWS_PROFILE"); p != "" {
		a.Profile, a.Source = p, "env"
	} else if os.Getenv("AWS_ACCESS_KEY_ID") != "" {
		a.Profile, a.Source = "(env credentials)", "env"
	} else {
		a.Profile, a.Source = "default", "default"
	}
}

// Verify performs the online STS call. Called only by `doctor` / `status --verify`
// because it is slow and requires connectivity + valid credentials. It only
// READS identity; it never assumes a role or writes anything.
func (AWS) Verify(ctx context.Context, id *model.Identity) {
	if !id.AWS.Present {
		return
	}
	out, err := sys.Out(ctx, "aws", "sts", "get-caller-identity", "--output", "json")
	if err != nil {
		return
	}
	var v struct{ Account, Arn string }
	if json.Unmarshal([]byte(out), &v) == nil {
		id.AWS.Account, id.AWS.Arn, id.AWS.Verified = v.Account, v.Arn, true
	}
}

func (AWS) Diff(id *model.Identity, p *model.Profile) []model.Mismatch {
	if p.AWS.Profile == "" {
		return nil
	}
	a := id.AWS
	if a.Profile == p.AWS.Profile {
		return nil
	}
	risk := model.RiskMedium
	explain := "active AWS profile differs from the expected profile"
	if a.Verified {
		risk = model.RiskHigh
		explain = fmt.Sprintf("AWS calls would hit account %s, not the expected profile", a.Account)
	}
	return []model.Mismatch{{
		Adapter: "aws", Field: "profile",
		Current: a.Profile, Expected: p.AWS.Profile,
		Risk: risk, Explain: explain,
	}}
}
