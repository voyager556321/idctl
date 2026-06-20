package adapter

import (
	"context"
	"strings"

	"github.com/voyager556321/idctl/internal/model"
	"github.com/voyager556321/idctl/internal/sys"
)

type Kube struct{}

func (Kube) Name() string { return "kubectl" }

func (Kube) Read(ctx context.Context, id *model.Identity) {
	if !sys.Has("kubectl") {
		return
	}
	k := &id.Kube
	k.Present = true
	k.Context, _ = sys.Out(ctx, "kubectl", "config", "current-context")
	k.Namespace, _ = sys.Out(ctx, "kubectl", "config", "view", "--minify",
		"-o", "jsonpath={..namespace}")
}

func (Kube) Diff(id *model.Identity, p *model.Profile) []model.Mismatch {
	var out []model.Mismatch
	k := id.Kube
	if !k.Present || p.Kube.Context == "" {
		return out
	}
	if k.Context != p.Kube.Context {
		risk := model.RiskMedium
		explain := "kubectl is pointed at the wrong context"
		if isProd(k.Context) || isProd(p.Kube.Context) {
			risk = model.RiskHigh
			explain = "kubectl context mismatch involving a production cluster"
		}
		out = append(out, model.Mismatch{
			Adapter: "kubectl", Field: "context",
			Current: k.Context, Expected: p.Kube.Context,
			Risk: risk, Explain: explain,
		})
	}
	if p.Kube.Namespace != "" && k.Namespace != p.Kube.Namespace {
		out = append(out, model.Mismatch{
			Adapter: "kubectl", Field: "namespace",
			Current: k.Namespace, Expected: p.Kube.Namespace,
			Risk: model.RiskLow, Explain: "kubectl default namespace differs from the expected profile",
		})
	}
	return out
}

func isProd(s string) bool {
	return strings.Contains(strings.ToLower(s), "prod")
}
