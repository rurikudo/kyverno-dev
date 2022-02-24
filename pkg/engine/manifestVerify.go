package engine

import (
	"fmt"
	"time"

	v1 "github.com/kyverno/kyverno/api/kyverno/v1"

	"github.com/go-logr/logr"
	"github.com/kyverno/kyverno/pkg/engine/response"
	k8smnfconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	"github.com/stolostron/integrity-shield/shield/pkg/shield"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func VerifyManifest(policyContext *PolicyContext) (resp *response.EngineResponse) {
	fmt.Println("VerifyManifest")
	resp = &response.EngineResponse{}

	policy := policyContext.Policy
	patchedResource := policyContext.NewResource
	logger := log.Log.WithName("EngineVerifyManifess").WithValues("policy", policy.Name,
		"kind", patchedResource.GetKind(), "namespace", patchedResource.GetNamespace(), "name", patchedResource.GetName())

	startTime := time.Now()
	defer func() {
		buildResponse(policyContext, resp, startTime)
		logger.V(4).Info("finished policy processing", "processingTime", resp.PolicyResponse.ProcessingTime.String(), "rulesApplied", resp.PolicyResponse.RulesAppliedCount)
	}()

	policyContext.JSONContext.Checkpoint()
	defer policyContext.JSONContext.Restore()

	for i := range policyContext.Policy.Spec.Rules {
		rule := &policyContext.Policy.Spec.Rules[i]
		if rule.VerifyManifest == nil {
			continue
		}

		if !matches(logger, rule, policyContext) {
			continue
		}

		policyContext.JSONContext.Restore()

		if err := LoadContext(logger, rule.Context, policyContext, rule.Name); err != nil {
			appendError(resp, rule, fmt.Sprintf("failed to load context: %s", err.Error()), response.RuleStatusError)
			continue
		}

		ruleCopy, err := substituteVariables(rule, policyContext.JSONContext, logger)
		if err != nil {
			appendError(resp, rule, fmt.Sprintf("failed to substitute variables: %s", err.Error()), response.RuleStatusError)
			continue
		}

		mv := &manifestVerifier{
			logger:        logger,
			policyContext: policyContext,
			rule:          ruleCopy,
			resp:          resp,
		}

		mv.verify(rule.VerifyManifest)

	}

	return
}

type manifestVerifier struct {
	logger        logr.Logger
	policyContext *PolicyContext
	rule          *v1.Rule
	resp          *response.EngineResponse
}

func (mv *manifestVerifier) verify(manifestVerify *k8smnfconfig.ParameterObject) {
	start := time.Now()
	kind := mv.policyContext.NewResource.GetKind()
	ns := mv.policyContext.NewResource.GetNamespace()
	name := mv.policyContext.NewResource.GetName()
	ruleResp := &response.RuleResponse{}
	// call ishield
	operation := "CREATE"
	if isUpdateRequest(mv.policyContext) {
		operation = "UPDATE"
	}
	err, allow, msg := shield.ManifestVerify(mv.policyContext.NewResource, mv.policyContext.OldResource, operation, mv.policyContext.AdmissionInfo.AdmissionUserInfo.Username, manifestVerify)
	fmt.Println("VerifyManifest verify: ", err, allow, msg)
	if err != nil {
		ruleResp.Status = response.RuleStatusFail
		ruleResp.Message = fmt.Sprintf("manifest verification failed for %s.%s: %v", kind, name, err)
	}
	if allow {
		ruleResp.Status = response.RuleStatusPass
	} else {
		ruleResp.Status = response.RuleStatusFail
	}
	ruleResp.Message = fmt.Sprintf("manifest %s.%s verified: %s", kind, name, msg)
	mv.logger.V(3).Info("verified manifest", "kind", kind, "namespace", ns, "name", name, "duration", time.Since(start).Seconds())
	mv.resp.PolicyResponse.Rules = append(mv.resp.PolicyResponse.Rules, *ruleResp)
	incrementAppliedCount(mv.resp)

}
