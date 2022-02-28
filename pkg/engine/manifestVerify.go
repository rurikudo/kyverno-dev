package engine

import (
	"fmt"
	"os"
	"time"

	v1 "github.com/kyverno/kyverno/api/kyverno/v1"

	"github.com/go-logr/logr"
	"github.com/kyverno/kyverno/pkg/config"
	"github.com/kyverno/kyverno/pkg/engine/response"
	k8smnfconfig "github.com/stolostron/integrity-shield/shield/pkg/config"
	"github.com/stolostron/integrity-shield/shield/pkg/shield"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func VerifyResource(policyContext *PolicyContext) (resp *response.EngineResponse) {
	resp = &response.EngineResponse{}

	policy := policyContext.Policy
	patchedResource := policyContext.NewResource
	logger := log.Log.WithName("EngineVerifyResource").WithValues("policy", policy.Name,
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
		if rule.VerifyResource == nil {
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

		mv := &resourceVerifier{
			logger:        logger,
			policyContext: policyContext,
			rule:          ruleCopy,
			resp:          resp,
		}

		mv.verify(rule.VerifyResource)

	}

	return
}

type resourceVerifier struct {
	logger        logr.Logger
	policyContext *PolicyContext
	rule          *v1.Rule
	resp          *response.EngineResponse
}

func (mv *resourceVerifier) verify(resourceVerify *k8smnfconfig.ManifestIntegrityConstraint) {
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
	namespace := config.KyvernoNamespace
	// define dry-run namespace
	os.Setenv("POD_NAMESPACE", namespace)
	// get integrity shield config
	shieldConfig, err := k8smnfconfig.LoadRequestHandlerConfig(namespace, "")
	if err != nil {
		ruleResp.Status = response.RuleStatusFail
		ruleResp.Message = fmt.Sprintf("k8s resource verification failed for %s.%s: %v", kind, name, err)
	} else if shieldConfig == nil {
		ruleResp.Status = response.RuleStatusFail
		ruleResp.Message = fmt.Sprintf("k8s resource verification failed for %s.%s: %v", kind, name, "shieldConfig is nil")
	} else {
		// manifest verify
		err, allow, msg := shield.ResourceVerify(mv.policyContext.NewResource, mv.policyContext.OldResource, operation, mv.policyContext.AdmissionInfo.AdmissionUserInfo.Username, shieldConfig.RequestFilterProfile, resourceVerify)
		if err != nil {
			ruleResp.Status = response.RuleStatusFail
			ruleResp.Message = fmt.Sprintf("k8s resource verification failed for %s.%s: %v", kind, name, err)
		}
		if allow {
			ruleResp.Status = response.RuleStatusPass
		} else {
			ruleResp.Status = response.RuleStatusFail
		}
		ruleResp.Message = fmt.Sprintf("resource %s.%s verified: %s", kind, name, msg)
	}
	mv.logger.V(3).Info("verified k8s resource", "kind", kind, "namespace", ns, "name", name, "duration", time.Since(start).Seconds())
	mv.resp.PolicyResponse.Rules = append(mv.resp.PolicyResponse.Rules, *ruleResp)
	incrementAppliedCount(mv.resp)

}
