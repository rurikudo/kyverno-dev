package webhooks

import (
	"errors"

	"github.com/go-logr/logr"
	v1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/engine"
	"github.com/kyverno/kyverno/pkg/engine/response"
	"github.com/kyverno/kyverno/pkg/policyreport"
	"k8s.io/api/admission/v1beta1"
)

func (ws *WebhookServer) applyManifestVerifyPolicies(request *v1beta1.AdmissionRequest, policyContext *engine.PolicyContext, policies []*v1.ClusterPolicy, logger logr.Logger) error {
	ok, message := ws.handleVerifyManifest(request, policyContext, policies)
	if !ok {
		return errors.New(message)
	}

	logger.V(6).Info("manifest verified")
	return nil
}

func (ws *WebhookServer) handleVerifyManifest(request *v1beta1.AdmissionRequest,
	policyContext *engine.PolicyContext,
	policies []*v1.ClusterPolicy) (bool, string) {

	if len(policies) == 0 {
		return true, ""
	}

	resourceName := getResourceName(request)
	logger := ws.log.WithValues("action", "verifyManifest", "resource", resourceName, "operation", request.Operation, "gvk", request.Kind.String())

	var engineResponses []*response.EngineResponse
	var patches [][]byte
	for _, p := range policies {
		policyContext.Policy = *p
		resp := engine.VerifyManifest(policyContext)
		engineResponses = append(engineResponses, resp)
		patches = append(patches, resp.GetPatches()...)
	}

	prInfos := policyreport.GeneratePRsFromEngineResponse(engineResponses, logger)
	ws.prGenerator.Add(prInfos...)

	blocked := toBlockResource(engineResponses, logger)
	if blocked {
		logger.V(4).Info("resource blocked")
		return false, getEnforceFailureErrorMsg(engineResponses)
	}

	return true, ""
}
