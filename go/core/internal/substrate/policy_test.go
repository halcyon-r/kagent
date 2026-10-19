package substrate

import (
	"testing"

	"github.com/stretchr/testify/require"

	apia2a "github.com/kagent-dev/kagent/go/api/a2a"
	"github.com/kagent-dev/kagent/go/core/internal/egress"
)

func TestActorPolicyKeepsCredentialsOnExactOrigin(t *testing.T) {
	policy, err := ActorEgressPolicy("team", []string{"https://*.example.com", "https://api.example.com:443", "https://api.example.com:8443", "http://api.example.com"}, []egress.Credential{
		{Origin: "https://api.example.com", Header: "authorization", Prefix: "Bearer ", URI: "ate-secret://k8s.io/default/team/auth/token"},
		{Origin: "https://api.example.com:8443", Header: "x-api-key", URI: "ate-secret://k8s.io/default/team/other/key"},
	}, "")
	require.NoError(t, err)
	require.Len(t, policy.Rules, 4)
	require.Empty(t, policy.Rules[0].GetHttp().GetEffects().GetReplaceHeaders())
	require.Equal(t, []string{"*.example.com"}, policy.Rules[1].GetHttps().GetHostnames())
	require.Empty(t, policy.Rules[1].GetHttps().GetEffects().GetReplaceHeaders())
	for i, header := range []string{"authorization", "x-api-key"} {
		rule := policy.Rules[i+2].GetHttps()
		require.Equal(t, []string{"api.example.com"}, rule.GetHostnames())
		require.Len(t, rule.GetEffects().GetReplaceHeaders(), 1)
		require.Equal(t, header, rule.GetEffects().GetReplaceHeaders()[0].Header)
	}
	require.Equal(t, []int32{443}, policy.Rules[2].GetHttps().GetPorts().GetNumbers())
	require.Equal(t, []int32{8443}, policy.Rules[3].GetHttps().GetPorts().GetNumbers())
}

func TestActorPolicyInjectsRuntimeJWTOnlyAtControlPlane(t *testing.T) {
	const controlPlane = "http://kagent-controller.kagent.svc:8083"
	policy, err := ActorEgressPolicy("team", []string{controlPlane, "https://models.example"}, []egress.Credential{
		{Origin: controlPlane, Header: "authorization", URI: "ate-secret://k8s.io/default/team/auth/token"},
	}, "http://KAGENT-CONTROLLER.kagent.svc.:8083")
	require.NoError(t, err)
	headers := policy.Rules[0].GetHttp().GetEffects().GetReplaceHeaders()
	require.Len(t, headers, 2)
	require.Equal(t, "authorization", headers[0].Header, "public credentials coexist with runtime authentication")
	require.Equal(t, apia2a.RuntimeAuthorizationHeader, headers[1].Header)
	require.Equal(t, "Bearer ", headers[1].Prefix)
	require.Empty(t, headers[1].CredentialUri)
	require.Equal(t, []string{runtimeJWTAudience}, headers[1].ActorJwt.Audiences)
	require.EqualValues(t, 300, headers[1].ActorJwt.ExpirationSeconds)
	require.Empty(t, policy.Rules[1].GetHttps().GetEffects().GetReplaceHeaders())
	policy, err = ActorEgressPolicy("team", nil, nil, controlPlane)
	require.NoError(t, err)
	require.Empty(t, policy.Rules, "runtime authentication must not grant sandbox network access")
	_, err = ActorEgressPolicy("team", []string{controlPlane}, []egress.Credential{
		{Origin: controlPlane, Header: "X-Kagent-Runtime-Authorization", URI: "ate-secret://k8s.io/default/team/auth/token"},
	}, controlPlane)
	require.Error(t, err, "a credential binding must not override runtime identity")
}
