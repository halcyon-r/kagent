package substrate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kagent-dev/kagent/go/core/internal/egress"
)

const testControlPlaneURL = "http://kagent-controller.kagent.svc:8083"

func TestActorPolicyRequiresControlPlaneOrigin(t *testing.T) {
	for _, test := range []struct {
		name string
		url  string
	}{
		{"missing", ""},
		{"invalid", "kagent-controller.kagent.svc:8083"},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := ActorEgressPolicy("team", nil, nil, test.url)
			require.ErrorContains(t, err, "invalid runtime control-plane origin")
			require.Nil(t, policy)
		})
	}
}

func TestActorPolicyKeepsCredentialsOnExactOrigin(t *testing.T) {
	policy, err := ActorEgressPolicy("team", []string{"https://*.example.com", "https://api.example.com:443", "https://api.example.com:8443", "http://api.example.com"}, []egress.Credential{
		{Origin: "https://api.example.com", Header: "authorization", Prefix: "Bearer ", URI: "ate-secret://k8s.io/default/team/auth/token"},
		{Origin: "https://api.example.com:8443", Header: "x-api-key", URI: "ate-secret://k8s.io/default/team/other/key"},
	}, testControlPlaneURL)
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
	const controlPlane = testControlPlaneURL
	policy, err := ActorEgressPolicy("team", []string{controlPlane, "https://models.example"}, nil, "http://KAGENT-CONTROLLER.kagent.svc.:8083")
	require.NoError(t, err)
	headers := policy.Rules[0].GetHttp().GetEffects().GetReplaceHeaders()
	require.Len(t, headers, 1)
	require.Equal(t, "authorization", headers[0].Header)
	require.Equal(t, "Bearer ", headers[0].Prefix)
	require.Empty(t, headers[0].CredentialUri)
	require.Equal(t, []string{runtimeJWTAudience}, headers[0].ActorJwt.Audiences)
	require.EqualValues(t, 300, headers[0].ActorJwt.ExpirationSeconds)
	require.Empty(t, policy.Rules[1].GetHttps().GetEffects().GetReplaceHeaders())
	policy, err = ActorEgressPolicy("team", nil, nil, controlPlane)
	require.NoError(t, err)
	require.Empty(t, policy.Rules, "runtime authentication must not grant sandbox network access")
	_, err = ActorEgressPolicy("team", []string{controlPlane}, []egress.Credential{
		{Origin: controlPlane, Header: "Authorization", URI: "ate-secret://k8s.io/default/team/auth/token"},
	}, controlPlane)
	require.Error(t, err, "a credential binding must not override runtime identity")
}
