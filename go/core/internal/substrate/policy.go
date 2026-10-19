package substrate

import (
	"fmt"
	"strconv"

	"go.ate.dev/substrate/pkg/proto/ateapipb"

	"github.com/kagent-dev/kagent/go/core/internal/egress"
)

// ActorEgressPolicy compiles HTTP(S) origins into an actor's default allowlist.
// Credential bindings are already canonicalized by the store.
func ActorEgressPolicy(atespace string, destinations []string, credentials []egress.Credential, controlPlaneURL string) (*ateapipb.EgressPolicy, error) {
	access, err := egress.CanonicalAccess(destinations, credentials, nil)
	if err != nil {
		return nil, err
	}
	u, err := egress.ParseOrigin(controlPlaneURL)
	if err != nil {
		return nil, fmt.Errorf("invalid runtime control-plane origin: %w", err)
	}
	runtimeOrigin := u.String()
	effects := map[string]*ateapipb.HttpRuleEffects{}
	for _, binding := range access.Credentials {
		if binding.Origin == runtimeOrigin && binding.Header == "authorization" {
			return nil, fmt.Errorf("runtime authorization header is reserved for Actor JWTs")
		}
		if effects[binding.Origin] == nil {
			effects[binding.Origin] = &ateapipb.HttpRuleEffects{}
		}
		effects[binding.Origin].ReplaceHeaders = append(effects[binding.Origin].ReplaceHeaders, &ateapipb.CredentialHeader{Header: binding.Header, Prefix: binding.Prefix, CredentialUri: binding.URI})
	}
	policy := &ateapipb.EgressPolicy{Metadata: &ateapipb.ResourceMetadata{Atespace: atespace, Name: "default"}}
	for _, origin := range access.Destinations {
		if origin == runtimeOrigin {
			if effects[origin] == nil {
				effects[origin] = &ateapipb.HttpRuleEffects{}
			}
			effects[origin].ReplaceHeaders = append(effects[origin].ReplaceHeaders, &ateapipb.CredentialHeader{
				Header: "authorization", Prefix: "Bearer ",
				ActorJwt: &ateapipb.ActorJwtSource{Audiences: []string{runtimeJWTAudience}, ExpirationSeconds: 300},
			})
		}
		target, _ := egress.ParseOrigin(origin) // validated by CanonicalAccess
		port, _ := strconv.ParseInt(target.Port(), 10, 32)
		ports := &ateapipb.Ports{Numbers: []int32{int32(port)}}
		// One rule per origin: exact matches win over wildcard rules, keeping
		// credentials on their exact origin even when a wildcard also grants access.
		if target.Scheme == "https" {
			policy.Rules = append(policy.Rules, &ateapipb.EgressRule{Https: &ateapipb.HttpsRule{Hostnames: []string{target.Hostname()}, Ports: ports, Effects: effects[origin]}})
		} else {
			policy.Rules = append(policy.Rules, &ateapipb.EgressRule{Http: &ateapipb.HttpRule{Hostnames: []string{target.Hostname()}, Ports: ports, Effects: effects[origin]}})
		}
	}
	return policy, nil
}
