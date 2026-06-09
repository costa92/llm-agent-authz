// Package role defines the RBAC role enum and the org⊕scope merge algebra
// shared by all llm-agent-authz consumers. Pure: no I/O.
package role

import "fmt"

type Role string

const (
	RoleNone     Role = ""
	RoleViewer   Role = "viewer"
	RoleEditor   Role = "editor"
	RoleAdmin    Role = "admin"
	RoleOrgAdmin Role = "org_admin"
)

// Rank returns a total order; higher is more privileged.
func (r Role) Rank() int {
	switch r {
	case RoleOrgAdmin:
		return 4
	case RoleAdmin:
		return 3
	case RoleEditor:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether r is at least as privileged as min.
func (r Role) AtLeast(min Role) bool { return r.Rank() >= min.Rank() && r.Rank() > 0 }

// Merge returns the highest-ranked role among the inputs (RoleNone if empty).
func Merge(roles ...Role) Role {
	best := RoleNone
	for _, r := range roles {
		if r.Rank() > best.Rank() {
			best = r
		}
	}
	return best
}

// Parse validates and converts a string to a Role.
func Parse(s string) (Role, error) {
	switch Role(s) {
	case RoleViewer, RoleEditor, RoleAdmin, RoleOrgAdmin:
		return Role(s), nil
	default:
		return RoleNone, fmt.Errorf("authz: unknown role %q", s)
	}
}
