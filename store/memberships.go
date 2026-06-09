package store

import (
	"context"

	"github.com/costa92/llm-agent-authz/role"
)

func (s *Store) UpsertMembership(ctx context.Context, orgID, userID, scopeKind string, scopeID *string, r role.Role) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth_membership (org_id, user_id, scope_kind, scope_id, role)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (org_id, user_id, scope_kind, COALESCE(scope_id, ''))
		 DO UPDATE SET role = EXCLUDED.role`,
		orgID, userID, scopeKind, scopeID, string(r))
	return err
}

func (s *Store) ResolveRole(ctx context.Context, userID, orgID, scopeKind, scopeID string) (role.Role, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT role FROM auth_membership
		 WHERE user_id = $1 AND org_id = $2 AND scope_kind = $3
		   AND (scope_id IS NULL OR scope_id = $4)`,
		userID, orgID, scopeKind, scopeID)
	if err != nil {
		return role.RoleNone, err
	}
	defer rows.Close()
	var found []role.Role
	for rows.Next() {
		var rs string
		if err := rows.Scan(&rs); err != nil {
			return role.RoleNone, err
		}
		found = append(found, role.Role(rs))
	}
	if err := rows.Err(); err != nil {
		return role.RoleNone, err
	}
	return role.Merge(found...), nil
}
