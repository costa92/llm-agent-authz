package role

import "testing"

func TestRankOrdering(t *testing.T) {
	if !(RoleOrgAdmin.Rank() > RoleAdmin.Rank() &&
		RoleAdmin.Rank() > RoleEditor.Rank() &&
		RoleEditor.Rank() > RoleViewer.Rank()) {
		t.Fatalf("rank ordering wrong: orgAdmin=%d admin=%d editor=%d viewer=%d",
			RoleOrgAdmin.Rank(), RoleAdmin.Rank(), RoleEditor.Rank(), RoleViewer.Rank())
	}
}

func TestMergeTakesHighest(t *testing.T) {
	if got := Merge(RoleViewer, RoleAdmin); got != RoleAdmin {
		t.Fatalf("Merge(viewer,admin)=%q, want admin", got)
	}
	if got := Merge(RoleEditor, RoleOrgAdmin); got != RoleOrgAdmin {
		t.Fatalf("Merge(editor,orgAdmin)=%q, want org_admin", got)
	}
	if got := Merge(); got != RoleNone {
		t.Fatalf("Merge()=%q, want none", got)
	}
	if got := Merge(RoleNone, RoleViewer); got != RoleViewer {
		t.Fatalf("Merge(none,viewer)=%q, want viewer", got)
	}
}

func TestAtLeast(t *testing.T) {
	if !RoleAdmin.AtLeast(RoleEditor) {
		t.Fatal("admin should satisfy editor minimum")
	}
	if RoleViewer.AtLeast(RoleEditor) {
		t.Fatal("viewer must NOT satisfy editor minimum")
	}
	if RoleNone.AtLeast(RoleViewer) {
		t.Fatal("none must NOT satisfy viewer minimum")
	}
}

func TestParseRejectsUnknown(t *testing.T) {
	if _, err := Parse("superuser"); err == nil {
		t.Fatal("Parse(superuser) should error")
	}
	r, err := Parse("editor")
	if err != nil || r != RoleEditor {
		t.Fatalf("Parse(editor)=%q,%v", r, err)
	}
}
