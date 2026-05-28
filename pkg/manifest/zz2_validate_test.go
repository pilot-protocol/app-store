package manifest

import (
	"strings"
	"testing"
)

// TestParse_BadJSON covers the json.Unmarshal error branch in Parse.
func TestParse_BadJSON(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte("not-json"))
	if err == nil {
		t.Error("Parse on bad JSON should error")
	}
}

// TestParse_EmptyDocument covers the empty-object branch.
func TestParse_EmptyDocument(t *testing.T) {
	t.Parallel()
	m, err := Parse([]byte("{}"))
	if err != nil {
		t.Fatalf("Parse({}) = %v", err)
	}
	if m == nil {
		t.Fatal("nil manifest")
	}
	// Validate on an empty manifest produces errors (all required
	// fields missing), exercising several Validate branches.
	errs := m.Validate()
	if len(errs) == 0 {
		t.Error("empty manifest should fail validation")
	}
}

// TestValidate_EmptyBinaryPath covers the binary.path empty branch.
func TestValidate_EmptyBinaryPath(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Binary.Path = "   " // whitespace-only
	errs := m.Validate()
	if !hasErrorContaining(errs, "binary.path") {
		t.Errorf("expected binary.path error, got: %v", errs)
	}
}

// TestValidate_EmptyStoreSignature covers the store.signature
// whitespace-only branch.
func TestValidate_EmptyStoreSignature(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Store.Signature = "   "
	errs := m.Validate()
	if !hasErrorContaining(errs, "store.signature") {
		t.Errorf("expected store.signature error, got: %v", errs)
	}
}

// TestValidate_BadStorePublisher covers the publisher-pattern branch.
func TestValidate_BadStorePublisher(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Store.Publisher = "not-a-pubkey"
	errs := m.Validate()
	if !hasErrorContaining(errs, "store.publisher") {
		t.Errorf("expected store.publisher error, got: %v", errs)
	}
}

// TestValidate_BadAffiliatePubkey covers the affiliates pubkey branch.
func TestValidate_BadAffiliatePubkey(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Affiliates = []Affiliate{{Pubkey: "bogus", Role: "settlement"}}
	errs := m.Validate()
	if !hasErrorContaining(errs, "affiliates[0].pubkey") {
		t.Errorf("expected affiliate pubkey error, got: %v", errs)
	}
}

// TestValidate_EmptyAffiliateRole covers the affiliate role branch.
func TestValidate_EmptyAffiliateRole(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Affiliates = []Affiliate{{
		Pubkey: "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		Role:   "   ",
	}}
	errs := m.Validate()
	if !hasErrorContaining(errs, "affiliates[0].role") {
		t.Errorf("expected affiliate role error, got: %v", errs)
	}
}

// TestValidate_EmptyDependsMethods covers the depends methods branch.
func TestValidate_EmptyDependsMethods(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Depends = []Dependency{{App: "io.other.app", Methods: nil}}
	errs := m.Validate()
	if !hasErrorContaining(errs, "depends[0].methods") {
		t.Errorf("expected depends methods error, got: %v", errs)
	}
}

// TestValidate_EmptyExtendsMethod covers the extends[].method branch.
func TestValidate_EmptyExtendsMethod(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Exposes = append(m.Exposes, "wallet.h")
	m.Extends = []Extension{{Primitive: "send-message.pre", Method: "   "}}
	errs := m.Validate()
	if !hasErrorContaining(errs, "extends[0].method") {
		t.Errorf("expected extends.method error, got: %v", errs)
	}
}

// TestValidate_GrantConditionInvalidLeaf covers the unknown-kind
// branch in validateCondition.
func TestValidate_GrantConditionInvalidLeaf(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Grants[1].Condition = &Condition{Kind: "made-up-kind"}
	errs := m.Validate()
	if !hasErrorContaining(errs, "made-up-kind") {
		t.Errorf("expected unknown-kind error, got: %v", errs)
	}
}

// TestValidate_GrantConditionEmptyMustError covers the "neither leaf
// nor composite" branch (empty condition).
func TestValidate_GrantConditionEmptyMustError(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Grants[1].Condition = &Condition{}
	errs := m.Validate()
	if !hasErrorContaining(errs, "must specify either kind or op") {
		t.Errorf("expected 'must specify' error, got: %v", errs)
	}
}

// TestValidate_GrantConditionBadOp covers the default-case (unknown
// op) branch.
func TestValidate_GrantConditionBadOp(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Grants[1].Condition = &Condition{
		Op: "xor", Compose: []Condition{{Kind: "rate"}, {Kind: "cap"}},
	}
	errs := m.Validate()
	if !hasErrorContaining(errs, "and|or|not") {
		t.Errorf("expected bad-op error, got: %v", errs)
	}
}

// TestValidate_GrantConditionNotNeedsExactlyOne covers the "not needs
// exactly 1" branch.
func TestValidate_GrantConditionNotNeedsExactlyOne(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Grants[1].Condition = &Condition{
		Op: "not", Compose: []Condition{{Kind: "rate"}, {Kind: "cap"}},
	}
	errs := m.Validate()
	if !hasErrorContaining(errs, "not needs exactly 1") {
		t.Errorf("expected not-arity error, got: %v", errs)
	}
}

// TestValidate_GrantConditionAndNeedsAtLeastTwo covers the and/or
// minimum-arity branch.
func TestValidate_GrantConditionAndNeedsAtLeastTwo(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Grants[1].Condition = &Condition{
		Op: "and", Compose: []Condition{{Kind: "rate"}},
	}
	errs := m.Validate()
	if !hasErrorContaining(errs, "needs at least 2") {
		t.Errorf("expected and-arity error, got: %v", errs)
	}
}

// TestValidate_NestedCompositeWalks covers the recursive walk over
// compose entries.
func TestValidate_NestedCompositeWalks(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	// Outer 'not' wrapping an inner kind=bad → recursion must surface
	// the inner error.
	m.Grants[1].Condition = &Condition{
		Op: "not", Compose: []Condition{{Kind: "no-such-kind"}},
	}
	errs := m.Validate()
	if !hasErrorContaining(errs, "no-such-kind") {
		t.Errorf("expected recursion to surface inner error, got: %v", errs)
	}
}

// TestValidate_GrantEmptyTarget covers the grant.target empty branch.
func TestValidate_GrantEmptyTarget(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	m.Grants[0].Target = "   "
	errs := m.Validate()
	if !hasErrorContaining(errs, "target must not be empty") {
		t.Errorf("expected target-empty error, got: %v", errs)
	}
}

// TestMarshal_PreservesStructuralFields confirms a roundtrip produces
// valid JSON containing the input fields. Doubles as smoke for
// Marshal().
func TestMarshal_PreservesStructuralFields(t *testing.T) {
	t.Parallel()
	m := mustValid(t)
	body, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{`"io.pilot.wallet"`, `"binary"`, `"grants"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body missing %s: %s", want, body)
		}
	}
}
