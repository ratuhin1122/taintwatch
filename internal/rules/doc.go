// Package rules will evaluate policy, session taint, and attempted actions.
// Default restrictions ask for approval; deny requires explicit user policy.
// Content detector matches alone never decide blocking.
package rules
