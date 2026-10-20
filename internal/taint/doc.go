// Package taint classifies untrusted sources using a built-in policy that M2 will
// replace with layered policy loading. Content detectors do not decide blocking.
// Session-level tracking is coarse and cannot capture every information flow.
package taint
