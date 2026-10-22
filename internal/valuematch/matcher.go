package valuematch

// Pattern associates a bounded literal with a safe source label, not its body.
type Pattern struct{ Text, Source string }
type node struct {
	edge, fail, output int32
}

type edge struct {
	next, child int32
	value       byte
}

// Matcher is a sparse Aho-Corasick automaton. Only one output is needed: the
// rule asks on the first match. Failure outputs are propagated during compile.
type Matcher struct {
	nodes   []node
	edges   []edge
	sources []string
}

// step scans at most 256 edges (the fixed byte alphabet). Flat edge storage
// avoids one Go map/allocation per trie node while preserving bounded linear
// matching and the original first-pattern output precedence.
func (m *Matcher) step(n int32, value byte) int32 {
	for e := m.nodes[n].edge; e != 0; e = m.edges[e].next {
		if m.edges[e].value == value {
			return m.edges[e].child
		}
	}
	return 0
}

func Compile(patterns []Pattern) *Matcher {
	budget := 0
	for _, p := range patterns {
		if len(p.Text) >= 2 && budget+len(p.Text) <= MaxPatternBytes {
			budget += len(p.Text)
		}
	}
	m := &Matcher{nodes: make([]node, 1, budget+1), edges: make([]edge, 1, budget+1)}
	m.nodes[0].output = -1
	used := 0
	for _, p := range patterns {
		if len(p.Text) < 2 || used+len(p.Text) > MaxPatternBytes {
			continue
		}
		used += len(p.Text)
		n := int32(0)
		for i := 0; i < len(p.Text); i++ {
			next := m.step(n, p.Text[i])
			if next == 0 {
				next = int32(len(m.nodes)) // bounded by MaxPatternBytes+1
				m.nodes = append(m.nodes, node{output: -1})
				m.edges = append(m.edges, edge{m.nodes[n].edge, next, p.Text[i]})
				m.nodes[n].edge = int32(len(m.edges) - 1)
			}
			n = next
		}
		if m.nodes[n].output < 0 {
			m.nodes[n].output = int32(len(m.sources))
			m.sources = append(m.sources, p.Source)
		}
	}
	queue := make([]int32, 0, len(m.nodes))
	for e := m.nodes[0].edge; e != 0; e = m.edges[e].next {
		queue = append(queue, m.edges[e].child)
	}
	for head := 0; head < len(queue); head++ {
		n := queue[head]
		for e := m.nodes[n].edge; e != 0; e = m.edges[e].next {
			b, child := m.edges[e].value, m.edges[e].child
			queue = append(queue, child)
			f := m.nodes[n].fail
			for f != 0 && m.step(f, b) == 0 {
				f = m.nodes[f].fail
			}
			m.nodes[child].fail = m.step(f, b)
			if m.nodes[child].output < 0 {
				m.nodes[child].output = m.nodes[m.nodes[child].fail].output
			}
		}
	}
	return m
}

// Match is linear in argument length; it never concatenates separate arguments.
func (m *Matcher) Match(text string) (string, bool) {
	if len(text) > MaxTextBytes {
		text = text[:MaxTextBytes]
	}
	n := int32(0)
	for i := 0; i < len(text); i++ {
		for n != 0 && m.step(n, text[i]) == 0 {
			n = m.nodes[n].fail
		}
		n = m.step(n, text[i])
		if o := m.nodes[n].output; o >= 0 {
			return m.sources[o], true
		}
	}
	return "", false
}
