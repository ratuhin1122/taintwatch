package valuematch

// Pattern associates a bounded literal with a safe source label, not its body.
type Pattern struct{ Text, Source string }
type node struct {
	next         map[byte]int
	fail, output int
}

// Matcher is a sparse Aho-Corasick automaton. Only one output is needed: the
// rule asks on the first match. Failure outputs are propagated during compile.
type Matcher struct {
	nodes   []node
	sources []string
}

func Compile(patterns []Pattern) *Matcher {
	m := &Matcher{nodes: []node{{output: -1}}}
	used := 0
	for _, p := range patterns {
		if len(p.Text) < 2 || used+len(p.Text) > MaxPatternBytes {
			continue
		}
		used += len(p.Text)
		n := 0
		for i := 0; i < len(p.Text); i++ {
			if m.nodes[n].next == nil {
				m.nodes[n].next = map[byte]int{}
			}
			next, ok := m.nodes[n].next[p.Text[i]]
			if !ok {
				next = len(m.nodes)
				m.nodes = append(m.nodes, node{output: -1})
				m.nodes[n].next[p.Text[i]] = next
			}
			n = next
		}
		if m.nodes[n].output < 0 {
			m.nodes[n].output = len(m.sources)
			m.sources = append(m.sources, p.Source)
		}
	}
	queue := []int{}
	for _, n := range m.nodes[0].next {
		queue = append(queue, n)
	}
	for head := 0; head < len(queue); head++ {
		n := queue[head]
		for b, child := range m.nodes[n].next {
			queue = append(queue, child)
			f := m.nodes[n].fail
			for f != 0 {
				if _, ok := m.nodes[f].next[b]; ok {
					break
				}
				f = m.nodes[f].fail
			}
			m.nodes[child].fail = m.nodes[f].next[b]
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
	n := 0
	for i := 0; i < len(text); i++ {
		for n != 0 {
			if _, ok := m.nodes[n].next[text[i]]; ok {
				break
			}
			n = m.nodes[n].fail
		}
		n = m.nodes[n].next[text[i]]
		if o := m.nodes[n].output; o >= 0 {
			return m.sources[o], true
		}
	}
	return "", false
}
