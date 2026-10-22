package valuematch

import (
	"fmt"
	"testing"
)

func BenchmarkCompileRetainedIndicators(b *testing.B) {
	patterns := []Pattern{}
	for i := 0; i < MaxSessionValues; i++ {
		value := fmt.Sprintf("https://source-%d.example.net/docs/%d", i/4, i%4)
		patterns = append(patterns, Pattern{value, "WebFetch"})
		for _, variant := range Variants(value) {
			patterns = append(patterns, Pattern{variant, "WebFetch"})
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Compile(patterns).Match("go test ./...")
	}
}
