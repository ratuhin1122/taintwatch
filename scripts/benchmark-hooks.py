#!/usr/bin/env python3
"""Reproduce local hook process latency with synthetic, private persistent data."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--launcher', type=Path)
    parser.add_argument('--sessions', type=int, default=10000)
    parser.add_argument('--audit-mib', type=int, default=32)
    parser.add_argument('--samples', type=int, default=200)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, help='existing local filesystem directory for private fixtures')
    args = parser.parse_args()
    if min(args.sessions, args.audit_mib, args.samples) < 1 or args.samples < 100:
        parser.error('positive fixture sizes and at least 100 samples are required')
    binary = args.binary.resolve(strict=True)
    launcher = args.launcher.resolve(strict=True) if args.launcher else None
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='taintwatch-latency-', dir=args.work_dir) as temporary:
        base = Path(temporary)
        project, user, state = base/'project', base/'user', base/'state'
        for path in (project, user/'.config/taintwatch', state/'sessions', project/'.taintwatch'):
            path.mkdir(parents=True, mode=0o700)
        (project/'.env').write_text('BENCHMARK_ONLY=fake\n', encoding='utf-8')
        user_policy = '''version: 1
fail_mode: closed
profile: balanced
allow_project_loosening: false
egress:
  allow_domains:
    append: [docs.example.net, packages.example.net, git.example.net, registry.example.net]
secrets:
  paths:
    append: ['*.secret', '**/credentials/**', '**/private/**']
protected_writes:
  append: ['**/deploy/**', '**/infrastructure/**']
sources:
  mcp:
    trusted_servers:
      append: [internal_docs]
  bash:
    reader_commands:
      append: ['company issues view', 'company docs get']
log:
  rotation:
    max_bytes: 67108864
    keep: 3
state:
  retention_days: 7
'''
        project_policy = "version: 1\nprotected_writes:\n  append: ['**/production/**']\n"
        (user/'.config/taintwatch/policy.yaml').write_text(user_policy, encoding='utf-8')
        (project/'.taintwatch/policy.yaml').write_text(project_policy, encoding='utf-8')
        env = {k: v for k, v in os.environ.items() if not k.startswith('TAINTWATCH_') and k not in ('HOME', 'XDG_STATE_HOME', 'GOMAXPROCS')}
        env.update(HOME=str(user), TAINTWATCH_HOME=str(state), TAINTWATCH_NO_BOOTSTRAP='1')
        def payload(kind, tool='', tool_input=None, response=None):
            data = dict(session_id='latency-session', cwd=str(project), hook_event_name=kind, transcript_path=str(base/'unused-transcript.jsonl'))
            if tool:
                data.update(tool_name=tool, tool_input=tool_input or {}, tool_use_id='benchmark-use')
            if response is not None:
                data['tool_response'] = response
            if kind == 'UserPromptSubmit':
                data['prompt'] = 'Please review this log.\n```text\n' + 'INFO completed routine step\n'*128 + '```'
            return json.dumps(data).encode()
        def invoke(command, data):
            start = time.perf_counter_ns()
            result = subprocess.run(command, input=data, cwd=project, env=env, capture_output=True, timeout=3)
            elapsed = time.perf_counter_ns()-start
            if result.returncode or result.stderr:
                raise RuntimeError('hook failed: '+result.stderr.decode(errors='replace'))
            return elapsed, result.stdout
        # Real post hooks seed current-session indicators; no manually invented variants.
        for number in range(20):
            text = 'Public reference\n' + '\n'.join(f'https://source-{number}.example.net/docs/{i}' for i in range(4))
            invoke([str(binary), 'hook', 'post'], payload('PostToolUse', 'WebFetch', {'url':'https://docs.example.net/guide'}, text))
        seed = (state/'sessions/latency-session.json').read_bytes()
        stamp = '2026-10-23T00:00:00Z'
        # File mtime, not embedded event date, controls retention cleanup.
        for number in range(args.sessions):
            record = dict(id=f'fixture-{number}', tainted=False, created_at=stamp, updated_at=stamp)
            (state/'sessions'/f'fixture-{number}.json').write_text(json.dumps(record)+'\n', encoding='utf-8')
        log_record = dict(ts=stamp, session='fixture', hook='PreToolUse', tool='Bash', decision='allow', rule='default.allow', reason='Synthetic benchmark history. '*16, tainted=False, state_known=True, taint_sources=[], input_summary='tool arguments and response omitted', fail_mode='closed')
        line = (json.dumps(log_record)+'\n').encode()
        lines = math.ceil(args.audit_mib*1024*1024/len(line))
        with (state/'audit.jsonl').open('wb') as stream:
            for _ in range(lines):
                stream.write(line)
        initial_audit_bytes = (state/'audit.jsonl').stat().st_size
        cases = [
            ('pre-benign', [str(binary),'hook','pre'], payload('PreToolUse','Bash',{'command':'go test ./...'}), '{}'),
            ('pre-secret', [str(binary),'hook','pre'], payload('PreToolUse','Read',{'file_path':str(project/'.env')}), 'ask'),
            ('post-web-32k', [str(binary),'hook','post'], payload('PostToolUse','WebFetch',{'url':'https://docs.example.net/reference'}, ('Public reference text. '*2000)[:32768]), 'additionalContext'),
            ('prompt-log', [str(binary),'hook','prompt'], payload('UserPromptSubmit'), ''),
        ]
        if launcher:
            plugin = base/'plugin'
            (plugin/'bin').mkdir(parents=True)
            os.symlink(binary, plugin/'bin'/('taintwatch-'+platform.system().lower()+'-'+('arm64' if platform.machine() in ('arm64','aarch64') else 'amd64')))
            env['CLAUDE_PLUGIN_ROOT']=str(plugin)
            launcher_copy=plugin/'bin/taintwatch-launcher'
            launcher_copy.write_bytes(launcher.read_bytes())
            launcher_copy.chmod(0o700)
            cases.append(('launcher-pre-benign',['sh',str(launcher_copy),'hook','pre'],cases[0][2],'{}'))
        report = dict(platform=platform.platform(), python=platform.python_version(), logical_cpus=os.cpu_count(), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), sessions=args.sessions+1, session_bytes=len(seed), retained_events=20, audit_bytes=initial_audit_bytes, policy_sha256=hashlib.sha256((user_policy+project_policy).encode()).hexdigest(), samples=args.samples, warmup=10, statistic='median and nearest-rank p99 of fresh-process wall-clock duration; fixture reset excluded', cases=[])
        report['fixture_parent']=str(base.parent)
        report['launcher_sha256']=hashlib.sha256(launcher.read_bytes()).hexdigest() if launcher else None
        if platform.system()=='Linux':
            report['filesystem']=subprocess.check_output(['stat','-f','-c','%T',str(base)],text=True).strip()
            report['cpu_model']=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown')
        for name, command, data, expected in cases:
            samples=[]
            for number in range(args.samples+10):
                (state/'sessions/latency-session.json').write_bytes(seed)
                elapsed, output=invoke(command,data)
                text=output.decode()
                if expected and expected not in text or not expected and text:
                    raise RuntimeError('unexpected hook decision for '+name+': '+text)
                if number>=10:
                    samples.append(elapsed/1e6)
            ordered=sorted(samples)
            report['cases'].append(dict(name=name, median_ms=statistics.median(samples), p99_ms=ordered[math.ceil(.99*len(ordered))-1], min_ms=min(samples), max_ms=max(samples), samples_ms=samples))
        # Evidence that these were successful persistent hooks, not fast error paths.
        managed_files=[state/'.lock', state/'audit.jsonl', state/'sessions/latency-session.json']
        report['file_modes']={p.name:oct(p.stat().st_mode & 0o777) for p in managed_files}
        report['directory_modes']={str(p.relative_to(base)):oct(p.stat().st_mode & 0o777) for p in (state,state/'sessions')}
        if set(report['file_modes'].values()) != {'0o600'} or set(report['directory_modes'].values()) != {'0o700'}:
            raise RuntimeError('insecure fixture/storage modes')
        args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        for case in report['cases']:
            print(f"{case['name']}: median={case['median_ms']:.3f} ms p99={case['p99_ms']:.3f} ms")
        print('Raw samples and fixture metadata:',args.output)

if __name__=='__main__':
    main()
