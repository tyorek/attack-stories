#!/usr/bin/env python3
"""Supervisor chat: render ```mermaid blocks as diagrams (2026-11-24). Serves static/mermaid.min.js from this
server, allows script-src 'self', and tells the model how to write diagrams. Idempotent; backups *.pre-mermaid."""
import py_compile, shutil, sys
W = "/home/agent/agents/supervisor/"
def edit(path, pairs, marker):
    s = open(path).read()
    if marker in s:
        print(path, "already patched"); return
    shutil.copy2(path, path + ".pre-mermaid")
    for old, new in pairs:
        if s.count(old) != 1:
            sys.exit(f"{path}: anchor found {s.count(old)}x: {old[:70]!r}")
        s = s.replace(old, new)
    open(path, "w").write(s); print(path, "patched")

edit(W + "server.py", [
    # 1. load the library in the page head
    ('</style></head><body>',
     '.mmd{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:8px;margin:6px 0;overflow-x:auto}\n'
     '.mmd svg{max-width:100%;height:auto}\n'
     '</style><script src="/static/mermaid.min.js"></script></head><body>'),
    # 2. fenced blocks remember their language; mermaid blocks become .mmd placeholders
    ('let list=null,para=[],fence=null,code=[],tbl=null;', 'let list=null,para=[],fence=null,code=[],tbl=null,lang="";'),
    ('if(fence!==null){if(line.startsWith(fence)){o.push("<pre><code>"+esc(code.join("\\n"))+"</code></pre>");fence=null;code=[]}else code.push(line);continue}',
     'if(fence!==null){if(line.startsWith(fence)){o.push(blk(code,lang));fence=null;code=[];lang=""}else code.push(line);continue}'),
    ('if((m=line.match(/^(`{3,}|~{3,})/))){fp();cl();ct();fence=m[1];continue}',
     'if((m=line.match(/^(`{3,}|~{3,})\\s*([\\w-]*)/))){fp();cl();ct();fence=m[1];lang=(m[2]||"").toLowerCase();continue}'),
    ('if(fence!==null)o.push("<pre><code>"+esc(code.join("\\n"))+"</code></pre>");',
     'if(fence!==null)o.push(blk(code,lang));'),
    ('function render(md){',
     'function blk(code,lang){const t=code.join("\\n");return lang==="mermaid"?\'<div class="mmd" data-src="\'+esc(t)+\'"><pre><code>\'+esc(t)+"</code></pre></div>":"<pre><code>"+esc(t)+"</code></pre>"}\n'
     '// Mermaid diagrams: draw every new .mmd block; on a syntax error keep the code and show the error\n'
     'let mmdN=0;\n'
     'async function mmdRun(){if(!window.mermaid)return;for(const n of document.querySelectorAll(".mmd:not([data-done])")){n.dataset.done="1";\n'
     ' try{const r=await mermaid.render("mmd"+(++mmdN),n.dataset.src);n.innerHTML=r.svg+\'<details><summary>diagram source</summary><pre><code>\'+esc(n.dataset.src)+"</code></pre></details>"}\n'
     ' catch(e){n.insertAdjacentHTML("afterbegin",\'<div class="meta">The diagram didn\\\'t render: \'+esc(String((e&&e.message)||e).slice(0,240))+"</div>")}}}\n'
     'if(window.mermaid){mermaid.initialize({startOnLoad:false,securityLevel:"strict",theme:"dark",flowchart:{htmlLabels:false}});\n'
     ' new MutationObserver(()=>mmdRun()).observe(document.body,{childList:true,subtree:true})}\n'
     'function render(md){'),
    # 3. serve the library
    ('''        if self.path.split("?")[0] != "/":
            return self.send(404, "not found", "text/plain")''',
     '''        if self.path.split("?")[0] == "/static/mermaid.min.js":
            try:
                with open(os.path.join(WORKDIR, "static", "mermaid.min.js"), "rb") as f:
                    return self.send(200, f.read(), "application/javascript; charset=utf-8")
            except OSError:
                return self.send(404, "not found", "text/plain")
        if self.path.split("?")[0] != "/":
            return self.send(404, "not found", "text/plain")'''),
    # 4. CSP: scripts from this server too (the library), still no other origin
    ('''"default-src 'self'; script-src 'unsafe-inline'; ''', '''"default-src 'self'; script-src 'self' 'unsafe-inline'; '''),
], "mmdRun")
py_compile.compile(W + "server.py", doraise=True)

edit(W + "CLAUDE.md", [("\n## Where the agents keep their files\n", '''
## Diagrams
The chat draws Mermaid. When the admin asks for a diagram, chart, flow or chain, answer with a fenced code block
that starts with ```mermaid and ends with ```, plus one or two sentences around it. Read the facts first
(for attacker stories: `attack-stories/stories.jsonl`; for agents and flows: their README.md) and draw only
what the files say.
- ATT&CK chain of a story: `flowchart LR`, one node per tactic in kill-chain order (Reconnaissance, Initial
  Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral
  Movement, Collection, Command and Control, Exfiltration, Impact), technique IDs and names inside the node,
  arrows between tactics, event counts on the arrows or in the node.
  Example:
  ```mermaid
  flowchart LR
    A["Reconnaissance<br/>T1595 Active Scanning (207)"] --> B["Initial Access<br/>T1190 Exploit Public-Facing App (64)"]
    B --> C["Discovery<br/>T1083 File and Directory Discovery (2)"]
  ```
- Timelines: `timeline` or `sequenceDiagram`. Relationships between hosts: `flowchart LR` with IPs as nodes.
- Rules: double-quote every label, at most about 25 nodes, `<br/>` for line breaks, no click, link, style,
  classDef or init directives. If something doesn't fit, summarise it in the text instead.
- The full interactive view of a story (ATT&CK chain, matrix position, Navigator layer download) is the
  dashboard: https://digest.example.com/attack.html?cat=<severity>&story=<story id>. Give that link too.

## Where the agents keep their files
''')], "## Diagrams")
