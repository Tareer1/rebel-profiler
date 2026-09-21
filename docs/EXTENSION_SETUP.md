# Firefox Extension Setup (Rebel Profiler Bridge) — qadam ba qadam

Extension "Add-ons manager" mein nahi dikhti kyunke ye **temporary add-on** hai
(about:debugging se load hoti hai, sirf usi Firefox session ke liye). Ye normal
hai — niche ke steps se connect ho jayegi.

## 1. Bridge start karo (pehle ye)

```bash
rp bridge
```

Ye bridge ko 127.0.0.1:8765 par start karta hai aur **token print karta hai** —
wo copy kar lo. (Dobara chalao ge to pehle se live hai to kuch nahi bigarta.)

Monitor ke liye dusri terminal mein:

```bash
tail -f /tmp/rp_bridge.log
```

## 2. Firefox mein extension load karo

1. Firefox kholo → address bar mein type karo: `about:debugging#/runtime/this-firefox`
2. **"Load Temporary Add-on…"** button dabao
3. File dialog mein repo ke andar jao: `extension/manifest.json` choose karo
4. Ab toolbar mein **Rebel Profiler Bridge icon** aa jayega (agar nahi dikhe to
   puzzle-piece icon 🧩 ke andar dekho)

> Note: Firefox band karke dobara kholne par extension hat jayegi — phir se
> 3 steps dohrana honge (permanent ke liye signing chahiye, v2 roadmap item).

## 3. Extension ko bridge se connect karo

1. Toolbar icon click karo → popup khulega
2. **Bridge token** paste karo (jo `rp bridge` ne print kiya) → **Save**
3. **Check bridge** dabao → "bridge ok — case …" dikhna chahiye
4. **Grant site access** dabao (ek dafa) — ye Firefox ka host-permission
   gate hai; iske baghair pages read nahi ho sakte
5. **Run now** dabao → turant poll hoga

## 4. Job do aur dekho

```bash
rp grab https://in-scope-url/        # job queue hota hai
rp job <job-id>                      # result dekho
```

Ya Hermes se bolo (`rp talk` → "grab https://… and tell me what's on it").

Extension har 30s–1min mein poll karti hai (MV3 alarm limits), tab switching
par bhi turant tick hoti hai. Job milte hi ek background tab kholti hai, page
padhti hai (read-only: title, links, text, headers, forms, cookies), tab
band karti hai, result bridge ko wapas bhejti hai → **evidence + claims khud
ban jate hain**.

## Kya ho raha hai monitor karne ke 3 tareeqe

| Kahan | Kya dikhega |
|---|---|
| `tail -f /tmp/rp_bridge.log` | har poll/ack/result request ki line |
| `rp job <id>` | job ka state + extracted data preview |
| `rebel-profiler intel claims <case-id>` | job se bane claims |

## Troubleshooting

- **"bridge unreachable"** popup mein → `rp bridge` chalao, phir **Check bridge**
- **401 / unauthorized** → popup ka token mismatch; `rp bridge` ka token dobara Save karo
- **Job pending hi rehta hai** → extension load hai? Grant site access kiya?
  Popup mein **Run now** dabao. `about:debugging` mein "Rebel Profiler Bridge"
  ke aage "running" likha hona chahiye
- **"URL out of scope"** result mein → URL case scope mein add karo:
  `rebel-profiler case scope add <case-id> <host>` — extension kabhi
  out-of-scope fetch nahi karti (fail-closed)
- **onion site kholna hai** → Tor Browser alag cheez hai; ye extension normal
  Firefox chalati hai. `.onion` dorking `dork-search + ahmia` engine se hoti hai

## Safety (yaad rakhna)

- Extension sirf `127.0.0.1:8765` se baat karti hai
- Har URL pehle **case scope** se check hota hai — client-side bhi
- Read-only extractors: title, text, links, headers, forms, cookies, meta
- Koi click/type sirf explicit `--actions` + `--approved` par
