# bash completion for rebel-profiler
# Source this file (or drop it in ~/.local/share/bash-completion/completions/):
#   source ~/.local/share/rebel-profiler/completions/rebel-profiler.bash

_rebel_profiler() {
    local cur prev cids actions
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # The global subcommand list — keep in sync with the CLI parser.
    local commands="hermes case scope-check plan run adapters knowledge report \
surface intel evidence audit member approval hypothesis workflow schedule \
search credential plugin events serve ops worker browser agent forge system \
detection complaint llm bounty doctor"

    # --output choices
    if [[ "$prev" == "-o" || "$prev" == "--output" ]]; then
        COMPREPLY=( $(compgen -W "human json jsonl csv" -- "$cur") )
        return 0
    fi

    # case ids after common positional slots
    case "${COMP_WORDS[1]}" in
        case)
            local case_sub="create list show activate close scope"
            case "${COMP_WORDS[2]}" in
                activate|close|show)
                    [[ "$cur" == -* ]] || { COMPREPLY=( $(compgen -W "$(_rp_case_ids)" -- "$cur") ); return 0; } ;;
                scope)
                    [[ "${COMP_WORDS[3]}" == "add" || "${COMP_WORDS[3]}" == "remove" ]] && { COMPREPLY=( $(compgen -W "$(_rp_case_ids)" -- "$cur") ); return 0; } ;;
                *)
                    [[ "$cur" == -* ]] || { COMPREPLY=( $(compgen -W "$case_sub" -- "$cur") ); return 0; } ;;
            esac ;;
        scope-check|plan|run|report|evidence|audit|surface|intel|fusion|hypothesis)
            # first positional after the subcommand is usually a case id
            if [[ "$cur" != -* && $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$(_rp_case_ids)" -- "$cur") )
                return 0
            fi ;;
        agent)
            local agent_sub="run auto chat work"
            case "${COMP_WORDS[2]}" in
                run|auto|chat|work)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=( $(compgen -W "--llm --plan --max-actions --max-turns --max-repair-attempts" -- "$cur") )
                    elif [[ $COMP_CWORD -eq 3 ]]; then
                        COMPREPLY=( $(compgen -W "$(_rp_case_ids)" -- "$cur") )
                    fi
                    return 0 ;;
                *)
                    [[ "$cur" == -* ]] || { COMPREPLY=( $(compgen -W "$agent_sub" -- "$cur") ); return 0; } ;;
            esac ;;
        llm)
            local llm_sub="setup models local status generate plan submit data daemon"
            case "${COMP_WORDS[2]}" in
                generate|plan|submit|data)
                    [[ "$cur" == -* ]] && COMPREPLY=( $(compgen -W "--model --tier --local --max-new-tokens" -- "$cur") )
                    return 0 ;;
                *)
                    [[ "$cur" == -* ]] || { COMPREPLY=( $(compgen -W "$llm_sub" -- "$cur") ); return 0; } ;;
            esac ;;
        bounty)
            local bounty_sub="import run assess report auto"
            [[ "$cur" == -* ]] || { COMPREPLY=( $(compgen -W "$bounty_sub" -- "$cur") ); return 0; } ;;
        forge)
            local forge_sub="propose list register"
            [[ "$cur" == -* ]] || { COMPREPLY=( $(compgen -W "$forge_sub" -- "$cur") ); return 0; } ;;
    esac

    # top-level completion
    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands --output --yes --actor --rbac --config-file" -- "$cur") )
        return 0
    fi

    # generic flags
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "--output -o --yes --actor --rbac --config-file --help" -- "$cur") )
    fi
    return 0
}

_rp_case_ids() {
    # Case ids from the workspace index; fail silently when absent.
    python3 - <<'PY' 2>/dev/null
import json, pathlib
idx = pathlib.Path.home() / ".local/share/rebel-profiler/index.json"
try:
    data = json.loads(idx.read_text())
except Exception:
    raise SystemExit
cases = data.get("cases") if isinstance(data, dict) else data
if isinstance(cases, list):
    for c in cases:
        if isinstance(c, dict) and c.get("id"):
            print(c["id"])
PY
}

complete -F _rebel_profiler rebel-profiler
