import angr
import claripy
import logging
logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)

proj = angr.Project("flattened_win.exe", auto_load_libs=False)
cfg = proj.analyses.CFGFast()

func = None
for addr, f in cfg.kb.functions.items():
    if f.name == "check_license":
        func = f
        break

print(f"check_license adresi: {hex(func.addr)}")

code_sym = claripy.BVS('code', 32)
state = proj.factory.call_state(func.addr, code_sym, cc=proj.factory.cc())
simgr = proj.factory.simulation_manager(state)
simgr.explore(n=1000)

print(f"active={len(simgr.active)} deadended={len(simgr.deadended)} errored={len(simgr.errored)}")

# hata nedenini gorelim
for e in simgr.errored[:3]:
    print("ERROR:", e.error)

def to_signed32(v):
    return v - 2**32 if v >= 2**31 else v

print("\n=== Kurtarilan (code -> result) esleme ornekleri ===")
seen = set()
for st in simgr.deadended:
    try:
        ret_val_u = st.solver.eval(st.regs.rax, cast_to=int)
        ret_val = to_signed32(ret_val_u & 0xFFFFFFFF)
        code_v_u = st.solver.eval(code_sym, cast_to=int)
        code_v = to_signed32(code_v_u)
        key = (code_v, ret_val)
        if key not in seen:
            seen.add(key)
            print(f"  code={code_v:>6}  ->  result={ret_val}")
    except Exception as ex:
        print("  eval error:", ex)
