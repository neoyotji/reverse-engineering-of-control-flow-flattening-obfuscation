import angr, claripy, logging
logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)

def to_signed32(v):
    v &= 0xFFFFFFFF
    return v - 2**32 if v >= 2**31 else v

def symbolic_explore(path):
    proj = angr.Project(path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    func = None
    for addr, f in cfg.kb.functions.items():
        if f.name == "check_license":
            func = f
            break
    code_sym = claripy.BVS('code', 32)
    state = proj.factory.call_state(func.addr, code_sym, cc=proj.factory.cc())
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(n=1000)

    mappings = []
    for st in simgr.deadended:
        try:
            ret_u = st.solver.eval(st.regs.rax, cast_to=int)
            code_u = st.solver.eval(code_sym, cast_to=int)
            mappings.append((to_signed32(code_u), to_signed32(ret_u)))
        except Exception:
            pass
    return len(list(func.blocks)), len(simgr.deadended), mappings

n_blocks_o, n_paths_o, map_o = symbolic_explore("original_win.exe")
n_blocks_f, n_paths_f, map_f = symbolic_explore("flattened_win.exe")

print("=== KARSILASTIRMA: Sembolik Yol Kesfi Sonuclari ===\n")
print(f"{'':30}{'Orijinal':<15}{'CFF':<15}")
print(f"{'Temel blok sayisi':30}{n_blocks_o:<15}{n_blocks_f:<15}")
print(f"{'Kesfedilen distinct yol sayisi':30}{n_paths_o:<15}{n_paths_f:<15}")

def classify(code, ret):
    if code < 0: return "NEG (result=-1)"
    if code == 0: return "ZERO (result=0)"
    if (code * 2) == ret: return "MOD_TRUE (result=code*2)"
    if (code + 100) == ret: return "MOD_FALSE (result=code+100)"
    return "BILINMEYEN"

print("\n--- Orijinal binary'de kesfedilen dallar ---")
for c, r in map_o:
    print(f"  code={c:>15}  result={r:<15}  sinif={classify(c,r)}")

print("\n--- CFF binary'de kesfedilen dallar ---")
for c, r in map_f:
    print(f"  code={c:>15}  result={r:<15}  sinif={classify(c,r)}")

classes_o = sorted(set(classify(c,r) for c,r in map_o))
classes_f = sorted(set(classify(c,r) for c,r in map_f))
print(f"\nOrijinal'de bulunan davranis siniflari: {classes_o}")
print(f"CFF'de bulunan davranis siniflari:      {classes_f}")
print(f"Davranissal esdegerlik (ayni sinif kumesi mi?): {'EVET' if classes_o == classes_f else 'HAYIR'}")
