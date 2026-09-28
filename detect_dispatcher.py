"""
Pilot deney: check_license fonksiyonunda dispatcher tespiti.
angr (CFGFast) ile hem orijinal hem CFF uygulanmis Windows PE binary
uzerinde statik CFG cikarilir; CFF versiyonunda dispatcher adayi
(en yuksek in-degree'ye sahip blok) tespit edilir ve orijinal CFG ile
karsilastirilir.
"""
import angr
import logging
logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)

def analyze(path, label):
    proj = angr.Project(path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    # check_license fonksiyonunu bul
    func = None
    for addr, f in cfg.kb.functions.items():
        if f.name == "check_license":
            func = f
            break
    if func is None:
        print(f"[{label}] check_license bulunamadi!")
        return None

    blocks = list(func.blocks)
    graph = func.transition_graph

    # in-degree hesapla (kac farkli bloktan bu bloga geliniyor)
    in_degree = {}
    for u, v in graph.edges():
        in_degree[v] = in_degree.get(v, 0) + 1

    n_blocks = len(blocks)
    n_edges = graph.number_of_edges()
    max_indeg_node = max(in_degree, key=in_degree.get) if in_degree else None
    max_indeg = in_degree.get(max_indeg_node, 0)

    print(f"\n=== {label} ===")
    print(f"Fonksiyon adresi: {hex(func.addr)}")
    print(f"Temel blok sayisi: {n_blocks}")
    print(f"Kenar (edge) sayisi: {n_edges}")
    if max_indeg_node is not None:
        print(f"En yuksek in-degree'ye sahip blok: {hex(max_indeg_node.addr) if hasattr(max_indeg_node,'addr') else max_indeg_node} (in-degree={max_indeg})")
        # dispatcher supheli mi? esik: toplam blok sayisinin >%40'i kadar in-degree
        is_dispatcher_candidate = max_indeg >= max(3, n_blocks * 0.4)
        print(f"Dispatcher adayi mi (heuristik: in-degree >= max(3, %40*blok)): {'EVET' if is_dispatcher_candidate else 'hayir'}")
    return {"n_blocks": n_blocks, "n_edges": n_edges, "max_indeg": max_indeg}

orig = analyze("original_win.exe", "ORIJINAL (obfuscation yok)")
flat = analyze("flattened_win.exe", "CFF UYGULANMIS")

if orig and flat:
    print("\n=== KARSILASTIRMA (Cizelge 3.2 icin gercek veri) ===")
    print(f"{'Metrik':<30} {'Orijinal':<12} {'CFF':<12}")
    print(f"{'Temel blok sayisi':<30} {orig['n_blocks']:<12} {flat['n_blocks']:<12}")
    print(f"{'Kenar sayisi':<30} {orig['n_edges']:<12} {flat['n_edges']:<12}")
    print(f"{'Max in-degree':<30} {orig['max_indeg']:<12} {flat['max_indeg']:<12}")
