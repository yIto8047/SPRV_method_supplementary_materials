#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sprv_calc.py — SPRV の計算（論文 3.4 節、式 3〜5・14〜16）と図 7〜10 の再現

入力: SPRV/SPRV_LG_LONG_scenario{A,B,C,D}.xlsx の LONG シート
      （1 行 = 1 攻撃ツリーの 1 ステップ。必要列: Scenario_ID, AttackTree_ID, Step_num,
        Technique_ID, Asset, Pi, Mi_Current, Ci）
      Mi_Current から d_i を逆算し、式 14 で三条件（遵守時 / 無対策 / 全対策）の M_i を作る。

計算:
  Q_i    = P_i · M_i                              (式 3)
  Q̂_i    = min(1, P_i · M_i · C_i)               (式 4)
  R_i    = R_{i-1} · Q̂_i,  R_0 = 1               (式 5, 7)
  R_tree = R_4                                     (式 16)
  R_sum  = Σ_k R_tree,k                            (式 15)
  Risk 分類: LogRatio = (ln R_遵守 − ln R_全対策) / (ln R_無対策 − ln R_全対策)
             ≥ 2/3 → Risk A, ≥ 1/3 → Risk B, それ未満 → Risk C

出力: out/sprv_long.csv（全ステップ）, out/sprv_trees.csv（ツリー単位）, out/sprv_summary.csv（R_sum と A/B/C 本数）
      out/fig7_risk_class.png, out/fig8_rsum.png, out/fig9_B-002.png, out/fig10_D-002.png

使い方:
  python3 sprv_calc.py --indir ../SPRV --out out
  python3 sprv_calc.py --indir ../SPRV --out out --check     # xlsx の計算列と突き合わせる
"""
import argparse, os, sys
import numpy as np, pandas as pd

BETA, DMAX = 0.1, 5
MI_WORST, MI_FULL = 0.9, 0.1
RISK_B, RISK_A = 1 / 3, 2 / 3
PAPER_RSUM = {"A": 0.014060, "B": 0.045477, "C": 0.017576, "D": 0.040929}

def M_of_d(d, beta=BETA): return beta + (1 - d / DMAX) * (1 - beta)          # 式 14
def d_of_M(m, beta=BETA): return int(round(DMAX * (1 - (m - beta) / (1 - beta))))  # 式 14 の逆算

def load(indir):
    frames = []
    for s in "ABCD":
        p = os.path.join(indir, f"SPRV_LG_LONG_scenario{s}.xlsx")
        if not os.path.exists(p): continue
        d = pd.read_excel(p, sheet_name="LONG")
        frames.append(d)
    if not frames: sys.exit("no input")
    df = pd.concat(frames, ignore_index=True)
    df = df.sort_values(["Scenario_ID", "AttackTree_ID", "Step_num"]).reset_index(drop=True)
    return df

def compute(df, beta=BETA):
    out = df[["Scenario_ID", "AttackTree_ID", "AttackTree_Key", "Step_num", "Technique_ID", "Asset", "Pi", "Ci"]].copy()
    out["di"] = df.Mi_Current.map(lambda m: d_of_M(m, BETA))
    out["Mi"] = out.di.map(lambda d: M_of_d(d, beta))
    out["Qi"] = out.Pi * out.Mi                                             # 式 3
    for cond, mi in [("cur", out.Mi), ("worst", MI_WORST), ("full", MI_FULL)]:
        q = (out.Pi * mi * out.Ci).clip(upper=1.0)                           # 式 4
        out[f"Qhat_{cond}"] = q
        out[f"R_{cond}"] = q.groupby([out.Scenario_ID, out.AttackTree_ID]).cumprod()   # 式 5
    trees = out[out.Step_num == out.Step_num.max()][["Scenario_ID", "AttackTree_ID", "AttackTree_Key", "R_cur", "R_worst", "R_full"]].copy()
    trees.columns = ["Scenario_ID", "AttackTree_ID", "AttackTree_Key", "Rtree", "Rtree_worst", "Rtree_full"]      # 式 16
    with np.errstate(divide="ignore", invalid="ignore"):
        lr = (np.log(trees.Rtree) - np.log(trees.Rtree_full)) / (np.log(trees.Rtree_worst) - np.log(trees.Rtree_full))
    trees["LogRatio"] = lr.fillna(0)
    trees["Risk_Class"] = np.where(trees.LogRatio >= RISK_A, "Risk A", np.where(trees.LogRatio >= RISK_B, "Risk B", "Risk C"))
    summ = trees.groupby("Scenario_ID").agg(Rsum=("Rtree", "sum"),
                                            nA=("Risk_Class", lambda x: (x == "Risk A").sum()),
                                            nB=("Risk_Class", lambda x: (x == "Risk B").sum()),
                                            nC=("Risk_Class", lambda x: (x == "Risk C").sum())).reset_index()   # 式 15
    return out, trees, summ

def check(df, out, trees):
    ok = True
    for a, b in [("Qhat_i_Current", "Qhat_cur"), ("Ri_Current", "R_cur"), ("Ri_Worst", "R_worst"), ("Ri_Full", "R_full")]:
        if a in df:
            diff = (df[a].astype(float) - out[b]).abs().max()
            print(f"  {a:14s} vs {b:8s} max|diff| = {diff:.2e}"); ok &= diff < 1e-9
    if "Risk_Class" in df:
        ref = df[df.Step_num == df.Step_num.max()].Risk_Class.values
        agree = (ref == trees.Risk_Class.values).mean(); print(f"  Risk_Class 一致率 {agree:.3f}"); ok &= agree == 1.0
    return ok

def figures(out, trees, summ, odir):
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    # 図 8: R_sum
    s = summ.sort_values("Rsum", ascending=False)
    fig, ax = plt.subplots(figsize=(5, 3.2)); ax.bar(s.Scenario_ID, s.Rsum, color="#f28e8e", label="Rsum")
    for x, v in zip(s.Scenario_ID, s.Rsum): ax.text(x, v, f"{v:.6f}", ha="center", va="bottom", fontsize=8)
    ax.set_xlabel("Scenario"); ax.set_ylabel("Rsum"); ax.legend(); fig.tight_layout(); fig.savefig(f"{odir}/fig8_rsum.png", dpi=200); plt.close(fig)
    # 図 7: Risk class（SPRV 側のみ）
    fig, ax = plt.subplots(figsize=(5, 3.2)); x = np.arange(len(summ))
    ax.bar(x, summ.nC, color="#6dbb6d", label="Risk C"); ax.bar(x, summ.nB, bottom=summ.nC, color="#f2b233", label="Risk B")
    ax.bar(x, summ.nA, bottom=summ.nC + summ.nB, color="#d9534f", label="Risk A")
    ax.set_xticks(x); ax.set_xticklabels(summ.Scenario_ID); ax.set_ylabel("Number of attack trees"); ax.legend(); fig.tight_layout()
    fig.savefig(f"{odir}/fig7_risk_class.png", dpi=200); plt.close(fig)
    # 図 9・10: 代表ツリー
    for sc, tid, name in [("B", 2, "fig9_B-002"), ("D", 2, "fig10_D-002")]:
        t = out[(out.Scenario_ID == sc) & (out.AttackTree_ID == tid)]
        if t.empty: continue
        fig, ax = plt.subplots(figsize=(7, 3.6)); xs = t.Step_num
        ax.plot(xs, t.R_cur, "o-", color="#1f77b4", label="Ri: Current risk (guideline compliant)")
        ax.plot(xs, t.R_worst, "s--", color="#d62728", label="Ri: No mitigation (worst case, Mi=0.9)")
        ax.plot(xs, t.R_full, "^:", color="#2ca02c", label="Ri: Full mitigation (all controls, Mi=0.1)")
        ax.plot(xs, t.Qhat_cur, "D-.", color="#ff7f0e", label="Q̂i: Step-level attack success prob. (guideline compliant)")
        for x_, y_ in zip(xs, t.R_cur): ax.annotate(f"{y_:.3g}", (x_, y_), textcoords="offset points", xytext=(0, 6), ha="center", fontsize=7, color="#1f77b4")
        ax.set_xticks(list(xs)); ax.set_xticklabels([f"S{i}\n{tid_}\n{a}" for i, tid_, a in zip(xs, t.Technique_ID, t.Asset)], fontsize=7)
        ax.set_ylabel("Ri / Q̂i"); ax.set_ylim(0, 1.2); ax.legend(fontsize=7, loc="upper right"); fig.tight_layout()
        fig.savefig(f"{odir}/{name}.png", dpi=200); plt.close(fig)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--indir", default="../SPRV"); ap.add_argument("--out", default="out")
    ap.add_argument("--beta", type=float, default=BETA); ap.add_argument("--check", action="store_true"); ap.add_argument("--no-fig", action="store_true")
    a = ap.parse_args(); os.makedirs(a.out, exist_ok=True)
    df = load(a.indir); out, trees, summ = compute(df, a.beta)
    out.to_csv(f"{a.out}/sprv_long.csv", index=False); trees.to_csv(f"{a.out}/sprv_trees.csv", index=False); summ.to_csv(f"{a.out}/sprv_summary.csv", index=False)
    print(summ.to_string(index=False))
    if a.beta == BETA:
        for s, v in PAPER_RSUM.items():
            r = summ[summ.Scenario_ID == s]
            if len(r): print(f"  {s}: Rsum {r.Rsum.iloc[0]:.6f}  論文 {v}  {'OK' if abs(r.Rsum.iloc[0] - v) < 5e-7 else 'MISMATCH'}")
    if a.check: print("xlsx との突合:", "一致" if check(df, out, trees) else "不一致あり")
    if not a.no_fig: figures(out, trees, summ, a.out); print("figures ->", a.out)

if __name__ == "__main__":
    main()
