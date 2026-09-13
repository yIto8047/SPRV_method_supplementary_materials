#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pi_from_stix.py — 攻撃再現性率 P_i の算定（論文 3.4.1 節、式 7・8）

MITRE ATT&CK Enterprise の STIX バンドル（enterprise-attack.json）から、各テクニック T_k について
  G_k: 攻撃グループ（intrusion-set）からの参照回数
  C_k: キャンペーン（campaign）からの参照回数
  S_k: ソフトウェア（malware, tool）からの参照回数
を数え、F_k = G_k + C_k + S_k（式 7）を求める。参照は relationship_type = "uses" の関係とし、
revoked / deprecated のオブジェクトは除く。

F_k を 2 の冪で区切る対数 BIN で Level 1〜5 に離散化し（1 / 2〜3 / 4〜7 / 8〜15 / 16 以上）、
P = α × Level / L_max（α = 0.9, L_max = 5）で P_i を与える（式 8）。F_k = 0 は Level 0（候補から除外）。

使い方:
  python3 pi_from_stix.py --stix enterprise-attack.json --out Pi_scoring.csv
  python3 pi_from_stix.py --stix enterprise-attack.json --compare Pi_scoring_MITRE_v17.1_frequency_BIN.csv
STIX が無ければ v17.1 を GitHub（mitre/cti）から取得する（--download）。
"""
import argparse, collections, json, math, os, sys, urllib.request
import pandas as pd

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v17.1/enterprise-attack/enterprise-attack.json"
ALPHA, LMAX = 0.9, 5

def bin_level(f: int) -> int:
    """対数 BIN: 0→0, 1→1, 2-3→2, 4-7→3, 8-15→4, 16+→5"""
    if f <= 0: return 0
    return min(LMAX, int(math.floor(math.log2(f))) + 1)

def tid_of(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None

def count_references(stix_path):
    d = json.load(open(stix_path, encoding="utf-8"))
    objs = {o["id"]: o for o in d["objects"]}
    ap = {o["id"]: o for o in d["objects"]
          if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated")}
    kind = {"intrusion-set": "G", "campaign": "C", "malware": "S", "tool": "S"}
    cnt = collections.defaultdict(collections.Counter)
    for o in d["objects"]:
        if o["type"] != "relationship" or o.get("relationship_type") != "uses" or o.get("revoked"):
            continue
        src, tgt = objs.get(o["source_ref"]), o["target_ref"]
        if tgt not in ap or src is None or src.get("revoked") or src.get("x_mitre_deprecated"):
            continue
        k = kind.get(src["type"])
        if k: cnt[tid_of(ap[tgt])][k] += 1
    rows = []
    for o in ap.values():
        t = tid_of(o); g, c, s = cnt[t]["G"], cnt[t]["C"], cnt[t]["S"]
        rows.append(dict(Technique_ID=t, Technique_Name=o.get("name"),
                         Freq_Group=g, Freq_Campaign=c, Freq_Software=s, Freq_Total=g + c + s))
    df = pd.DataFrame(rows).sort_values("Freq_Total", ascending=False).reset_index(drop=True)
    tot = df.Freq_Total.sum()
    df["Freq_Total_Pct"] = (100 * df.Freq_Total / tot).round(3)
    df["Freq_BinScore"] = df.Freq_Total.map(bin_level)
    df["Pi"] = (ALPHA * df.Freq_BinScore / LMAX).round(2)
    return df, tot

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix", default="enterprise-attack.json")
    ap.add_argument("--download", action="store_true", help="STIX v17.1 を取得する")
    ap.add_argument("--out", default="Pi_scoring_from_stix.csv")
    ap.add_argument("--compare", default=None, help="既存の P_i 表と突き合わせる")
    a = ap.parse_args()
    if a.download or not os.path.exists(a.stix):
        print("downloading", STIX_URL, file=sys.stderr)
        urllib.request.urlretrieve(STIX_URL, a.stix)
    df, tot = count_references(a.stix)
    df.to_csv(a.out, index=False)
    print(f"techniques: {len(df)}  ΣF_k = {tot}  saved {a.out}")
    print("Level 別件数:", df.Freq_BinScore.value_counts().sort_index().to_dict())
    print("Level 別 F_k 範囲:", df.groupby("Freq_BinScore").Freq_Total.agg(["min", "max"]).to_dict("index"))
    if a.compare:
        ref = pd.read_csv(a.compare)
        m = df.merge(ref, on="Technique_ID", suffixes=("", "_ref"))
        ok = {c: int((m[c] == m[c + "_ref"]).sum()) for c in ["Freq_Group", "Freq_Campaign", "Freq_Software", "Freq_Total", "Freq_BinScore"]}
        print(f"compare with {a.compare}: matched keys {len(m)}/{len(ref)};", {k: f"{v}/{len(m)}" for k, v in ok.items()})

if __name__ == "__main__":
    main()
