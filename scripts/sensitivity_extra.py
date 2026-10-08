# -*- coding: utf-8 -*-
"""JSSM 4.4 追加の感度分析（4.4.1 節の P_i ±5%、4.4.2 節の C_i ±0.1・±0.2）。
   入力は SPRV_LG_LONG_scenario{A,B,C,D}.xlsx（LONG シート）。M_i は Mi_Current（式 14、β=0.1）をそのまま用いる。
   Q̂_i = min(1, P_i·M_i·C_i)（式 4）、R_i = R_{i-1}·Q̂_i（式 5）、R_sum = Σ R_4（式 15）。
   (1) P_i: 全ステップ・全シナリオを一律に ×0.95 / ×1.05
   (2) P_i: シナリオごとに独立に ±5%（隣接する順位の組ごとの最悪ケース。R_4 は P_i の 4 乗に比例）
   (3) C_i: 全ステップ・全シナリオの C_i に一律に −0.2 / −0.1 / +0.1 / +0.2 を加える
   (4) P_i: Monte Carlo（シード 0、10,000 回、P_i に ×U(0.95,1.05) を掛ける）。P_i はテクニックの属性なので乱数はテクニック単位で与える。
       (a) テクニックごとに独立（同一テクニックは全シナリオ・全攻撃ツリーで同じ倍率）… 論文 4.4.1 節の主記述
       (b) テクニック×シナリオごとに独立（同一テクニックでもシナリオが異なれば別の倍率）
       (c) シナリオごとに独立（シナリオ内の全ステップは同率）… 極端な条件（R_sum は P_i の 4 乗に比例）"""
import pandas as pd
D={s:pd.read_excel(f'../SPRV/SPRV_LG_LONG_scenario{s}.xlsx',sheet_name='LONG').sort_values(['AttackTree_ID','Step_num']).reset_index(drop=True) for s in 'ABCD'}
def rsum(x,pk=1.0,dc=0.0):
    q=(x.Pi*pk*x.Mi_Current*(x.Ci+dc)).clip(upper=1.0)
    return q.groupby(x.AttackTree_ID).cumprod()[x.Step_num==4].sum()
base={s:rsum(D[s]) for s in D}
rank=lambda v:' > '.join(sorted(v,key=lambda s:-v[s]))
rows=[]
def add(label,v): rows.append(dict(条件=label,**{s:round(v[s],6) for s in 'ABCD'},**{f'{s}変化率':f'{v[s]/base[s]-1:+.1%}' for s in 'ABCD'},順位=rank(v)))
add('基準',base)
for k in (0.95,1.05): add(f'P_i 一律 ×{k}',{s:rsum(D[s],pk=k) for s in D})
for dc in (-0.2,-0.1,0.1,0.2): add(f'C_i 一律 {dc:+.1f}',{s:rsum(D[s],dc=dc) for s in D})
T=pd.DataFrame(rows); print(T.to_string(index=False))
print('\nP_i ±5% をシナリオごとに独立に動かした最悪ケース（上位を ×0.95、下位を ×1.05）')
for hi,lo in [('B','D'),('D','C'),('C','A')]:
    a=rsum(D[hi],pk=0.95); b=rsum(D[lo],pk=1.05)
    print(f'  {hi}×0.95={a:.6f} vs {lo}×1.05={b:.6f} ->', '反転する' if b>a else '反転しない')

import numpy as np
for x in D.values(): assert (x.Step_num.values.reshape(-1,4)[:,3]==4).all()    # 4 ステップずつ並んでいること
def rs_fast(x,f):
    q=np.minimum(1,x.Pi.values*f*x.Mi_Current.values*x.Ci.values); return q.reshape(-1,4).prod(axis=1).sum()
rng=np.random.default_rng(0); N=10000; mc=[]
techs=sorted(set().union(*[set(x.Technique_ID) for x in D.values()]))
print('\nP_i Monte Carlo（×U(0.95,1.05)、10,000 回、シード 0）')
for mode in ['(a) テクニックごとに独立（全シナリオ共通）','(b) テクニック×シナリオごとに独立','(c) シナリオごとに独立（全ステップ同率）']:
    cnt={}; bd=ac=0
    for _ in range(N):
        if mode.startswith('(a)'):
            f=dict(zip(techs,rng.uniform(0.95,1.05,len(techs)))); v={s:rs_fast(D[s],D[s].Technique_ID.map(f).values) for s in D}
        elif mode.startswith('(b)'):
            v={}
            for s in D:
                f=dict(zip(techs,rng.uniform(0.95,1.05,len(techs)))); v[s]=rs_fast(D[s],D[s].Technique_ID.map(f).values)
        else:
            v={s:rs_fast(D[s],rng.uniform(0.95,1.05)) for s in D}
        k=' > '.join(sorted(v,key=lambda t:-v[t])); cnt[k]=cnt.get(k,0)+1; bd+=v['D']>v['B']; ac+=v['A']>v['C']
    for k,c in sorted(cnt.items(),key=lambda kv:-kv[1]): mc.append(dict(条件=mode,順位=k,割合=f'{c/N:.1%}'))
    print(mode,{r['順位']:r['割合'] for r in mc if r['条件']==mode},f'| D>B {bd/N:.1%}, A>C {ac/N:.1%}')
pd.DataFrame(mc).to_csv('results/sensitivity_extra_montecarlo.csv',index=False,encoding='utf-8-sig')
import os; os.makedirs('results',exist_ok=True); T.to_csv('results/sensitivity_extra.csv',index=False,encoding='utf-8-sig')
