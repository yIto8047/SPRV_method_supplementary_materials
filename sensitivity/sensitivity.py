# -*- coding: utf-8 -*-
"""JSSM 4.4 感度分析: β（式9）と Ci の一段階ずらし。入力は SPRV_LG_LONG_scenario{A,B,C,D}.xlsx（LONG シート）。
   基準（β=0.1, Ci 既定）が論文図 8 の Rsum と一致することを先に確認する。"""
import pandas as pd
BETA0=0.1
def d_from_M(m): return int(round(5*(1-(m-BETA0)/(1-BETA0))))   # 式9の逆算: 0.82→1 ... 0.10→5
def M(d,beta): return beta+(1-d/5)*(1-beta)                       # 式9
DOWN={2.0:1.5,1.5:1.35,1.35:1.2,1.2:1.0,1.0:1.0}; UP={1.0:1.2,1.2:1.35,1.35:1.5,1.5:2.0,2.0:2.0}
def rsum(d,beta=0.1,ci_shift=0):
    ci=d.Ci if ci_shift==0 else d.Ci.map(DOWN if ci_shift<0 else UP)
    q=(d.Pi*d.di.map(lambda x:M(x,beta))*ci).clip(upper=1.0)     # 式3
    r=q.groupby(d.AttackTree_ID).cumprod()                        # 式4
    return r[d.Step_num==4].sum()                                 # 式10
dfs={}
for s in 'ABCD':
    d=pd.read_excel(f'../SPRV/SPRV_LG_LONG_scenario{s}.xlsx',sheet_name='LONG').sort_values(['AttackTree_ID','Step_num']).reset_index(drop=True)
    d['di']=d.Mi_Current.map(d_from_M); dfs[s]=d
rows=[]
for label,kw in [('β=0.05',dict(beta=0.05)),('β=0.10（基準）',dict()),('β=0.20',dict(beta=0.20)),
                 ('Ci 一段階下げ',dict(ci_shift=-1)),('Ci 既定（基準）',dict()),('Ci 一段階上げ',dict(ci_shift=+1))]:
    v={s:rsum(dfs[s],**kw) for s in 'ABCD'}
    rows.append(dict(条件=label,**{s:round(v[s],6) for s in 'ABCD'},順位=' > '.join(sorted('ABCD',key=lambda s:-v[s]))))
T=pd.DataFrame(rows); print(T.to_string(index=False)); T.to_csv('sensitivity_beta_Ci.csv',index=False)
