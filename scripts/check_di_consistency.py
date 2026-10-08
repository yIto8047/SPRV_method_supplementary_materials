# -*- coding: utf-8 -*-
"""4 シナリオで用いた全テクニックについて，シナリオ間で d_i（M_i）と P_i が一致していることを確認する（回答書「修正の概要」の記載の根拠）。
   入力: ../SPRV/SPRV_LG_LONG_scenario{A,B,C,D}.xlsx（LONG シート）。C_i は資産クラスで決まるため，同一テクニックでも値が異なりうる。"""
import pandas as pd
rows=[]
for s in 'ABCD':
    x=pd.read_excel(f'../SPRV/SPRV_LG_LONG_scenario{s}.xlsx',sheet_name='LONG'); x['Scenario']=s
    rows.append(x[['Scenario','Technique_ID','Technique_Name','Asset','Pi','Mi_Current','Ci']])
d=pd.concat(rows)
g=d.groupby(['Technique_ID','Technique_Name']).agg(
    Scenarios=('Scenario',lambda v:''.join(sorted(set(v)))),Assets=('Asset',lambda v:' / '.join(sorted(set(v)))),
    Mi=('Mi_Current',lambda v:sorted(set(round(float(t),2) for t in v))),Pi=('Pi',lambda v:sorted(set(v))),Ci=('Ci',lambda v:sorted(set(v)))).reset_index()
pd.set_option('display.width',250); pd.set_option('display.max_colwidth',70)
print(g.to_string(index=False)); print(f'\nテクニック数: {len(g)}')
bad=g[(g.Mi.map(len)>1)|(g.Pi.map(len)>1)]
print('シナリオ間で d_i または P_i が不一致のテクニック:', '0 件' if bad.empty else '\n'+bad.to_string(index=False))
import os; os.makedirs('results',exist_ok=True); g.to_csv('results/di_consistency.csv',index=False,encoding='utf-8-sig')
