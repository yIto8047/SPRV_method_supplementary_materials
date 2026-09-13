# 補足資料 — 自治体ゼロトラスト環境を事例とした MITRE ATT&CK に基づく攻撃伝播型リスク可視化モデルの提案と評価（JSSM 投稿）

本リポジトリは、上記論文の第 4 章（検証と評価）で用いたリスク計算シートと感度分析の再現用スクリプトを提供する。

## 構成

| フォルダ / ファイル | 内容 | 論文での対応 |
|---|---|---|
| `SPRV/SPRV_LG_LONG_scenario{A,B,C,D}.xlsx` | SPRV 方式の計算シート。`LONG` シートに 64 攻撃ツリー × 4 ステップの P_i, M_i, C_i, Q̂_i, R_i（式 2〜4, 8, 9）。`Tree_Summary` に R_tree（式 11）、`Settings` に式と C_i 変換表 | 図 8（R_sum, 式 10）、図 9（B-002）、図 10（D-002） |
| `IPA/Scenario{A,B,C,D}_IPA_scenario_threat_fixed.xlsx` | IPA 方式の計算シート（攻撃ツリー単位の事業被害・脅威・対策・脆弱性とリスク値）。`IPA_Risk_Rules` に採点規則 | 表 6、図 7 の IPA 側 |
| `sensitivity/sensitivity.py` | β（式 9）を 0.05 / 0.10 / 0.20、C_i を一段階下げ／上げにした場合の R_sum と順位を再計算する | 4.4 節の感度分析 |
| `sensitivity/sensitivity_beta_Ci.csv` | 上の出力 | 同上 |

## 再現手順
```
cd sensitivity
python3 sensitivity.py      # pandas, openpyxl が必要
```
基準条件（β = 0.1、C_i 既定）の R_sum が A 0.007733 / B 0.045477 / C 0.017576 / D 0.040929（図 8）に一致することを最初に確認する。

## 記法
- 論文の図 9 で分析する攻撃ツリーは `SPRV_LG_LONG_scenarioB.xlsx` の B-002、図 10 は `scenarioD.xlsx` の D-002。
- C_i は標的資産の種別で割り当てる（端末 1.35 / 認証・中間サーバ 1.5 / 重要資産および最終ステップの Proxy Server 2.0）。`Settings` シートの変換表を参照。
