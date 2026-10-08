# 補足資料 — 自治体ゼロトラスト環境を事例とした MITRE ATT&CK に基づく攻撃伝播型リスク可視化モデルの提案と評価

Supplementary materials for: *Proposal and Evaluation of a Stepwise Propagated Risk Visualization Model for Cyber Attacks Based on the MITRE ATT&CK Using a Zero Trust Environment in Local Governments as a Case Study* (JSSM, JSSM-D-26-00006)

本リポジトリは、上記論文の第 3 章（提案方式）で定義した各指標の算定データと、第 4 章（検証と評価）で用いたリスク計算シート・感度分析の再現用スクリプトを提供する。論文中の式番号・図表番号との対応を下表に示す（番号は修正稿（2026 年 10 月）のもの）。

---

## 1. ファイル構成と論文との対応

| ファイル | 内容 | 論文での対応 |
|---|---|---|
| `Pi_scoring_MITRE_v17.1_frequency_BIN.csv` | MITRE ATT&CK Enterprise v17.1 の全 679 テクニックについて、攻撃グループ・キャンペーン・ソフトウェアからの参照回数（G_k, C_k, S_k）、総観測頻度 F_k、相対比率、BIN レベル（1〜5） | 3.4.1 節、式 (9)〜(12)、表 1、4.2.1 節（図 5） |
| `MITRE_dictionary_J_ver3.csv` | MITRE ATT&CK Enterprise v17.1 のテクニック辞書（823 件）。技術名の日本語訳、戦術、プラットフォーム、対象資産候補、攻撃ステップ（S1〜S4）への分類 | 4.1.1 節（表 6 のテクニック選定）、図 6 |
| `asset_list_LG.txt` | 攻撃進展構造の自動生成に入力する資産定義（自治体ゼロトラスト・ハイブリッド環境） | 図 4 |
| `SPRV/SPRV_LG_LONG_scenario{A,B,C,D}.xlsx` | SPRV 方式の計算シート（シナリオ A〜D、各 64 攻撃ツリー × 4 ステップ） | 式 (3)〜(5)、(12)、(14)〜(16)、図 7（SPRV 側）、図 8、図 9、図 10 |
| `IPA/Scenario{A,B,C,D}_IPA_scenario_threat_fixed.xlsx` | IPA 方式の計算シート（攻撃ツリー単位の事業被害・脅威・対策・脆弱性とリスク値） | 表 8、図 7（IPA 側） |
| `di_no_mitigation/scenario_no_mitigation_analysis.xlsx` | MITRE の Mitigation が定義されていないテクニックの抽出と、Detection 記述からの統制目標の導出 | 3.4.2 節（表 2）、4.1.2 節（表 7） |
| `di_no_mitigation/final_result_with_digital_and_pages.xlsx` | 導出した統制目標と、総務省ガイドライン・デジタル庁規定の該当箇所（ページ付き）の照合結果 | 同上 |
| `di_mitigation/calc_Mi_from_STIX_and_guidelines.ipynb` | Mitigation が定義されているテクニックについて、Mitigation ごとにガイドラインへの該当を照合し、実施率から対策評価値 d_i と防御失敗率 M_i を算出するノートブック | 3.4.2 節、式 (13)・(14) |
| `scripts/pi_from_stix.py` | MITRE ATT&CK の STIX から G_k・C_k・S_k を数え、F_k → 対数 BIN → P_i を算定する（`Pi_scoring_MITRE_v17.1_frequency_BIN.csv` を再生成） | 3.4.1 節、式 (9)〜(12) |
| `scripts/sprv_calc.py` | SPRV の計算（式 3〜5、14〜16）、Risk 分類、図 7〜10 の再現 | 3.4 節、4.2〜4.3 節 |
| `scripts/sensitivity.py` | β（式 14）と C_i を変化させた場合の R_sum と順位の再計算 | 4.4 節（表 10・表 11） |
| `scripts/sensitivity_extra.py` | P_i を ±5%（全体に一律、シナリオごとに独立、および Monte Carlo 10,000 回）、C_i を一律に ±0.1・±0.2 変えた場合の R_sum と順位の再計算 | 4.4.1 節（P_i ±5%）、4.4.2 節（C_i ±0.1・±0.2） |
| `scripts/check_di_consistency.py` | 4 シナリオで用いた全テクニック（15 件）について，シナリオ間で d_i（M_i）と P_i が一致していることを確認する（出力 `results/di_consistency.csv`） | 3.4.2 節，4.1.2 節（d_i の整合性） |
| `scripts/results/` | 上の 3 スクリプトの出力（P_i 表、ツリー別・シナリオ別の計算結果、図 7〜10、感度分析の表） | — |

---

## 2. 各ファイルの列と論文の記号

### 2.1 `Pi_scoring_MITRE_v17.1_frequency_BIN.csv`（式 9〜12）

| 列 | 論文の記号 | 説明 |
|---|---|---|
| `Technique_ID` | T_k | テクニック ID（サブテクニックを含む） |
| `Freq_Group` | G_k | 攻撃グループからの参照回数 |
| `Freq_Campaign` | C_k | キャンペーンからの参照回数 |
| `Freq_Software` | S_k | ソフトウェアからの参照回数 |
| `Freq_Total` | F_k = G_k + C_k + S_k | 総観測頻度（式 9） |
| `Freq_Total_Pct` | — | 全 679 テクニックの総参照数（ΣF_k = 15,049）に対する相対比率（%） |
| `Freq_BinScore` | L(T_k) | BIN レベル L(T_k) = min(5, ⌊log₂F_k⌋ + 1)（式 10。F_k = 0 は Level 0、式 11）。式 (12) の L(T_τ(i)) に用いる |
| `Applicable` | — | 攻撃ツリーの候補に用いたテクニック（1）。F_k ≥ 1 かつ攻撃ステップに分類可能なもの |
| `Step` | — | 攻撃ステップの分類（S1: 初期侵入、S2: 二次アクション、S3: 二次侵害行為、S4: 最終侵害行為） |

BIN レベルの境界は総観測頻度 F_k を 2 の冪で区切る対数ビンである。

| Level | F_k | 相対比率（%） | 該当数 |
|---|---|---|---|
| 5 | 16 以上 | 0.106 以上 | 186 |
| 4 | 8〜15 | 0.053〜0.100 | 86 |
| 3 | 4〜7 | 0.027〜0.047 | 104 |
| 2 | 2〜3 | 0.013〜0.020 | 116 |
| 1 | 1 | 0.007 | 82 |
| （0） | 0 | 0 | 105（候補から除外） |

攻撃再現性率は式 (12) により P_i = α · L(T_τ(i)) / L_max（α = 0.9、L_max = 5）、すなわち Level 1〜5 に対して 0.18, 0.36, 0.54, 0.72, 0.90 となる。

**F_k = 0 のサブテクニックの扱い（論文 3.4.1 節、式 (11) の例外）**: 攻撃ツリーの構成上必要となるサブテクニックのうち観測頻度が 0 のもの（本研究では T1496.002、T1496.004、T1578.004）は、親テクニック（T1496、T1578）に観測実績があることから、最小の Level 1（P_i = 0.18）を与えている。`Pi_scoring_MITRE_v17.1_frequency_BIN.csv` ではこの 3 件の `Freq_BinScore` は 0 のままであり、`SPRV/SPRV_LG_LONG_scenario*.xlsx` の `Pi` 列（0.18）がこの例外を適用した値である。4 シナリオでこの 3 件はすべて使用されている（Step 2: T1578.004、Step 4: T1496.002・T1496.004）。

### 2.2 `SPRV/SPRV_LG_LONG_scenario*.xlsx`（式 3〜5、12、14〜16）

`LONG` シート（1 行 = 1 攻撃ツリーの 1 ステップ、64 × 4 = 256 行）

| 列 | 論文の記号 | 説明 |
|---|---|---|
| `AttackTree_ID`, `AttackTree_Key` | k | 攻撃ツリー番号（例: B-002） |
| `Step_num` | i | 攻撃ステップ（1〜4） |
| `Technique_ID`, `Asset` | T_τ(i), 対象資産 | 表 6 と同じ組合せ |
| `Pi` | P_i | 攻撃再現性率（式 12） |
| `Mi_Current` | M_i | ガイドライン遵守時の防御失敗率（式 14、β = 0.1） |
| `Mi_Worst`, `Mi_Full` | — | 無対策時（0.9）、全対策実施時（0.1）の M_i |
| `Ci` | C_i | 補正係数（表 3・表 4。`Settings` シートの変換表で資産種別から割当） |
| `Qhat_i_Current` | Q̂_i = min(1, P_i · M_i · C_i) | 実効ステップ毎攻撃成功率（式 4） |
| `Ri_Current` | R_i = R_{i−1} · Q̂_i | 攻撃経路到達率（式 5）。図 9・10 の青線 |
| `Ri_Worst`, `Ri_Full` | — | 無対策時・全対策時の R_i。図 9・10 の赤線・緑線 |
| `Rtree_Current` | R_tree = R_4 | 最終ステップの到達率（式 16） |
| `Risk_Class` | — | R_tree の相対危険度（A/B/C）。図 7 |

`Tree_Summary` シート: ツリー単位の R_tree と Risk_Class。`Risk_Summary` シート: R_sum（式 15）と A/B/C の本数。`Settings` シート: 式と C_i の変換表。

Risk 分類（図 7）は、ガイドライン遵守時・無対策時（M_i = 0.9）・全対策時（M_i = 0.1）の R_tree を用いて

  LogRatio = (ln R_tree,遵守 − ln R_tree,全対策) / (ln R_tree,無対策 − ln R_tree,全対策)

を求め、LogRatio ≥ 2/3 を Risk A、≥ 1/3 を Risk B、それ未満を Risk C とする（無対策を 1、全対策を 0 とする対数尺度上の相対位置）。

論文の図 9 で分析する攻撃ツリーは `scenarioB.xlsx` の **B-002**、図 10 は `scenarioD.xlsx` の **D-002** である。

### 2.3 `IPA/Scenario*_IPA_scenario_threat_fixed.xlsx`（表 8、図 7）

攻撃ツリーごとに事業被害レベル・脅威レベル・対策レベルから脆弱性レベルとリスク値（A/B/C）を IPA 方式で算定したもの。`IPA_Risk_Rules` シートに採点規則を置く。脅威レベルはシナリオ単位で固定（表 8: A = 2, B = 2, C = 1, D = 3）。

### 2.4 `di_mitigation/` と `di_no_mitigation/`（3.4.2 節、式 13・14）

対策評価値 d_i（1〜5）の算定手順を再現する。

**Mitigation が定義されている場合**（`calc_Mi_from_STIX_and_guidelines.ipynb`）
1. MITRE ATT&CK v17.1 の STIX から、テクニックに紐づく Mitigation（N_i 件）とその説明文を取得する
2. 総務省「地方公共団体における情報セキュリティポリシーに関するガイドライン」およびデジタル庁のガバメントクラウド関連規定（計 5 文書）を文単位に分割し、各 Mitigation の説明文との意味類似度（多言語 Sentence-BERT、閾値 0.45）で該当候補を抽出する
3. 候補を人手で確認し、該当が確認された Mitigation の数 n_i を確定する
4. 実施率 m_i = n_i / N_i（式 13）を境界 0.2 / 0.4 / 0.6 / 0.8 で 5 段階に変換し、d_i とする
5. 式 (14) により M_i = β + (1 − d_i / 5)(1 − β)、β = 0.1

**Mitigation が定義されていない場合**（`scenario_no_mitigation_analysis.xlsx`、`final_result_with_digital_and_pages.xlsx`）
1. テクニックの Detection 記述から統制目的と導出対策（監視・検知の対象）を抽出する
2. 各導出対策について、総務省ガイドラインとデジタル庁規定の該当箇所を特定し（ページ付き）、充足度を 5 段階（1〜5）で評価する
3. 全導出対策の充足度の平均を四捨五入した値を d_i とする（例: T1496.001 は平均 3.83 → d_i = 4。論文の表 7）
4. 本稿の 4 シナリオで該当したテクニックは T1496.001, T1496.002, T1496.004, T1578.004 の 4 件で、いずれも d_i = 4（M_i = 0.28）。論文の表 2（4 観点の枠組み）は補完的対策を検討する際の参照枠であり、d_i の算定式ではない

---

## 3. 再現手順

```
pip install pandas openpyxl matplotlib
cd scripts

# (1) P_i の算定を STIX から再現し、同梱の表と突き合わせる（679 テクニックすべてで一致する）
python3 pi_from_stix.py --download --out results/Pi_scoring_from_stix.csv --compare ../Pi_scoring_MITRE_v17.1_frequency_BIN.csv

# (2) SPRV を計算し、xlsx の計算列および論文の図 8 の R_sum と突き合わせ、図 7〜10 を描く
python3 sprv_calc.py --indir ../SPRV --out results --check

# (3) 感度分析（4.4 節）
python3 sensitivity.py

# (4) P_i ±5% と C_i ±0.1・±0.2 の感度分析（4.4.1 節・4.4.2 節）
python3 sensitivity_extra.py

# (5) d_i・P_i のシナリオ間整合の点検
python3 check_di_consistency.py
```

(2) は基準条件（β = 0.1、C_i 既定）で R_sum が図 8 の値（A 0.014060 / B 0.045477 / C 0.017576 / D 0.040929）に一致し、Q̂_i・R_i・Risk 分類が xlsx と一致することを確認して出力する。`--beta` で式 14 の β を変えて計算できる。

(3) の出力は次のとおりで、いずれの条件でもシナリオの順位は B > D > C > A で変わらない。

| 条件 | 内容 |
|---|---|
| β = 0.05 / 0.10 / 0.20 | 式 (14) の β を変えて M_i を再計算（論文の表 10） |
| C_i 一段階下げ | 全ステップの C_i を表 4 の一段階下へ（2.0→1.5, 1.5→1.35, 1.35→1.2） |
| C_i 一段階上げ | 全ステップの C_i を一段階上へ（1.35→1.5, 1.5→2.0, 2.0 は上限）（論文の表 11） |

(4) の条件と結果（基準 R_sum：A 0.014060 / B 0.045477 / C 0.017576 / D 0.040929）

| 条件 | R_sum の変化率 | 順位 |
|---|---|---|
| P_i を全体に一律に ×0.95 / ×1.05 | 全シナリオ −18.5% / +21.6% | B > D > C > A（不変） |
| C_i を全体に一律に −0.2 / +0.2 | −0.2：A −36.8%、B −41.4%、C −36.8%、D −42.4%。+0.2：A +50.8%、B +60.1%、C +50.8%、D +62.2% | B > D > C > A（不変） |
| C_i を全体に一律に −0.1 / +0.1 | −0.1：−20.0%〜−23.4%。+0.1：+23.5%〜+28.3% | B > D > C > A（不変） |
| P_i をシナリオごとに独立に ±5%（上位 ×0.95、下位 ×1.05） | B 対 D、C 対 A は逆転する（D 対 C は逆転しない） | 順位が変わりうる |
| P_i に ×U(0.95, 1.05) を掛ける Monte Carlo（10,000 回、シード 0）(a) ステップごとに独立 | — | B > D > C > A が 100.0%（10,000 回すべて） |
| 同 (b) シナリオごとに独立（シナリオ内の全ステップは同率） | D > B が 26.7%、A > C が 10.0% | B > D > C > A は 66.1%（D > B > C > A 23.8%、B > D > A > C 7.2%、D > B > A > C 2.8%） |

R_4 は P_i の 4 乗に比例するため、±5% の変動は R_sum では約 −19%〜+22% になる。論文 4.4.1 節・4.4.2 節の記述はこの表の条件に対応する。出力は `scripts/results/sensitivity_extra.csv`（一律・Ci）と `scripts/results/sensitivity_extra_montecarlo.csv`（Monte Carlo）。

攻撃ツリーの生成（4.2.1 節、図 6）は本リポジトリの対象外とし、生成済みの 64 ツリー × 4 シナリオを `SPRV/` の入力として提供する。

## 4. 環境

- MITRE ATT&CK Enterprise v17.1（`enterprise-attack.json`、2025-04-22）
- Python 3.10 以上、pandas、openpyxl、matplotlib（scripts/）、sentence-transformers（d_i 算定ノートブック）
- Excel 計算シートは Microsoft Excel および LibreOffice Calc で再計算可能

## 5. 変更履歴

**2026 年 10 月（修正稿）— シナリオ A の対策評価値 d_i の修正**

手続きを具体的に書いたときに数値誤りに気付いたため、以下を修正した。

- 対象: `SPRV/SPRV_LG_LONG_scenarioA.xlsx` の T1578.002（Create Cloud Instance、Step 2、対象資産 Update server OnCloud）の 16 行（16 攻撃ツリー）。
- 修正: d_i = 5（M_i = 0.10）→ d_i = 3（M_i = 0.46）。同一テクニック・同一資産種別を含むシナリオ C（Update server OnCloud）およびシナリオ B・D（VDI Auth Server）の d_i = 3 に揃えた。
- 影響: 上記 16 本の R_tree が 4.6 倍になり、R_sum（シナリオ A）が 0.007733 → 0.014060 となった。他の 48 本およびシナリオ B・C・D は変わらない。
- 結果: シナリオ間の順位（B > D > C > A）、各シナリオのリスク分類（A: 64 本すべて Risk C、B・D: 28 本 Risk B）は変わらない。論文では図 8、4.3.1 節、表 10・表 11 のシナリオ A の値と、4.4.2 節の関連記述を更新した。
- 追加: 論文 4.4.1 節・4.4.2 節の感度分析（P_i ±5%、C_i ±0.1・±0.2）を再現する `scripts/sensitivity_extra.py` を追加した。これに合わせ、論文では変動の与え方（全体に一律）と変動幅（C_i ±0.2 で R_sum は −42%〜+62%）を明記した。
- 注記: 観測頻度 0 のサブテクニック 3 件（T1496.002、T1496.004、T1578.004）に Level 1（P_i = 0.18）を与えている旨を 2.1 節に明記した（論文 3.4.1 節の式 (11) の例外に対応）。
- 点検: 修正後，4 シナリオで用いた全 15 テクニックについて，シナリオ間で d_i と P_i が一致していることを `scripts/check_di_consistency.py` で確認した（不一致 0 件）。
- 再現: `scripts/sprv_calc.py` の基準値 `PAPER_RSUM["A"]` と `scripts/results/` 内の出力を更新した。

## 6. 引用

本資料を利用する場合は、上記論文を引用してください。

## 7. 連絡先

伊藤 吉也（東京電機大学 先端科学技術研究科）
