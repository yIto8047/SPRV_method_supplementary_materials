# 補足資料 — 自治体ゼロトラスト環境を事例とした MITRE ATT&CK に基づく攻撃伝播型リスク可視化モデルの提案と評価

Supplementary materials for: *Proposal and Evaluation of a Stepwise Propagated Risk Visualization Model for Cyber Attacks Based on the MITRE ATT&CK Using a Zero Trust Environment in Local Governments as a Case Study* (JSSM, JSSM-D-26-00006)

本リポジトリは、上記論文の第 3 章（提案方式）で定義した各指標の算定データと、第 4 章（検証と評価）で用いたリスク計算シート・感度分析の再現用スクリプトを提供する。論文中の式番号・図表番号との対応を下表に示す。

---

## 1. ファイル構成と論文との対応

| ファイル | 内容 | 論文での対応 |
|---|---|---|
| `Pi_scoring_MITRE_v17.1_frequency_BIN.csv` | MITRE ATT&CK Enterprise v17.1 の全 679 テクニックについて、攻撃グループ・キャンペーン・ソフトウェアからの参照回数（G_k, C_k, S_k）、総観測頻度 F_k、相対比率、BIN レベル（1〜5） | 3.4.1 節、式 (7)・(8)、表 1、4.2.1 節（図 5） |
| `MITRE_dictionary_J_ver3.csv` | MITRE ATT&CK Enterprise v17.1 のテクニック辞書（823 件）。技術名の日本語訳、戦術、プラットフォーム、対象資産候補、攻撃ステップ（S1〜S4）への分類 | 4.1.1 節（表 5 のテクニック選定）、図 6 |
| `asset_list_LG.txt` | 攻撃進展構造の自動生成に入力する資産定義（自治体ゼロトラスト・ハイブリッド環境） | 図 4 |
| `SPRV/SPRV_LG_LONG_scenario{A,B,C,D}.xlsx` | SPRV 方式の計算シート（シナリオ A〜D、各 64 攻撃ツリー × 4 ステップ） | 式 (2)〜(4)、(8)〜(11)、図 7（SPRV 側）、図 8、図 9、図 10 |
| `IPA/Scenario{A,B,C,D}_IPA_scenario_threat_fixed.xlsx` | IPA 方式の計算シート（攻撃ツリー単位の事業被害・脅威・対策・脆弱性とリスク値） | 表 6、図 7（IPA 側） |
| `di_no_mitigation/scenario_no_mitigation_analysis.xlsx` | MITRE の Mitigation が定義されていないテクニックの抽出と、Detection 記述からの統制目標の導出 | 3.4.2 節（表 2）、4.1.2 節 |
| `di_no_mitigation/final_result_with_digital_and_pages.xlsx` | 導出した統制目標と、総務省ガイドライン・デジタル庁規定の該当箇所（ページ付き）の照合結果 | 同上 |
| `di_mitigation/calc_Mi_from_STIX_and_guidelines.ipynb` | Mitigation が定義されているテクニックについて、Mitigation ごとにガイドラインへの該当を照合し、実施率から対策評価値 d_i と防御失敗率 M_i を算出するノートブック | 3.4.2 節、式 (9) |
| `scripts/pi_from_stix.py` | MITRE ATT&CK の STIX から G_k・C_k・S_k を数え、F_k → 対数 BIN → P_i を算定する（`Pi_scoring_MITRE_v17.1_frequency_BIN.csv` を再生成） | 3.4.1 節、式 (7)・(8) |
| `scripts/sprv_calc.py` | SPRV の計算（式 2〜4、9〜11）、Risk 分類、図 7〜10 の再現 | 3.4 節、4.2〜4.3 節 |
| `scripts/sensitivity.py` | β（式 9）と C_i を変化させた場合の R_sum と順位の再計算 | 4.4 節 |
| `scripts/results/` | 上の 3 スクリプトの出力（P_i 表、ツリー別・シナリオ別の計算結果、図 7〜10、感度分析の表） | — |

---

## 2. 各ファイルの列と論文の記号

### 2.1 `Pi_scoring_MITRE_v17.1_frequency_BIN.csv`（式 7・8）

| 列 | 論文の記号 | 説明 |
|---|---|---|
| `Technique_ID` | T_k | テクニック ID（サブテクニックを含む） |
| `Freq_Group` | G_k | 攻撃グループからの参照回数 |
| `Freq_Campaign` | C_k | キャンペーンからの参照回数 |
| `Freq_Software` | S_k | ソフトウェアからの参照回数 |
| `Freq_Total` | F_k = G_k + C_k + S_k | 総観測頻度（式 7） |
| `Freq_Total_Pct` | — | 全 679 テクニックの総参照数（ΣF_k = 15,049）に対する相対比率（%） |
| `Freq_BinScore` | L(T_k) | BIN レベル（1〜5）。式 (8) の L(T_i) に用いる |
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

攻撃再現性率は式 (8) により P_i = 0.9 × L(T_i) / 5、すなわち Level 1〜5 に対して 0.18, 0.36, 0.54, 0.72, 0.90 となる。

### 2.2 `SPRV/SPRV_LG_LONG_scenario*.xlsx`（式 2〜4、8〜11）

`LONG` シート（1 行 = 1 攻撃ツリーの 1 ステップ、64 × 4 = 256 行）

| 列 | 論文の記号 | 説明 |
|---|---|---|
| `AttackTree_ID`, `AttackTree_Key` | k | 攻撃ツリー番号（例: B-002） |
| `Step_num` | i | 攻撃ステップ（1〜4） |
| `Technique_ID`, `Asset` | T_i, 対象資産 | 表 5 と同じ組合せ |
| `Pi` | P_i | 攻撃再現性率（式 8） |
| `Mi_Current` | M_i | ガイドライン遵守時の防御失敗率（式 9、β = 0.1） |
| `Mi_Worst`, `Mi_Full` | — | 無対策時（0.9）、全対策実施時（0.1）の M_i |
| `Ci` | C_i | 補正係数（表 3。`Settings` シートの変換表で資産種別から割当） |
| `Qhat_i_Current` | Q̂_i = min(1, P_i · M_i · C_i) | 実効ステップ毎攻撃成功率（式 3） |
| `Ri_Current` | R_i = R_{i−1} · Q̂_i | 攻撃経路到達率（式 4）。図 9・10 の青線 |
| `Ri_Worst`, `Ri_Full` | — | 無対策時・全対策時の R_i。図 9・10 の赤線・緑線 |
| `Rtree_Current` | R_tree = R_4 | 最終ステップの到達率（式 11） |
| `Risk_Class` | — | R_tree の相対危険度（A/B/C）。図 7 |

`Tree_Summary` シート: ツリー単位の R_tree と Risk_Class。`Risk_Summary` シート: R_sum（式 10）と A/B/C の本数。`Settings` シート: 式と C_i の変換表。

Risk 分類（図 7）は、ガイドライン遵守時・無対策時（M_i = 0.9）・全対策時（M_i = 0.1）の R_tree を用いて

  LogRatio = (ln R_tree,遵守 − ln R_tree,全対策) / (ln R_tree,無対策 − ln R_tree,全対策)

を求め、LogRatio ≥ 2/3 を Risk A、≥ 1/3 を Risk B、それ未満を Risk C とする（無対策を 1、全対策を 0 とする対数尺度上の相対位置）。

論文の図 9 で分析する攻撃ツリーは `scenarioB.xlsx` の **B-002**、図 10 は `scenarioD.xlsx` の **D-002** である。

### 2.3 `IPA/Scenario*_IPA_scenario_threat_fixed.xlsx`（表 6、図 7）

攻撃ツリーごとに事業被害レベル・脅威レベル・対策レベルから脆弱性レベルとリスク値（A/B/C）を IPA 方式で算定したもの。`IPA_Risk_Rules` シートに採点規則を置く。脅威レベルはシナリオ単位で固定（表 6: A = 2, B = 2, C = 1, D = 3）。

### 2.4 `di_mitigation/` と `di_no_mitigation/`（3.4.2 節、式 9）

対策評価値 d_i（1〜5）の算定手順を再現する。

**Mitigation が定義されている場合**（`calc_Mi_from_STIX_and_guidelines.ipynb`）
1. MITRE ATT&CK v17.1 の STIX から、テクニックに紐づく Mitigation（N_i 件）とその説明文を取得する
2. 総務省「地方公共団体における情報セキュリティポリシーに関するガイドライン」およびデジタル庁のガバメントクラウド関連規定（計 5 文書）を文単位に分割し、各 Mitigation の説明文との意味類似度（多言語 Sentence-BERT、閾値 0.45）で該当候補を抽出する
3. 候補を人手で確認し、該当が確認された Mitigation の数 n_i を確定する
4. 実施率 m_i = n_i / N_i を境界 0.2 / 0.4 / 0.6 / 0.8 で 5 段階に変換し、d_i とする
5. 式 (9) により M_i = β + (1 − d_i / 5)(1 − β)、β = 0.1

**Mitigation が定義されていない場合**（`scenario_no_mitigation_analysis.xlsx`、`final_result_with_digital_and_pages.xlsx`）
1. テクニックの Detection 記述から統制目標（監視・検知の対象）を導出する
2. 各統制目標について、総務省ガイドラインとデジタル庁規定の該当箇所を照合する（○/△/×、ページ付き）
3. すべての統制目標が両規定で要求されていれば d_i = 4、一部が片方のみなら 3、いずれかが両方で要求されていなければ 2 とする。Detection 由来の統制は攻撃の検知・記録にとどまり実行を阻止しないため、上限を 4 とする
4. 本稿の 4 シナリオで該当したテクニックは T1496.001, T1496.002, T1496.004, T1578.004 の 4 件で、いずれも d_i = 4（M_i = 0.28）

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
```

(2) は基準条件（β = 0.1、C_i 既定）で R_sum が図 8 の値（A 0.007733 / B 0.045477 / C 0.017576 / D 0.040929）に一致し、Q̂_i・R_i・Risk 分類が xlsx と一致することを確認して出力する。`--beta` で式 9 の β を変えて計算できる。

(3) の出力は次のとおりで、いずれの条件でもシナリオの順位は B > D > C > A で変わらない。

| 条件 | 内容 |
|---|---|
| β = 0.05 / 0.10 / 0.20 | 式 (9) の β を変えて M_i を再計算 |
| C_i 一段階下げ | 全ステップの C_i を表 3 の一段階下へ（2.0→1.5, 1.5→1.35, 1.35→1.2） |
| C_i 一段階上げ | 全ステップの C_i を一段階上へ（1.35→1.5, 1.5→2.0, 2.0 は上限） |

攻撃ツリーの生成（4.2.1 節、図 6）は本リポジトリの対象外とし、生成済みの 64 ツリー × 4 シナリオを `SPRV/` の入力として提供する。

## 4. 環境

- MITRE ATT&CK Enterprise v17.1（`enterprise-attack.json`、2025-04-22）
- Python 3.10 以上、pandas、openpyxl、matplotlib（scripts/）、sentence-transformers（d_i 算定ノートブック）
- Excel 計算シートは Microsoft Excel および LibreOffice Calc で再計算可能

## 5. 引用

本資料を利用する場合は、上記論文を引用してください。

## 6. 連絡先

伊藤 吉也（東京電機大学 先端科学技術研究科）
