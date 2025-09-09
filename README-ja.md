# 論文タイトル:
自治体ゼロトラスト環境を事例としたMITRE ATT&CKに基づく攻撃伝播型リスク可視化モデルの提案と評価
Proposal and Evaluation of a Stepwise Propagated Risk Visualization Model 
for Cyber Attacks Based on the MITRE ATT&CK Using a Zero Trust Environment in Local Governments as a Case Study


## 概要
このリポジトリは、[自治体ゼロトラスト環境を事例としたMITRE ATT&CKに基づく攻撃伝播型リスク可視化モデルの提案と評価]に関連する
- リスク分析結果：IPA方式、SPRE方式
- 補助資料:MITRE ATT&CK Cloud Matrix 攻撃再現性スコアリング結果表(Prevalence_Score_for Cloud Matrix Technique all IDs.xls)
Pythonコードサンプル
等を提供します。

## 本リポジトリの内容

- `/data/`: Prevalence_Score_for Cloud Matrix Technique all IDs.xls：MITRE Cloud Matrix攻撃再現性スコアリング結果表
- `/data/`: ScenarioA_Attack_Path_IPA_20250822.xls：シナリオA_リスク分析結果_IPA方式
- `/data/`: ScenarioB_Attack_Paths_IPA_20250822.xls：シナリオB_リスク分析結果_IPA方式
- `/data/`: ScenarioC_IPA_Risk Score_Attack_Paths_IPA_20250822.xls：シナリオC_リスク分析結果_IPA方式
- `/data/`: ScenarioD_Attack_Paths_IPA_20250822.xls：シナリオD_リスク分析結果_IPA方式
- `/data/`: ScenarioA_SPRE_Risk Score_Attack_Path_IPA_20250803.xls：シナリオA_リスク分析結果_SPRE方式
- `/data/`: ScenarioB_SPRE_Risk Score_Attack_Paths_IPA_20250803.xls：シナリオB_リスク分析結果_SPRE方式
- `/data/`: ScenarioC_SPRE_Risk Score_Attack_Paths_IPA_20250803.xls：シナリオC_リスク分析結果_SPRE方式
- `/data/`: ScenarioD_SPRE_Risk Score_Attack_Paths_IPA_20250803.xls：シナリオD_リスク分析結果_SPRE方式
- `/data/`:3.1_MITRE ATT&CK Cloud Matrixから攻撃再現性のための頻度カウントを抽出するPythonコード.docx
- `/data/`:3.2.3_通信確立ルートへの限定と攻撃パスの最適化.docx
- `/data/`:3.2.4-3.2.5_攻撃パスを通常通信ルートに限定して抽出.docx
- `/data/`:3.3.2_MITRE ATT&CK Cloud Matrixと総務省及びデジタル庁ガイドラインと意味類似度を探索し対策の成熟度をスコア化するPythonコード.docx
- `/data/`:4.4 SPRV方式を可視化するための３つのパラメータ.docx
- `/data/`:4.4_SPRV数式と他方式比較による妥当性検証.docx 
- `/data/`:自治体ゼロトラスト環境モデル_20250821.pptx
- `README-ja.md`: 本ファイル

