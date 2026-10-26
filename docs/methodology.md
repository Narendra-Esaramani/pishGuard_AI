# Research Methodology and Training Workflow

## 1. Data Collection & Preprocessing
- **Raw Dataset**: 10,000 samples (5,000 phishing [CLASS_LABEL=1], 5,000 legitimate [CLASS_LABEL=0]).
- **Duplicate Removal & Validation**: Dropped 419 duplicate records, yielding 9,581 verified unique samples.
- **Stratified Partitioning**: 80% training set (7,664 samples), 20% held-out test set (1,917 samples).
- **Leakage Prevention**: All preprocessing and feature scaling transformations fitted strictly on training splits.

---

## 2. Model Training & Hyperparameter Configuration
The system evaluates six distinct algorithm classes:
1. **XGBoost Classifier**: 150 estimators, max depth 6, learning rate 0.08, subsample 0.85.
2. **Random Forest Classifier**: 150 estimators, max depth 16, min samples split 4.
3. **Decision Tree Classifier**: Max depth 12, min samples split 6.
4. **Logistic Regression**: L2 regularization, max iterations 1,500.
5. **K-Nearest Neighbors**: 5 neighbors, Euclidean distance.
6. **Support Vector Machine**: RBF kernel with calibrated probability estimates.

---

## 3. Explainability Pipeline
1. Local feature attributions calculated using Shapley values via `shap.TreeExplainer`.
2. Contributions aggregated and sorted by magnitude.
3. Attribution vectors mapped to domain-specific natural language rule templates.
