import os
import json
import numpy as np
import joblib


MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model')


def load_models():
    """Load trained ML models."""
    try:
        rf_model = joblib.load(os.path.join(MODEL_DIR, 'random_forest.joblib'))
        lr_model = joblib.load(os.path.join(MODEL_DIR, 'logistic_regression.joblib'))
        feature_names = joblib.load(os.path.join(MODEL_DIR, 'feature_names.joblib'))
        return rf_model, lr_model, feature_names
    except FileNotFoundError:
        return None, None, None


def predict_with_ml(features_dict):
    """Predict phishing using trained ML models."""
    rf_model, lr_model, feature_names = load_models()

    if rf_model is None:
        return None

    # Build feature vector in the correct order
    feature_vector = np.array([[features_dict.get(f, 0) for f in feature_names]])

    # Get predictions
    rf_prediction = rf_model.predict(feature_vector)[0]
    rf_proba = rf_model.predict_proba(feature_vector)[0]

    lr_prediction = lr_model.predict(feature_vector)[0]
    lr_proba = lr_model.predict_proba(feature_vector)[0]

    # Ensemble: average probabilities
    avg_proba = (rf_proba + lr_proba) / 2
    ensemble_prediction = 1 if avg_proba[1] > 0.5 else 0
    confidence = float(max(avg_proba)) * 100

    classification = 'PHISHING' if ensemble_prediction == 1 else 'BENIGN'

    # Get feature importances from Random Forest
    importances = {}
    if hasattr(rf_model, 'feature_importances_'):
        for fname, importance in zip(feature_names, rf_model.feature_importances_):
            importances[fname] = float(importance)

    return {
        'classification': classification,
        'confidence': round(confidence, 1),
        'rf_prediction': 'PHISHING' if rf_prediction == 1 else 'BENIGN',
        'lr_prediction': 'PHISHING' if lr_prediction == 1 else 'BENIGN',
        'rf_confidence': float(max(rf_proba)) * 100,
        'lr_confidence': float(max(lr_proba)) * 100,
        'feature_importances': importances,
        'model_used': 'ensemble_rf_lr',
    }
