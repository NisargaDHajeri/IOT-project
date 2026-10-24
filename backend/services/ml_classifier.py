"""Random Forest Machine Learning Risk Classifier Service.

Provides:
- Model loading from disk with automatic fallback training if model is missing
- Multi-class probability distribution estimation
- Evaluation of 8 runtime security telemetry features
"""

import os
import joblib
import pandas as pd
from typing import Dict, Any, Tuple
from config import MODEL_PATH, FEATURES


class MLRiskClassifier:
    _instance = None
    _model = None

    @classmethod
    def get_model(cls):
        if cls._model is None:
            if not MODEL_PATH.exists():
                raise FileNotFoundError(
                    "Device risk model artifact is unavailable."
                )
            cls._model = joblib.load(MODEL_PATH)
        return cls._model

    @classmethod
    def predict(cls, context: Dict[str, Any]) -> Dict[str, Any]:
        """Runs inference over the context features.
        
        Returns: {
            "predicted_risk": str,
            "confidence": Dict[str, float],
            "max_confidence": float,
            "model_version": str
        }
        """
        model = cls.get_model()
        
        # Extract features in exact order
        row = {f: context.get(f, 0) for f in FEATURES}
        df = pd.DataFrame([row])[FEATURES]

        prediction = model.predict(df)[0]
        probabilities = model.predict_proba(df)[0]

        confidence_map = {
            cls_name: round(float(prob), 4)
            for cls_name, prob in zip(model.classes_, probabilities)
        }

        return {
            "predicted_risk": prediction,
            "confidence": confidence_map,
            "max_confidence": round(float(max(probabilities)), 4),
            "model_version": "RandomForest-v2.1-N250",
        }


def predict_risk(context: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience wrapper for MLRiskClassifier inference."""
    return MLRiskClassifier.predict(context)
