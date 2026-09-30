"""
Behavior ML prediction and detection layer.

The behavior model classifies session feature vectors:
    0 -> attacker
    1 -> normal

Behavior ML detects threat signals and calculates attack probabilities.
The final security policy decision is determined by the Adaptive Security Agent.
"""

from typing import Optional
from app.behavior_model_loader import (
    behavior_model,
    behavior_label_encoder,
    behavior_feature_order,
    BEHAVIOR_MODEL_SUPPORTS_PROBA,
)

EXPECTED_FEATURE_COUNT = 28
ATTACKER_LABEL = 0
NORMAL_LABEL = 1


def decide_behavior(
    prediction_label: str,
    confidence: Optional[float],
) -> dict:
    """
    Legacy helper: convert the decoded behavior model prediction into a decision dict.
    Maintained for backward compatibility.
    """
    if prediction_label == "attacker":
        return {
            "prediction": "attacker",
            "confidence": confidence,
            "action": "BLOCK",
            "reason": "Session behavior classified as attacker",
        }

    if prediction_label == "normal":
        return {
            "prediction": "normal",
            "confidence": confidence,
            "action": "ALLOW",
            "reason": "Session behavior classified as normal",
        }

    raise ValueError(
        f"Unexpected behavior model label: {prediction_label!r}. Expected 'attacker' or 'normal'."
    )


def run_behavior_prediction(feature_vector: list) -> dict:
    """
    Run the behavior ML prediction pipeline:
    Validates the 28-feature vector, generates predictions, and computes
    continuous attack probability and confidence for the Dynamic Risk Engine.
    """
    if len(feature_vector) != EXPECTED_FEATURE_COUNT:
        raise ValueError(
            f"Behavior feature vector must contain exactly {EXPECTED_FEATURE_COUNT} values, but received {len(feature_vector)}."
        )

    if len(feature_vector) != len(behavior_feature_order):
        raise ValueError(
            f"Behavior feature vector length ({len(feature_vector)}) does not match feature_columns_behaviour.pkl ({len(behavior_feature_order)})."
        )

    numeric_prediction = int(behavior_model.predict([feature_vector])[0])

    prediction_confidence = None
    attack_probability = None

    if BEHAVIOR_MODEL_SUPPORTS_PROBA:
        probabilities = behavior_model.predict_proba([feature_vector])[0]
        classes = list(behavior_model.classes_)

        # Class 0 = attacker
        if ATTACKER_LABEL in classes:
            attacker_index = classes.index(ATTACKER_LABEL)
            attack_probability = float(probabilities[attacker_index])

        # Confidence for the predicted class
        if numeric_prediction in classes:
            predicted_index = classes.index(numeric_prediction)
            prediction_confidence = float(probabilities[predicted_index])

    if numeric_prediction == ATTACKER_LABEL:
        prediction = "attacker"
    elif numeric_prediction == NORMAL_LABEL:
        prediction = "normal"
    else:
        # Fallback to label encoder if unexpected numeric value
        prediction = str(behavior_label_encoder.inverse_transform([numeric_prediction])[0])

    # If attack_probability was not computed from proba, estimate from prediction
    if attack_probability is None:
        attack_probability = 1.0 if prediction == "attacker" else 0.0

    return {
        "prediction": prediction,
        "prediction_value": numeric_prediction,
        "confidence": prediction_confidence,
        "attack_probability": attack_probability,
        "action": "BLOCK" if prediction == "attacker" else "ALLOW",
        "reason": f"Session behavior classified as {prediction}",
    }
