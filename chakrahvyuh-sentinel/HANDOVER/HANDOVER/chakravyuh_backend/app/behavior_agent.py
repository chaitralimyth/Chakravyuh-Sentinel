"""
Deterministic behavior decision layer.

This module belongs ONLY to the behavior ML pipeline.

It does NOT replace or modify app/agent.py,
which belongs to the existing URL ML pipeline.

No LLM.
No reinforcement learning.
No heuristic URL blocking.

The behavior model's decoded prediction determines the action:

attacker -> BLOCK
normal   -> ALLOW
"""

from app.behavior_model_loader import (
    behavior_model,
    behavior_label_encoder,
    behavior_feature_order,
    BEHAVIOR_MODEL_SUPPORTS_PROBA,
)


EXPECTED_FEATURE_COUNT = 28


def decide_behavior(
    prediction_label: str,
    confidence: float | None,
) -> dict:
    """
    Convert the decoded behavior model prediction into
    a deterministic security decision.

    attacker -> BLOCK
    normal   -> ALLOW
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
        f"Unexpected behavior model label: {prediction_label!r}. "
        "Expected 'attacker' or 'normal'."
    )


def run_behavior_prediction(feature_vector: list) -> dict:
    """
    Run the behavior ML pipeline:

    feature vector
        ↓
    RandomForest model
        ↓
    numeric prediction
        ↓
    label encoder
        ↓
    attacker / normal
        ↓
    deterministic behavior decision
    """

    # ---------------------------------------------------------
    # Validate feature vector
    # ---------------------------------------------------------

    if len(feature_vector) != EXPECTED_FEATURE_COUNT:
        raise ValueError(
            "Behavior feature vector must contain exactly "
            f"{EXPECTED_FEATURE_COUNT} values, but received "
            f"{len(feature_vector)}."
        )

    if len(feature_vector) != len(behavior_feature_order):
        raise ValueError(
            "Behavior feature vector length does not match "
            "feature_columns_behaviour.pkl: "
            f"vector={len(feature_vector)}, "
            f"feature_order={len(behavior_feature_order)}."
        )

    # ---------------------------------------------------------
    # Run RandomForest prediction
    # ---------------------------------------------------------

    numeric_prediction = behavior_model.predict(
        [feature_vector]
    )[0]

    # ---------------------------------------------------------
    # Decode numeric prediction
    # ---------------------------------------------------------

    prediction_label = behavior_label_encoder.inverse_transform(
        [numeric_prediction]
    )[0]

    # ---------------------------------------------------------
    # Calculate confidence
    # ---------------------------------------------------------

    confidence = None

    if BEHAVIOR_MODEL_SUPPORTS_PROBA:
        probabilities = behavior_model.predict_proba(
            [feature_vector]
        )[0]

        class_index = list(
            behavior_model.classes_
        ).index(numeric_prediction)

        confidence = float(
            probabilities[class_index]
        )

    # ---------------------------------------------------------
    # Deterministic agent decision
    # ---------------------------------------------------------

    return decide_behavior(
        str(prediction_label),
        confidence,
    )