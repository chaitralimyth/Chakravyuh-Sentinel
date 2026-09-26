import joblib

MODEL_PATH = "models/sentinel_behavior_model.pkl"
FEATURES_PATH = "models/feature_columns_behaviour.pkl"

print("Loading behavior model...")
model = joblib.load(MODEL_PATH)

print("Loading feature columns...")
features = joblib.load(FEATURES_PATH)

print("\n===== BEHAVIOR MODEL VERIFICATION =====")

print("Model type:", type(model))
print("Number of features:", model.n_features_in_)

print("\nFeature count:", len(features))
print("Feature columns:")
for i, feature in enumerate(features):
    print(f"{i}: {feature}")

print("\nClasses:", model.classes_)

print("\nPredict proba supported:", hasattr(model, "predict_proba"))

print("\nModel loaded successfully.")