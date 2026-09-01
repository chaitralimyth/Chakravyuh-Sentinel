import pickle
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Paths
lr_path = os.path.join(BASE_DIR, "models", "logistic-regression-model.pkl")
rf_path = os.path.join(BASE_DIR, "models", "randomforest-model.pkl")
xgb_path = os.path.join(BASE_DIR, "models", "xgb_model.pkl")
feature_path = os.path.join(BASE_DIR, "models", "features-order.pkl")

# Load models
with open(lr_path, "rb") as f:
    lr_model = pickle.load(f)

with open(rf_path, "rb") as f:
    rf_model = pickle.load(f)

with open(xgb_path, "rb") as f:
    xgb_model = pickle.load(f)

# Load feature order
with open(feature_path, "rb") as f:
    feature_order = pickle.load(f)