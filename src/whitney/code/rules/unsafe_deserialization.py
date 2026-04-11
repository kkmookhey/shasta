# Test file for unsafe_deserialization.yaml rules
import pickle
import torch
import numpy
import numpy as np
import joblib
import yaml
import keras

# --- pickle ---
# ruleid: code-unsafe-deserialization-pickle
data = pickle.load(open("model.pkl", "rb"))

# ruleid: code-unsafe-deserialization-pickle
data = pickle.loads(raw_bytes)

# --- torch ---
# ruleid: code-unsafe-deserialization-torch-load
model = torch.load("model.pt")

# ok: code-unsafe-deserialization-torch-load
model = torch.load("model.pt", weights_only=True)

# --- numpy ---
# ruleid: code-unsafe-deserialization-numpy-load
data = numpy.load("data.npy", allow_pickle=True)

# ruleid: code-unsafe-deserialization-numpy-load
data = np.load("data.npy", allow_pickle=True)

# ok: code-unsafe-deserialization-numpy-load
data = numpy.load("data.npy")

# ok: code-unsafe-deserialization-numpy-load
data = np.load("data.npy")

# --- joblib ---
# ruleid: code-unsafe-deserialization-joblib
model = joblib.load("model.joblib")

# --- yaml ---
# ruleid: code-unsafe-deserialization-yaml
config = yaml.load(data)

# ok: code-unsafe-deserialization-yaml
config = yaml.safe_load(data)

# ok: code-unsafe-deserialization-yaml
config = yaml.load(data, Loader=yaml.SafeLoader)

# --- keras ---
# ruleid: code-unsafe-deserialization-keras
model = keras.models.load_model("model.h5")

# ok: code-unsafe-deserialization-keras
model = keras.models.load_model("model.h5", safe_mode=True)
