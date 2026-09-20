"""
SPECTRA PortScan Detector
=========================

Runtime adapter for the frozen SPECTRA binary PortScan XGBoost model.

The model was trained on CIC-IDS2017 PortScan flow telemetry using the
8-feature schema stored in spectra_portscan_feature_schema.json.

This module does NOT train, tune, or evaluate the model.
It only:
    1. validates runtime flow fields,
    2. builds the frozen 8-feature input,
    3. runs XGBoost inference,
    4. applies the model-native decision threshold,
    5. returns a standardized detector result.

The decision threshold (0.50166595) was derived from the trained
model_ps2 by finding the probability cutoff that exactly reproduces
model_ps2.predict() on the notebook test set.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "spectra_portscan_detector.joblib"
SCHEMA_PATH = BASE_DIR / "spectra_portscan_feature_schema.json"

# Model-native decision threshold reproduced from model_ps2.predict().
PORTSCAN_THRESHOLD = 0.50166595


# Runtime input fields used directly by the notebook model.
REQUIRED_INPUT_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "FIN Flag Count",
]


# Frozen feature order. Runtime output must match this order exactly.
FINAL_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "FIN Flag Count",
]


class PortScanDetector:
    """Load and run the frozen SPECTRA PortScan detector."""

    def __init__(
        self,
        model_path: Path = MODEL_PATH,
        schema_path: Path = SCHEMA_PATH,
    ) -> None:
        self.model_path = Path(model_path)
        self.schema_path = Path(schema_path)

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"PortScan model artifact not found: {self.model_path}"
            )

        if not self.schema_path.exists():
            raise FileNotFoundError(
                f"PortScan feature schema not found: {self.schema_path}"
            )

        artifact = joblib.load(self.model_path)

        # Support a directly saved XGBoost model, as used by the notebook.
        self.model = artifact["model"] if isinstance(artifact, dict) and "model" in artifact else artifact

        with self.schema_path.open("r", encoding="utf-8") as f:
            self.feature_schema = json.load(f)

        external_features = self.feature_schema.get("features", [])

        if external_features != FINAL_FEATURES:
            raise ValueError(
                "Feature schema does not match the frozen PortScan "
                "runtime feature order."
            )

        if len(FINAL_FEATURES) != 8:
            raise ValueError("Unexpected PortScan feature count.")

    @staticmethod
    def build_features(flow_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build the exact 8-feature input used by model_ps2.

        No additional feature engineering is performed because the final
        model consumes these eight CIC-IDS2017 columns directly.
        """
        missing = [
            col for col in REQUIRED_INPUT_COLUMNS
            if col not in flow_df.columns
        ]

        if missing:
            raise ValueError(
                "Missing required PortScan input fields: "
                + ", ".join(missing)
            )

        features = flow_df[FINAL_FEATURES].copy()

        # Match the notebook's numerical handling.
        for col in FINAL_FEATURES:
            features[col] = pd.to_numeric(features[col], errors="raise")

        features = features.replace(
            [np.inf, -np.inf],
            np.nan,
        ).fillna(0)

        return features

    def predict_flow(self, flow: Mapping[str, Any]) -> dict[str, Any]:
        """Run binary Benign-vs-PortScan inference on one flow."""
        flow_df = pd.DataFrame([dict(flow)])
        features = self.build_features(flow_df)

        score = float(self.model.predict_proba(features)[0, 1])
        detected = score >= PORTSCAN_THRESHOLD

        return {
            "status": "DETECTED" if detected else "BENIGN",
            "threat_class": "PortScan" if detected else "Benign",
            "score_type": "model_score",
            "raw_score": score,
            "threshold": PORTSCAN_THRESHOLD,
            "evidence": {
                feature: float(features.iloc[0][feature])
                for feature in FINAL_FEATURES
            },
            "context": {
                "feature_count": len(FINAL_FEATURES),
            },
            "detector_name": "portscan",
            "detector_version": self.feature_schema.get(
                "version",
                "1.0",
            ),
            "model_name": "XGBoost",
            "model_version": self.feature_schema.get(
                "version",
                "1.0",
            ),
            "feature_schema": "spectra_portscan_feature_schema.json",
        }

    def predict_batch(
        self,
        flows: pd.DataFrame,
    ) -> list[dict[str, Any]]:
        """Run binary Benign-vs-PortScan inference on multiple flows."""
        features = self.build_features(flows)

        scores = self.model.predict_proba(features)[:, 1]
        predictions = scores >= PORTSCAN_THRESHOLD

        results: list[dict[str, Any]] = []

        for idx, (score, detected) in enumerate(
            zip(scores, predictions)
        ):
            results.append(
                {
                    "status": "DETECTED" if detected else "BENIGN",
                    "threat_class": "PortScan" if detected else "Benign",
                    "score_type": "model_score",
                    "raw_score": float(score),
                    "threshold": PORTSCAN_THRESHOLD,
                    "evidence": {
                        feature: float(features.iloc[idx][feature])
                        for feature in FINAL_FEATURES
                    },
                    "context": {
                        "feature_count": len(FINAL_FEATURES),
                    },
                    "detector_name": "portscan",
                    "detector_version": self.feature_schema.get(
                        "version",
                        "1.0",
                    ),
                    "model_name": "XGBoost",
                    "model_version": self.feature_schema.get(
                        "version",
                        "1.0",
                    ),
                    "feature_schema": (
                        "spectra_portscan_feature_schema.json"
                    ),
                }
            )

        return results


# Convenience instance for simple integration:
#     from portscan_detector import detector
#     result = detector.predict_flow(flow)
detector = PortScanDetector()
