"""
SPECTRA DDoS Detector
=====================

Runtime adapter for the frozen SPECTRA binary DDoS XGBoost model.

The model was trained on CIC-DDoS2019-derived flow telemetry using the
12-feature schema stored in spectra_ddos_feature_schema.json.

This module does NOT train, tune, or evaluate the model.
It only:
    1. validates runtime flow fields,
    2. reproduces the frozen feature engineering,
    3. runs XGBoost inference,
    4. applies the validation-derived decision threshold,
    5. returns a standardized detector result.

Runtime input must provide the CIC-style flow fields listed in
REQUIRED_INPUT_COLUMNS. The upstream SPECTRA feature/telemetry layer is
responsible for mapping passive telemetry into these fields.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "spectra_ddos_detector.joblib"
SCHEMA_PATH = BASE_DIR / "spectra_ddos_feature_schema.json"

EPS = 1e-9

REQUIRED_INPUT_COLUMNS = [
    "Flow Packets/s",
    "Flow Bytes/s",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Packet Length Mean",
    "Packet Length Std",
    "Protocol",
]

# Frozen feature order. Runtime output must match this order exactly.
FINAL_FEATURES = [
    "Flow Packets/s",
    "Flow Bytes/s",
    "Flow Duration",
    "fwd_byte_ratio",
    "packet_asymmetry",
    "byte_asymmetry",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "Packet Length Mean",
    "packet_size_variability",
    "is_udp",
]


class DDoSDetector:
    """Load and run the frozen SPECTRA DDoS detector."""

    def __init__(
        self,
        model_path: Path = MODEL_PATH,
        schema_path: Path = SCHEMA_PATH,
    ) -> None:
        self.model_path = Path(model_path)
        self.schema_path = Path(schema_path)

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"DDoS model artifact not found: {self.model_path}"
            )

        if not self.schema_path.exists():
            raise FileNotFoundError(
                f"DDoS feature schema not found: {self.schema_path}"
            )

        artifact = joblib.load(self.model_path)

        self.model = artifact["model"]
        self.threshold = float(artifact["threshold"])
        self.feature_schema = artifact["feature_schema"]
        self.config = artifact.get("config", {})

        # Verify the separately supplied schema agrees with the packaged
        # artifact schema before allowing inference.
        import json

        with self.schema_path.open("r", encoding="utf-8") as f:
            external_schema = json.load(f)

        artifact_features = self.feature_schema["features"]
        external_features = external_schema["features"]

        if artifact_features != FINAL_FEATURES:
            raise ValueError(
                "Packaged model feature schema does not match the frozen "
                "runtime feature order."
            )

        if external_features != FINAL_FEATURES:
            raise ValueError(
                "External feature schema does not match the frozen "
                "runtime feature order."
            )

        if len(FINAL_FEATURES) != 12:
            raise ValueError("Unexpected DDoS feature count.")

    @staticmethod
    def build_features(flow_df: pd.DataFrame) -> pd.DataFrame:
        """
        Reproduce the exact 12-feature engineering used during training.

        Input:
            DataFrame containing REQUIRED_INPUT_COLUMNS.

        Output:
            DataFrame containing FINAL_FEATURES in frozen order.
        """
        missing = [
            col for col in REQUIRED_INPUT_COLUMNS
            if col not in flow_df.columns
        ]

        if missing:
            raise ValueError(
                "Missing required DDoS input fields: "
                + ", ".join(missing)
            )

        df = flow_df[REQUIRED_INPUT_COLUMNS].copy()

        # Match notebook behavior for numerical values.
        for col in REQUIRED_INPUT_COLUMNS:
            df[col] = pd.to_numeric(df[col], errors="raise")

        df["total_packets"] = (
            df["Total Fwd Packets"] +
            df["Total Backward Packets"]
        )

        df["total_bytes"] = (
            df["Fwd Packets Length Total"] +
            df["Bwd Packets Length Total"]
        )

        df["fwd_byte_ratio"] = (
            df["Fwd Packets Length Total"] /
            (df["total_bytes"] + EPS)
        )

        df["packet_asymmetry"] = (
            (
                df["Total Fwd Packets"] -
                df["Total Backward Packets"]
            ).abs()
            / (df["total_packets"] + EPS)
        )

        df["byte_asymmetry"] = (
            (
                df["Fwd Packets Length Total"] -
                df["Bwd Packets Length Total"]
            ).abs()
            / (df["total_bytes"] + EPS)
        )

        df["syn_ratio"] = (
            df["SYN Flag Count"] /
            (df["total_packets"] + EPS)
        )

        df["rst_ratio"] = (
            df["RST Flag Count"] /
            (df["total_packets"] + EPS)
        )

        df["ack_ratio"] = (
            df["ACK Flag Count"] /
            (df["total_packets"] + EPS)
        )

        df["packet_size_variability"] = (
            df["Packet Length Std"] /
            (df["Packet Length Mean"] + EPS)
        )

        df["is_udp"] = (
            df["Protocol"] == 17
        ).astype(int)

        features = df[FINAL_FEATURES].copy()

        # Match the notebook's final numerical cleanup.
        features = features.replace(
            [np.inf, -np.inf],
            np.nan,
        ).fillna(0)

        return features

    def predict_flow(self, flow: Mapping[str, Any]) -> dict[str, Any]:
        """Run binary Benign-vs-DDoS inference on one flow."""
        flow_df = pd.DataFrame([dict(flow)])
        features = self.build_features(flow_df)

        score = float(self.model.predict_proba(features)[0, 1])
        detected = score >= self.threshold

        return {
            "status": "DETECTED" if detected else "BENIGN",
            "threat_class": "DDoS" if detected else "Benign",
            "score_type": "model_score",
            "raw_score": score,
            "threshold": self.threshold,
            "evidence": {
                feature: float(features.iloc[0][feature])
                for feature in FINAL_FEATURES
            },
            "context": {
                "feature_count": len(FINAL_FEATURES),
            },
            "detector_name": "ddos",
            "detector_version": self.feature_schema.get(
                "version",
                "1.0",
            ),
            "model_name": "XGBoost",
            "model_version": self.feature_schema.get(
                "version",
                "1.0",
            ),
            "feature_schema": "spectra_ddos_feature_schema.json",
        }

    def predict_batch(
        self,
        flows: pd.DataFrame,
    ) -> list[dict[str, Any]]:
        """Run binary Benign-vs-DDoS inference on multiple flows."""
        features = self.build_features(flows)

        scores = self.model.predict_proba(features)[:, 1]
        predictions = scores >= self.threshold

        results: list[dict[str, Any]] = []

        for idx, (score, detected) in enumerate(
            zip(scores, predictions)
        ):
            results.append(
                {
                    "status": (
                        "DETECTED" if detected else "BENIGN"
                    ),
                    "threat_class": (
                        "DDoS" if detected else "Benign"
                    ),
                    "score_type": "model_score",
                    "raw_score": float(score),
                    "threshold": self.threshold,
                    "evidence": {
                        feature: float(features.iloc[idx][feature])
                        for feature in FINAL_FEATURES
                    },
                    "context": {
                        "feature_count": len(FINAL_FEATURES),
                    },
                    "detector_name": "ddos",
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
                        "spectra_ddos_feature_schema.json"
                    ),
                }
            )

        return results


# Convenience instance for simple integration:
#     from ddos_detector import detector
#     result = detector.predict_flow(flow)
detector = DDoSDetector()
