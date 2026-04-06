from __future__ import annotations

import argparse
import csv
from pathlib import Path

import joblib
import numpy as np
import soundfile as sf
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app_audio_ml.features import extract_feature_vector, feature_names


def load_manifest(manifest_path: Path) -> tuple[np.ndarray, np.ndarray]:
    rows = []
    labels = []
    with manifest_path.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            wav_path = (manifest_path.parent / row["file_path"]).resolve()
            samples, sample_rate = sf.read(wav_path)
            if samples.ndim > 1:
                samples = samples.mean(axis=1)
            rows.append(extract_feature_vector(samples, int(sample_rate)))
            labels.append(row["label"])
    return np.asarray(rows, dtype=np.float32), np.asarray(labels)


def train(manifest_path: Path, output_path: Path) -> None:
    X, y = load_manifest(manifest_path)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    labels = sorted(set(y.tolist()))
    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "clf",
                RandomForestClassifier(
                    n_estimators=300,
                    max_depth=16,
                    random_state=42,
                    class_weight="balanced",
                ),
            ),
        ]
    )
    pipeline.fit(X_train, y_train)
    predictions = pipeline.predict(X_test)
    print(classification_report(y_test, predictions, digits=4))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "pipeline": pipeline,
        "labels": labels,
        "feature_names": feature_names(),
    }
    joblib.dump(artifact, output_path)
    print(f"Saved model to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train CENTAURUS audio classifier")
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="CSV manifest with file_path,label columns",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("models/audio_event_classifier.joblib"),
    )
    args = parser.parse_args()
    train(args.manifest, args.output)
