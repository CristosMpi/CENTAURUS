# Trained Model Artifacts

This directory stores trained audio models such as:
- `audio_event_classifier.joblib`

Training command:

```bash
pip install -r requirements-ml.txt
python scripts/train_audio_model.py --manifest data/audio_dataset/manifest_example.csv --output models/audio_event_classifier.joblib
```

Then serve the inference API:

```bash
uvicorn app_audio_ml.main:app --reload
```
