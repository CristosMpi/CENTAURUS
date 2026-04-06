from __future__ import annotations

import math
from typing import Iterable

import numpy as np
from scipy.fft import rfft, rfftfreq


def zero_crossing_rate(waveform: np.ndarray) -> float:
    signs = np.sign(waveform)
    return float(np.mean(np.abs(np.diff(signs)) > 0))


def spectral_centroid(waveform: np.ndarray, sample_rate: int) -> float:
    magnitude = np.abs(rfft(waveform))
    freqs = rfftfreq(len(waveform), d=1.0 / sample_rate)
    denom = np.sum(magnitude) + 1e-9
    return float(np.sum(freqs * magnitude) / denom)


def spectral_bandwidth(waveform: np.ndarray, sample_rate: int, centroid: float) -> float:
    magnitude = np.abs(rfft(waveform))
    freqs = rfftfreq(len(waveform), d=1.0 / sample_rate)
    denom = np.sum(magnitude) + 1e-9
    return float(np.sqrt(np.sum(((freqs - centroid) ** 2) * magnitude) / denom))


def rms_energy(waveform: np.ndarray) -> float:
    return float(np.sqrt(np.mean(np.square(waveform)) + 1e-9))


def peak_amplitude(waveform: np.ndarray) -> float:
    return float(np.max(np.abs(waveform)))


def dominant_frequency(waveform: np.ndarray, sample_rate: int) -> float:
    magnitude = np.abs(rfft(waveform))
    freqs = rfftfreq(len(waveform), d=1.0 / sample_rate)
    return float(freqs[int(np.argmax(magnitude))])


def short_term_energy_variance(waveform: np.ndarray, frame_size: int = 1024) -> float:
    if len(waveform) < frame_size:
        return 0.0
    frames = len(waveform) // frame_size
    trimmed = waveform[: frames * frame_size].reshape(frames, frame_size)
    energies = np.mean(np.square(trimmed), axis=1)
    return float(np.var(energies))


def extract_feature_vector(samples: Iterable[float], sample_rate: int) -> np.ndarray:
    waveform = np.asarray(list(samples), dtype=np.float32)
    if waveform.size == 0:
        raise ValueError("waveform is empty")
    max_abs = np.max(np.abs(waveform)) + 1e-9
    waveform = waveform / max_abs
    centroid = spectral_centroid(waveform, sample_rate)
    bandwidth = spectral_bandwidth(waveform, sample_rate, centroid)
    return np.asarray(
        [
            rms_energy(waveform),
            peak_amplitude(waveform),
            zero_crossing_rate(waveform),
            centroid,
            bandwidth,
            dominant_frequency(waveform, sample_rate),
            short_term_energy_variance(waveform),
            float(len(waveform)) / float(sample_rate),
        ],
        dtype=np.float32,
    )


def feature_names() -> list[str]:
    return [
        "rms_energy",
        "peak_amplitude",
        "zero_crossing_rate",
        "spectral_centroid",
        "spectral_bandwidth",
        "dominant_frequency",
        "energy_variance",
        "duration_seconds",
    ]
