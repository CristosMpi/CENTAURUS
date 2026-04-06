# Audio Dataset Layout

Store labeled WAV files here, grouped however you like.

Use a CSV manifest with these columns:

```csv
file_path,label
train/digging_001.wav,digging
train/metal_hit_001.wav,metal_hit
train/drilling_001.wav,drilling
train/background_001.wav,background
```

Recommended classes:
- digging
- metal_hit
- drilling
- background

Recommended recording tips:
- mono WAV
- 16 kHz or 22.05 kHz
- 1 to 4 seconds per clip
- collect different tools, surfaces, and distances
