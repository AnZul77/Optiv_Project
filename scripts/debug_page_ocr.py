import json
import os

with open('data/outputs/ocr_cache_policy_v6.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

print("=== Page 2 Items ===")
p2 = data.get('2', {}).get('items', [])
for it in p2:
    y = it['bbox'][0][1]
    x = it['bbox'][0][0]
    if 800 <= y <= 1100:
        print(f"y={y:.1f}, x={x:.1f}: {it['text']}")

print("\n=== Page 25 Items ===")
p25 = data.get('25', {}).get('items', [])
for it in p25:
    y = it['bbox'][0][1]
    x = it['bbox'][0][0]
    if 700 <= y <= 1100:
        print(f"y={y:.1f}, x={x:.1f}: {it['text']}")
