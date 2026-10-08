# Developer 2: OCR Engine & Image Redaction Architecture Guide

**Role:** Person 2 — OCR & Vision Lead  
**Domain:** Optical Character Recognition, Image Preprocessing, Bounding-Box Coordinate Tracking, True Pixel Redaction, and Re-OCR Verification  
**Key Modules:** `src/ocr/engine.py`, `src/ocr/preprocess.py`, `src/ocr/regions.py`, `src/ocr/confidence.py`, `src/sanitization/image_redactor.py`, `src/sanitization/pdf_redactor.py`  

---

## 1. Role Purpose & Core Security Mandate

Developer 2 is responsible for the **visual intelligence and physical sanitization** layer of the PII Security Firewall. 

In this system:
1. **OCR-First Philosophy**: OCR is **not** a fallback. Every scanned page, embedded screenshot, and image is treated as potentially containing visual PII (e.g., OneTrust access dashboards, org charts, scanned ID forms, handwritten signatures).
2. **True Pixel Burning**: Text redaction in visual assets cannot be implemented as decorative transparent overlay boxes or PDF annotations that an attacker can unlayer. Sensitive areas must have their underlying RGB/grayscale pixel values permanently overwritten with solid black opaque blocks.
3. **Low-Confidence Fail-Closed Signaling**: If image quality is poor, blurry, or low-contrast such that OCR character confidence drops below threshold ($\le 0.60$), Developer 2's module must flag the region as a high-risk security event to trigger the fail-closed gate.

---

## 2. Directory & Module Specifications

```
src/
├── ocr/
│   ├── __init__.py           # Package exports
│   ├── engine.py             # Unified OCR adapter (PaddleOCR / EasyOCR / PyTesseract)
│   ├── preprocess.py         # Image contrast enhancement, binarization, deskewing
│   ├── regions.py            # Bounding box generation & coordinate normalization
│   └── confidence.py         # Word/character confidence scoring & low-confidence flagging
└── sanitization/
    ├── image_redactor.py     # True pixel burning on standalone/embedded images (Pillow/OpenCV)
    └── pdf_redactor.py       # Burned opaque redactions directly into scanned PDF pages
```

---

## 3. Detailed Component Technical Requirements

### 3.1 OCR Preprocessing Engine (`src/ocr/preprocess.py`)
- **Input:** Raw image bytes or PIL Image / OpenCV ndarray.
- **Tasks:**
  - **DPI Upscaling & Rescaling**: Standardize inputs to **220 DPI** (matching the 35-page scanned Risk Policy PDF standard).
  - **Adaptive Binarization / Otsu Thresholding**: Clean low-contrast scans and screenshot backgrounds.
  - **Deskewing**: Detect rotation skew ($-45^\circ$ to $+45^\circ$) via Hough line transforms and correct orientation.
  - **Denoising**: Apply median or bilateral filtering to eliminate JPEG compression artifacts in scanned pages.

### 3.2 OCR Adapter (`src/ocr/engine.py`)
- **Interface Contract**:
  ```python
  class OCREngineAdapter:
      def extract_text(self, image_input: Union[bytes, Image.Image, np.ndarray]) -> Dict[str, Any]:
          """
          Returns:
              {
                  "text": str,                      # Extracted aggregated text
                  "confidence": float,              # Mean confidence score [0.0 - 1.0]
                  "words": [                        # Word-level coordinates and scores
                      {
                          "word": "John",
                          "bbox": [x0, y0, x1, y1],  # Normalized [0.0 - 1.0] or pixel coords
                          "confidence": 0.98
                      }
                  ]
              }
          """
  ```
- **Engine Selection**: Benchmark PaddleOCR vs. EasyOCR on CPU/GPU. Ensure fallback handling if GPU is unavailable.

### 3.3 Coordinate Normalization & Regions (`src/ocr/regions.py`)
- Transform diverse coordinate outputs (e.g. 4-point polygon `[[x1,y1], [x2,y2], [x3,y3], [x4,y4]]`) into canonical `BoundingBox` `[x0, y0, x1, y1]`.
- Implement coordinate transformers that map between normalized page ratios (`[0.0, 1.0]`) and actual image pixel dimensions (`width`, `height`).

### 3.4 Confidence Engine (`src/ocr/confidence.py`)
- Calculate character-level and word-level certainty scores.
- Flag any region where confidence drops below safety threshold (e.g., $0.60$).
- Output metadata flags consumed by Developer 4's Fail-Closed Gate (`src/verification/gate.py`).

### 3.5 True Pixel Burning Redactor (`src/sanitization/image_redactor.py`)
- **Pixel Overwrite**: Permanently write solid opaque black pixels (`(0, 0, 0)`) over target bounding boxes with a safety margin (padding $+3$ to $+5$ pixels).
- **Embedded DOCX Image Replacement**: Replace the redacted image blob in the OpenXML relationship part without corrupting file structure.
- **Format Preservation**: Preserve original format and color profile without introducing visual degradation to non-redacted areas.

### 3.6 Scanned PDF Redactor (`src/sanitization/pdf_redactor.py`)
- For scanned PDFs (such as the 35-page Risk Policy PDF), permanently replace the page pixmap with the burned image version.
- Ensure no hidden vector text layer or original image streams remain in the PDF object tree.

---

## 4. Inputs Consumed from Developer 1

Developer 2 consumes objects produced by Developer 1 (`src/schema/document.py`):
1. **Scanned PDF Pages**: `ExtractedPage.images` where `metadata["rendered_page"] == True` (rendered at 220 DPI).
2. **Embedded Screenshots**: `doc.get_all_images()` where `is_screenshot == True`.
3. **Image Payloads**: `img.image_bytes` (raw bytes, format in `img.image_format`).

---

## 5. Outputs Produced for Other Developers

1. **For Developer 3 (PII Detection)**:
   - Provide `ExtractedPage.ocr_text` and word-level bounding boxes so Regex and Presidio NER can localize PII on images.
2. **For Developer 4 (Policy & Verification)**:
   - Provide `ExtractedPage.ocr_confidence` for fail-closed checks.
   - Provide `residual_scan.py` support: re-running OCR over sanitized output images to verify zero residual text.
3. **For Developer 5 (UI Dashboard)**:
   - Provide coordinate bounding boxes and before/after visual images for side-by-side Streamlit rendering.

---

## 6. Developer 2 Implementation Checklist

- [ ] Benchmark EasyOCR vs. PaddleOCR on CPU/GPU
- [ ] Implement image preprocessing pipeline (220-DPI scaling, binarization, deskew) in `src/ocr/preprocess.py`
- [ ] Implement unified OCR adapter in `src/ocr/engine.py`
- [ ] Implement coordinate normalization in `src/ocr/regions.py`
- [ ] Implement confidence scoring and low-confidence flagging in `src/ocr/confidence.py`
- [ ] Implement true pixel burning in `src/sanitization/image_redactor.py`
- [ ] Implement burned PDF page replacement in `src/sanitization/pdf_redactor.py`
- [ ] Implement re-OCR scanning routine for residual verification
- [ ] Write unit and integration tests in `tests/unit/test_ocr.py` and `tests/unit/test_redactor.py`
