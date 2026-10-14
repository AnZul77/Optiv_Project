"""
Evaluation Metrics & Matcher
Calculates bounding box overlaps and text span matches between 
ground truth and predicted entity annotations.
"""
from typing import List, Dict, Any, Tuple
import re
from src.schema.document import EntityAnnotation


def normalize_entity_type(etype: Any) -> str:
    """Normalize entity type representation across detectors and ground truth."""
    if hasattr(etype, "value"):
        etype = etype.value
    etype_str = str(etype).upper().replace("ENTITYTYPE.", "")
    type_aliases = {
        "PHONE_NUMBER": "PHONE",
        "NAME": "PERSON",
        "CREDIT_CARD": "CARD",
        "CREDIT_DEBIT_CARD": "CARD",
        "DATE_OF_BIRTH": "DOB",
        "LOCATION": "ADDRESS",
        "ORGANIZATION": "ORG",
        "EMPLOYEE_NUMBER": "EMPLOYEE_ID",
        "GOVT_ID": "SSN",
    }
    return type_aliases.get(etype_str, etype_str)


def calculate_iou_bbox(bbox1: List[float], bbox2: List[float]) -> float:
    """Calculate Intersection-over-Union (IoU) for two bounding boxes [x0, y0, x1, y1]."""
    x_left = max(bbox1[0], bbox2[0])
    y_top = max(bbox1[1], bbox2[1])
    x_right = min(bbox1[2], bbox2[2])
    y_bottom = min(bbox1[3], bbox2[3])

    if x_right < x_left or y_bottom < y_top:
        return 0.0

    intersection_area = (x_right - x_left) * (y_bottom - y_top)
    bbox1_area = (bbox1[2] - bbox1[0]) * (bbox1[3] - bbox1[1])
    bbox2_area = (bbox2[2] - bbox2[0]) * (bbox2[3] - bbox2[1])

    union_area = bbox1_area + bbox2_area - intersection_area
    if union_area <= 0:
        return 0.0

    return intersection_area / union_area


def calculate_iou_text(span1: Tuple[int, int], span2: Tuple[int, int]) -> float:
    """Calculate overlap ratio (IoU equivalent) for two 1D text spans [start, end]."""
    start1, end1 = span1
    start2, end2 = span2
    
    if end1 <= start1 or end2 <= start2:
        return 0.0

    intersection_start = max(start1, start2)
    intersection_end = min(end1, end2)

    if intersection_end < intersection_start:
        return 0.0

    intersection_length = intersection_end - intersection_start
    union_length = (end1 - start1) + (end2 - start2) - intersection_length
    
    if union_length <= 0:
        return 0.0
        
    return intersection_length / union_length


def _extract_raw_value(ann: Any) -> str:
    """Extract raw value snippet if present in context or attributes."""
    if hasattr(ann, "raw_value") and getattr(ann, "raw_value"):
        return str(getattr(ann, "raw_value"))
    if hasattr(ann, "context") and isinstance(ann.context, dict):
        if ann.context.get("raw_value"):
            return str(ann.context.get("raw_value"))
        if ann.context.get("value_snippet"):
            return str(ann.context.get("value_snippet"))
    return ""


def _clean_text_for_match(val: str) -> str:
    """Normalize text for fuzzy equivalence."""
    return re.sub(r"[\s\-_.,;:#*/\\]+", "", val).lower()


def match_entities(
    predicted: List[EntityAnnotation],
    ground_truth: List[EntityAnnotation],
    iou_threshold: float = 0.50
) -> Dict[str, Any]:
    """
    Evaluates predicted entities against ground truth.
    Supports multi-modal matching via:
      1. Direct salted hash equality
      2. Normalized text equality / substring containment
      3. Character span IoU
      4. Spatial bounding-box IoU
    Returns lists of True Positives, False Positives, and False Negatives.
    """
    tp = []
    fp = []
    fn = []
    
    gt_matched = set()
    
    for pred in predicted:
        matched = False
        pred_type = normalize_entity_type(pred.type)
        pred_raw = _extract_raw_value(pred)
        pred_clean = _clean_text_for_match(pred_raw) if pred_raw else ""

        for i, gt in enumerate(ground_truth):
            if i in gt_matched:
                continue
            
            gt_type = normalize_entity_type(gt.type)
            
            # Type matching: types must match, or either is generic "PII"
            if pred_type != gt_type and pred_type != "PII" and gt_type != "PII":
                continue

            gt_raw = _extract_raw_value(gt)
            gt_clean = _clean_text_for_match(gt_raw) if gt_raw else ""

            # Check Page Compatibility
            # Allow match if pages identical, or if either page is unassigned (0),
            # or if exact text matches and page drift is <= 2 (common in flowing DOCX)
            same_page = (pred.page == gt.page) or (pred.page <= 0) or (gt.page <= 0)
            text_exact_match = (
                (pred.value_hash and gt.value_hash and pred.value_hash == gt.value_hash) or
                (pred_clean and gt_clean and (pred_clean == gt_clean or pred_clean in gt_clean or gt_clean in pred_clean))
            )

            if not same_page and not (text_exact_match and abs(pred.page - gt.page) <= 2):
                continue

            # Condition 1: Exact Hash Match
            if pred.value_hash and gt.value_hash and pred.value_hash == gt.value_hash:
                tp.append(pred)
                gt_matched.add(i)
                matched = True
                break

            # Condition 2: Normalized Text Equivalence / Containment
            if text_exact_match:
                tp.append(pred)
                gt_matched.add(i)
                matched = True
                break

            # Condition 3: Text Span IoU (when offsets are non-zero)
            if pred.text_end > 0 and gt.text_end > 0 and same_page:
                text_iou = calculate_iou_text(
                    (pred.text_start, pred.text_end),
                    (gt.text_start, gt.text_end)
                )
                if text_iou >= iou_threshold:
                    tp.append(pred)
                    gt_matched.add(i)
                    matched = True
                    break

            # Condition 4: Bounding Box Overlap (when spatial coordinates are non-zero)
            if sum(pred.bbox) > 0 and sum(gt.bbox) > 0 and same_page:
                bbox_iou = calculate_iou_bbox(pred.bbox, gt.bbox)
                if bbox_iou >= iou_threshold:
                    tp.append(pred)
                    gt_matched.add(i)
                    matched = True
                    break
        
        if not matched:
            fp.append(pred)
            
    # Any ground truth not matched is a False Negative
    for i, gt in enumerate(ground_truth):
        if i not in gt_matched:
            fn.append(gt)
            
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "counts": {
            "TP": len(tp),
            "FP": len(fp),
            "FN": len(fn)
        }
    }
