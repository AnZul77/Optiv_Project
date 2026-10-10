"""
Evaluation Metrics & Matcher
Calculates bounding box overlaps and text span matches between 
ground truth and predicted entity annotations.
"""
from typing import List, Dict, Any, Tuple
from src.schema.document import EntityAnnotation

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
    if union_area == 0:
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
    
    if union_length == 0:
        return 0.0
        
    return intersection_length / union_length

def match_entities(predicted: List[EntityAnnotation], ground_truth: List[EntityAnnotation], iou_threshold: float = 0.50) -> Dict[str, Any]:
    """
    Evaluates predicted entities against ground truth.
    Returns lists of True Positives, False Positives, and False Negatives.
    """
    tp = []
    fp = []
    fn = []
    
    gt_matched = set()
    
    for pred in predicted:
        matched = False
        for i, gt in enumerate(ground_truth):
            if i in gt_matched:
                continue
            
            # Must be on the same page and same PII type
            if pred.page != gt.page or pred.type != gt.type:
                continue
                
            # Check Text Overlap if text offsets exist
            if pred.text_end > 0 and gt.text_end > 0:
                text_iou = calculate_iou_text((pred.text_start, pred.text_end), (gt.text_start, gt.text_end))
                if text_iou >= iou_threshold:
                    tp.append(pred)
                    gt_matched.add(i)
                    matched = True
                    break
                    
            # Fallback to Bounding Box Overlap if no text offsets but bboxes exist
            elif sum(pred.bbox) > 0 and sum(gt.bbox) > 0:
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
