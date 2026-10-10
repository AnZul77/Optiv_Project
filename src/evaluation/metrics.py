"""
Evaluation Metrics Calculator
Computes Precision, Recall, F1, Leak Rate, and Over-Redaction Rate.
"""
from typing import List, Dict, Any
from src.schema.document import EntityAnnotation
from src.evaluation.matcher import match_entities

def calculate_precision(tp: int, fp: int) -> float:
    if tp + fp == 0:
        return 0.0
    return tp / (tp + fp)

def calculate_recall(tp: int, fn: int) -> float:
    if tp + fn == 0:
        return 0.0
    return tp / (tp + fn)

def calculate_f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return 2 * (precision * recall) / (precision + recall)

def calculate_document_leak_rate(document_results: List[Dict[str, Any]]) -> float:
    """
    A document is leaked if even a single ground-truth PII entity was not caught (FN > 0).
    Zero Tolerance Target: 0.0
    """
    if not document_results:
        return 0.0
        
    leaked_docs = 0
    for res in document_results:
        if res["counts"]["FN"] > 0:
            leaked_docs += 1
            
    return leaked_docs / len(document_results)

def calculate_over_redaction_rate(tp: int, fp: int) -> float:
    """
    Over-redaction rate = False Positives / Total Redactions (TP + FP)
    Target: < 10%
    """
    total_redactions = tp + fp
    if total_redactions == 0:
        return 0.0
    return fp / total_redactions

def generate_report(predicted_docs: List[List[EntityAnnotation]], ground_truth_docs: List[List[EntityAnnotation]]) -> Dict[str, Any]:
    """Generates full evaluation metrics across a benchmark dataset of documents."""
    if len(predicted_docs) != len(ground_truth_docs):
        raise ValueError("Number of predicted documents must match ground truth documents.")
        
    doc_results = []
    total_tp = 0
    total_fp = 0
    total_fn = 0
    
    # Critical and High risk specific tracking per PRD schema definitions
    critical_types = {"SSN", "PAN", "PASSPORT", "AADHAAR", "NINO"}
    high_types = {"EMAIL", "PHONE", "PERSON", "ADDRESS", "CARD", "BANK_ACCOUNT", "IFSC", "GST", "UPI"}
    
    crit_tp = 0
    crit_fn = 0
    high_tp = 0
    high_fn = 0
    
    for preds, gts in zip(predicted_docs, ground_truth_docs):
        match_result = match_entities(preds, gts)
        doc_results.append(match_result)
        
        total_tp += match_result["counts"]["TP"]
        total_fp += match_result["counts"]["FP"]
        total_fn += match_result["counts"]["FN"]
        
        for tp_ent in match_result["TP"]:
            if tp_ent.type in critical_types: crit_tp += 1
            elif tp_ent.type in high_types: high_tp += 1
            
        for fn_ent in match_result["FN"]:
            if fn_ent.type in critical_types: crit_fn += 1
            elif fn_ent.type in high_types: high_fn += 1

    precision = calculate_precision(total_tp, total_fp)
    recall = calculate_recall(total_tp, total_fn)
    f1 = calculate_f1(precision, recall)
    
    crit_recall = calculate_recall(crit_tp, crit_fn)
    high_recall = calculate_recall(high_tp, high_fn)
    
    leak_rate = calculate_document_leak_rate(doc_results)
    over_redaction = calculate_over_redaction_rate(total_tp, total_fp)
    
    return {
        "Overall_Recall": recall,
        "Critical_PII_Recall": crit_recall,
        "High_Risk_PII_Recall": high_recall,
        "Precision": precision,
        "F1_Score": f1,
        "Document_Leak_Rate": leak_rate,
        "Over_Redaction_Rate": over_redaction,
        "Total_TP": total_tp,
        "Total_FP": total_fp,
        "Total_FN": total_fn
    }
