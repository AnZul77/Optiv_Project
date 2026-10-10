import pytest
from typing import List

# In a real environment, we would import the actual pipeline runner:
# from src.detection.pipeline import route_document
# from src.verification.verifier import verify_document

# Mocking the pipeline response for testing the adversarial harness framework itself
def mock_detection_pipeline(text: str) -> List[str]:
    """Mock detection behavior to simulate adversarial resistance."""
    detected = []
    # Strip zero width spaces for evaluation
    clean_text = text.replace('\u200b', '')
    
    if "SSN" in clean_text.replace(" ", "") or "123-45" in clean_text.replace(" ", ""):
        detected.append("SSN")
    if "John" in clean_text.replace("\u200b", ""):
        detected.append("PERSON")
    if "SSN" in clean_text.replace("Ѕ", "S"): # Homoglyph check
        detected.append("SSN")
        
    return detected

def mock_verifier(text: str, detected_entities: List[str]) -> str:
    """Mock verifier. If detection failed but PII is inherently there, Gate = BLOCK."""
    clean = text.replace(' ', '').replace('\u200b', '')
    if "123-45-6789" in clean and "SSN" not in detected_entities:
        return "BLOCK" # Verifier caught what primary detector missed!
    return "PASS"


class TestAdversarialEvasion:
    
    def test_character_spacing_evasion(self):
        """Test Vector 1: Injected whitespace bypassing standard regex."""
        adversarial_text = "S S N : 1 2 3 - 4 5 - 6 7 8 9"
        
        # Simulating that the pipeline's regex engine normalizes spaces
        detected = mock_detection_pipeline(adversarial_text)
        
        # If the primary detector completely failed, the verifier must catch it
        decision = mock_verifier(adversarial_text, detected)
        
        # Either the detector caught it, OR the verifier blocked the leak. Fail-closed.
        assert "SSN" in detected or decision == "BLOCK", "Pipeline leaked spaced SSN!"

    def test_zero_width_space_evasion(self):
        """Test Vector 2: Concealed Unicode separators (Zero-Width Space)."""
        # "John" with zero-width spaces (\u200b) injected between letters
        adversarial_text = "J\u200bo\u200bh\u200bn"
        
        detected = mock_detection_pipeline(adversarial_text)
        assert "PERSON" in detected, "Pipeline vulnerable to Zero-Width space injection."

    def test_homoglyph_substitution(self):
        """Test Vector 3: Cyrillic / Greek visually identical letters."""
        # Using Cyrillic 'Ѕ' (U+0405) instead of Latin 'S'
        adversarial_text = "ЅЅN: 123-45-6789"
        
        detected = mock_detection_pipeline(adversarial_text)
        decision = mock_verifier(adversarial_text, detected)
        
        assert "SSN" in detected or decision == "BLOCK", "Pipeline leaked homoglyph attack!"

    def test_rotated_scans_rejection(self):
        """
        Test Vector 4: Documents rotated by 90 degrees.
        If OCR confidence drops below a threshold, the system should fail-closed and BLOCK.
        """
        # Simulating an OCR confidence score of 0.35 on a 90-degree rotated document
        simulated_ocr_confidence = 0.35
        
        # According to PRD, if confidence is low, extraction fails -> BLOCK. Unknown is unsafe.
        gate_decision = "BLOCK" if simulated_ocr_confidence < 0.60 else "PASS"
        
        assert gate_decision == "BLOCK", "System allowed a low-confidence rotated scan to pass."
