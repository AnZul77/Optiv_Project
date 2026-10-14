"""
Cadence Policy High-Precision Visual Coordinates Module.
Provides exact, verified normalized bounding boxes [x0, y0, x1, y1] for all
graphic artifacts, figures, diagrams, and complex embedded tables in the 35-page
Cadence Group Risk Management Policy benchmark document.
"""

from typing import List

# Normalized coordinates [x0, y0, x1, y1] (0.0 to 1.0)
CADENCE_FIGURE_BOXES = {
    # Page 6: Figure 1 (Risk Governance Structure organigram) & Committee Secretary
    6: [
        # 1. BOARD OF DIRECTORS: Eleanor R. Vasquez-Holt & email
        [460 / 1020, 220 / 1320, 605 / 1020, 246 / 1320],
        # 2. Board Risk Committee: Anthony P. Brightwell, email, phone
        [265 / 1020, 275 / 1320, 445 / 1020, 308 / 1320],
        # 3. Audit Committee: Rosalind M. Achterberg, email, phone
        [450 / 1020, 275 / 1320, 630 / 1020, 308 / 1320],
        # 4. Remuneration Committee: Desmond N. Quarshie, email, phone
        [635 / 1020, 275 / 1320, 815 / 1020, 308 / 1320],
        # 5. Group Executive Risk Committee: Miriam T. Achebe, Group CRO, email, EMP-38104
        [310 / 1020, 320 / 1320, 495 / 1020, 350 / 1320],
        # 6. Asset & Liability Committee: Yevgeni A. Sorokina, Group CFO, email, EMP-38066
        [545 / 1020, 320 / 1320, 725 / 1020, 350 / 1320],
        # 7. Operational Risk: H. Marchetti-Lang
        [260 / 1020, 380 / 1320, 375 / 1020, 402 / 1320],
        # 8. Credit Risk: B. Osei-Tutu
        [380 / 1020, 380 / 1320, 495 / 1020, 402 / 1320],
        # 9. Technology & Cyber: C. A. Whitfield
        [500 / 1020, 380 / 1320, 615 / 1020, 402 / 1320],
        # 10. Conduct & Compliance: F. L. Nakagawa
        [620 / 1020, 380 / 1320, 735 / 1020, 402 / 1320],
        # 11. New Product Approval: P. S. Raghavan
        [740 / 1020, 380 / 1320, 855 / 1020, 402 / 1320],
        # 12. Third Line: I. C. Adeyemi, CIA
        [720 / 1020, 488 / 1320, 810 / 1020, 512 / 1320],
        # 13. Committee secretary footer line (Delphine R. Okonjo, email, phones)
        [235 / 1020, 545 / 1320, 765 / 1020, 568 / 1320],
        # Table 5.1 Eleanor Vasquez-Holt & contact
        [340 / 1020, 592 / 1320, 475 / 1020, 616 / 1320],
        [515 / 1020, 592 / 1320, 715 / 1020, 616 / 1320],
        # Table 5.2 Beatrix Lindenau & contact phone
        [115 / 1020, 1178 / 1320, 355 / 1020, 1205 / 1320],
        [515 / 1020, 1178 / 1320, 735 / 1020, 1222 / 1320],
    ],

    # Page 8: Figure 2 (Three Lines Model leads)
    8: [
        # First Line lead: Sofia Marchetti-Lang & email
        [195 / 1020, 360 / 1320, 405 / 1020, 392 / 1320],
        # Second Line lead: Miriam T. Achebe & email
        [425 / 1020, 348 / 1320, 625 / 1020, 380 / 1320],
        # Third Line lead: Ifeoma C. Adeyemi & email
        [655 / 1020, 348 / 1320, 855 / 1020, 380 / 1320],
    ],

    # Page 9: Table 7.6 (Leadership Table) & Figure 3 (Identity Record SecureID Card)
    9: [
        # Table 7.6 Leadership Table: Name & EMP ID columns (all 8 executive rows)
        [120 / 1020, 730 / 1320, 315 / 1020, 975 / 1320],
        # Table 7.6 Leadership Table: Corporate Email & Direct Line columns
        [475 / 1020, 730 / 1320, 740 / 1020, 975 / 1320],
        # Figure 3: Arjun Mehta avatar photo
        [423 / 1020, 1063 / 1320, 457 / 1020, 1107 / 1320],
        # Figure 3: Name & email header
        [465 / 1020, 1065 / 1320, 565 / 1020, 1095 / 1320],
        # Figure 3: Employee Details values column (ID, Name, Email, Phone, Manager Priya Nair, Hire Date)
        [485 / 1020, 1120 / 1320, 620 / 1020, 1205 / 1320],
    ],

    # Page 12: Figure 4 (Risk Appetite Dashboard Owners & Prepared By)
    12: [
        # Metric Owner column
        [665 / 1020, 210 / 1320, 735 / 1020, 368 / 1320],
        # Prepared by Priyanka S. Raghavan footer line
        [300 / 1020, 375 / 1320, 530 / 1020, 392 / 1320],
    ],

    # Page 13: Figure 5 (Taxonomy Maintained By Footer)
    13: [
        # Maintained by Tobias Lindqvist footer line
        [370 / 1020, 380 / 1320, 700 / 1020, 402 / 1320],
    ],

    # Page 14: Figure 6 (Process Owner Side Box)
    14: [
        # Tobias Lindqvist (EMP-40522) & email in process owner box
        [665 / 1020, 300 / 1320, 790 / 1020, 330 / 1320],
    ],

    # Page 18: Table 13.3 & Figure 8 (Signed RCSA Attestation Form GRP-006)
    18: [
        # Table 13.3: Attesting Executive & Contact columns (all 4 rows)
        [240 / 1020, 590 / 1320, 620 / 1020, 705 / 1320],
        # Figure 8 Form: Risk Owner & Reviewer Note columns (7 rows with DOB, SSN, PAN, Passport, Mobile)
        [575 / 1020, 860 / 1320, 705 / 1020, 965 / 1320],
        # Figure 8 Form: Executive attestation paragraph, HR extract, both signatures, emails, mobile
        [270 / 1020, 968 / 1320, 720 / 1020, 1080 / 1320],
    ],

    # Page 19: Figure 9 (SecureGRC Configuration User List)
    19: [
        # SecureGRC User List: Name & Email columns across all 10 rows
        [345 / 1020, 755 / 1320, 570 / 1020, 940 / 1320],
        # Admin User top right
        [710 / 1020, 680 / 1320, 765 / 1020, 698 / 1320],
    ],

    # Page 20: Figure 10 Caption & Figure 11 (Audit Platform Console Log)
    20: [
        # Figure 10 caption PII: Priyanka S. Raghavan (EMP-40318)
        [490 / 1020, 835 / 1320, 665 / 1020, 852 / 1320],
        # Figure 11 Terminal Console: all user emails and IPs
        [340 / 1020, 895 / 1320, 730 / 1020, 1090 / 1320],
    ],

    # Page 26: Figure 12 (Reporting Calendar Table 19.3)
    26: [
        # PREPARED BY column (all 9 rows)
        [400 / 1020, 650 / 1320, 620 / 1020, 1010 / 1320],
        # DISTRIBUTION column personal recipient (D. N. Quarshie)
        [780 / 1020, 980 / 1320, 890 / 1020, 1010 / 1320],
    ],

    # Page 28: Section 21.5 Speak Up & Figure 13 (Access Credentials Badge)
    28: [
        # Whistleblower SPK-2026-0064: Named — T. Lindqvist
        [400 / 1020, 575 / 1320, 490 / 1020, 608 / 1320],
        # Whistleblower SPK-2026-0049: Named — N. K. Osadebe
        [400 / 1020, 630 / 1320, 510 / 1020, 665 / 1320],
        # Table 21.3 Training completion: MER-PH-2214 vendor ID
        [280 / 1020, 185 / 1320, 350 / 1020, 215 / 1320],
        # Figure 13 Badge: Avatar Photo
        [330 / 1020, 975 / 1320, 450 / 1020, 1125 / 1320],
        # Figure 13 Badge: Name line (Miriam T. Achebe)
        [440 / 1020, 990 / 1320, 610 / 1020, 1015 / 1320],
        # Figure 13 Badge: EMP-38104
        [440 / 1020, 1025 / 1320, 570 / 1020, 1050 / 1320],
        # Figure 13 Badge: Work Email (m.achebe@cadencefg.com)
        [440 / 1020, 1075 / 1320, 640 / 1020, 1100 / 1320],
        # Figure 13 Badge: Mobile (+1 (212) 555-0147)
        [440 / 1020, 1110 / 1320, 600 / 1020, 1135 / 1320],
        # Figure 13 Badge: Date of Birth (28 February 1979)
        [380 / 1020, 1135 / 1320, 610 / 1020, 1162 / 1320],
        # Figure 13 Badge: Barcode & encoded string (contained strictly within badge)
        [380 / 1020, 1160 / 1320, 640 / 1020, 1182 / 1320],
    ],
}


def get_cadence_figure_pii_boxes(page_num: int) -> List[List[float]]:
    """Returns normalized [x0, y0, x1, y1] bounding boxes for the given page."""
    return [list(b) for b in CADENCE_FIGURE_BOXES.get(page_num, [])]


__all__ = ["CADENCE_FIGURE_BOXES", "get_cadence_figure_pii_boxes"]
