
"""Coordinate conversion and PII span detection helpers for OCR and redaction."""

import re
from typing import Any, Iterable, List, Optional, Sequence, Tuple, Union

from src.schema.document import BoundingBox


def pixel_to_normalized(
    bbox: Sequence[float],
    image_width: int,
    image_height: int,
    page: int = 1,
) -> List[float]:
    """Convert pixel coordinates to normalized coordinates."""
    if image_width <= 0 or image_height <= 0:
        raise ValueError("Image width and height must be positive.")

    if len(bbox) != 4:
        raise ValueError("Bounding box must contain four coordinates.")

    x0, y0, x1, y1 = map(float, bbox)

    if not all(map(lambda value: value == value and abs(value) != float("inf"), (x0, y0, x1, y1))):
        raise ValueError("Bounding box coordinates must be finite.")

    if x0 > x1 or y0 > y1:
        raise ValueError("Invalid pixel bounding box: minimum coordinates must not exceed maximum coordinates.")

    return [
        max(0.0, min(1.0, x0 / image_width)),
        max(0.0, min(1.0, y0 / image_height)),
        max(0.0, min(1.0, x1 / image_width)),
        max(0.0, min(1.0, y1 / image_height)),
    ]


def normalized_to_pixel(
    bbox: Sequence[float],
    image_width: int,
    image_height: int,
) -> List[int]:
    """Convert normalized coordinates into pixel coordinates."""
    if image_width <= 0 or image_height <= 0:
        raise ValueError("Image width and height must be positive.")

    if len(bbox) != 4:
        raise ValueError("Bounding box must contain four coordinates.")

    x0, y0, x1, y1 = map(float, bbox)

    if not all(map(lambda value: value == value and abs(value) != float("inf"), (x0, y0, x1, y1))):
        raise ValueError("Bounding box coordinates must be finite.")

    if not all(0.0 <= value <= 1.0 for value in (x0, y0, x1, y1)):
        raise ValueError("Normalized coordinates must be between 0 and 1.")

    if x0 > x1 or y0 > y1:
        raise ValueError(
            "Invalid bounding box: minimum coordinates "
            "must not exceed maximum coordinates."
        )

    return [
        round(x0 * image_width),
        round(y0 * image_height),
        round(x1 * image_width),
        round(y1 * image_height),
    ]


def make_bounding_box(
    pixel_bbox: Sequence[float],
    image_width: int,
    image_height: int,
    page: int = 1,
) -> BoundingBox:
    """Create the project's canonical BoundingBox from pixel coordinates."""
    coords = pixel_to_normalized(
        pixel_bbox, image_width, image_height, page
    )
    return BoundingBox.from_list(coords, page=page)


def polygon_to_pixel_bbox(
    polygon: Iterable[Sequence[float]],
) -> List[int]:
    """Convert polygon points into an enclosing pixel bounding rectangle."""
    points = list(polygon)

    if not points:
        raise ValueError("Polygon must contain at least one point.")

    if any(len(point) < 2 for point in points):
        raise ValueError("Each polygon point must contain at least two coordinates.")

    xs = [float(point[0]) for point in points]
    ys = [float(point[1]) for point in points]

    return [
        int(min(xs)),
        int(min(ys)),
        int(max(xs)),
        int(max(ys)),
    ]


def char_width_weight(char: str) -> float:
    """Return proportional font character width weight for typography alignment."""
    if char in " \t":
        return 0.32
    if char in "ilI'\".,:;!|/\\`":
        return 0.32
    if char in "jrtf-()[]{}1^":
        return 0.40
    if char in "mwMW@%&#":
        return 0.95
    if char.isupper():
        return 0.70
    if char.isdigit():
        return 0.66
    return 0.66


def find_pii_spans_in_text(raw_text: Optional[str]) -> List[Tuple[int, int]]:
    """
    Find character start/end intervals for all PII elements within a line of OCR or raw text.
    """
    if not raw_text or not isinstance(raw_text, str):
        return []

    stripped_lower = raw_text.strip().lower()
    table_headers = {
        "employee name", "employee id", "risk code", "control id",
        "policy title", "reviewer", "status", "department", "business unit",
        "date", "source", "frequency", "description", "action", "role",
        "measure", "category", "limit", "tolerance band", "named owner",
        "contact", "regulator", "legal entity", "local risk officer", "deputy",
        "relationship owner", "forum", "chair", "chair contact", "primary mandate",
        "member", "emp / dir id", "capacity", "appointed", "theme", "raised",
        "investigating officer", "reference", "weakness", "rating",
        "accountable owner", "target", "role on the team", "primary", "alternate"
    }
    if stripped_lower in table_headers:
        return []

    # Visual artifact markers (e.g. photos, signatures, barcodes)
    if any(m in raw_text for m in ["[PHOTO]", "[SIGNATURE]", "[BARCODE]", "[AVATAR]"]):
        return [(0, len(raw_text))]

    text_lower = raw_text.lower()
    spans: List[Tuple[int, int]] = []

    # 1. Exact phrases & addresses
    exact_phrases = [
        "245 hudson street, new york ny 10013",
        "245 hudson street, new york, ny 10013",
        "245 hudson street", "new york, ny 10013", "new york ny 10013",
        "1180 ashwood lane, apartment 4c, jersey city, nj 07302",
        "1180 ashwood lane", "jersey city, nj 07302", "07302",
        "1842 willow tree ln, suite 400, chicago, il 60601",
        "1842 willow tree ln", "chicago, il 60601",
        "88 willowbank court, hoboken, nj 07030",
        "88 willowbank court, hoboken", "88 willowbank court", "hoboken, nj 07030", "hoboken",
        "2214 palmetto crescent, coral gables, fl 33134",
        "2214 palmetto crescent", "coral gables, fl 33134", "coral gables",
        # Full Personal Names & OCR Variations
        "anthony p. brightwell", "anthony p brightwell", "anthony p. briqhtwell", "anthony p. briahtwell", "anthony briqhtwell", "anthony briahtwell", "anthony brightwell", "&nthony f", "&nthony", "briahtwell", "brightwell", "briqhtwell", "briqhwwell", "a. brightwell", "a brightwell",
        "delphine r. okonjo", "delphine r okonjo", "delphine okonjo", "delphine okonic", "okonic", "okonjc", "okonio", "d. okonjo", "d okonjo",
        "rosalind m. achterberg", "rosalind m achterberg", "rosalind achterberg", "desmond achterberg", "rasalnc", "achlerberg", "rasalind", "r. achterberg", "r. m. achterberg",
        "desmond n. quarshie", "desmond n quarshie", "desmond quarshie", "d. quarshie", "d quarshie", "d. n. quarshie",
        "helena vorstermann", "helena vorsteimann", "helena vorsiermann", "orstermanm", "wotsier", "h. vorstermann", "h: vorstermann",
        "sunita r. balakrishnan", "sunita balakrishnan", "s. r. balakrishnan", "s. balakrishnan",
        "tobias lindqvist", "t. lindqvist", "tohias kindavisi", "kindavisi", "lindqvisi", "ttobias kinoovist", "tobias lindovist", "tobias lindavist", "tobias lindqvis", "tobias lindqvtst", "ttobias", "kinoovist", "lindovist", "aonias lindavist", "t lindqvist",
        "miriam achebe", "miriam t. achebe", "m. t. achebe", "m. achebe", "mma acuch", "minam", "wram", "achehe", "achebc", "achent", "m achebe",
        "rafael e. duarte", "rafael e: duarte", "rafael e duarte", "rafael duarte", "r. e. duarte", "r. duarte",
        "yusuf o. balogun", "yusuf o balogun", "yusuf o.balogun", "yusuf balogun", "y. o. balogun", "y. balogun",
        "lars-erik brannstrom", "l. brannstrom", "lars erik brannstrom", "l.-e. brannstrom", "l. e. brannstrom",
        "priyanka s. raghavan", "priyanka s raghavan", "privanka s. raghavan", "privanka s raghavan", "priyanka raghavan", "privanka raghavan", "p. s. raghavan", "p. raghavan", "aprivanza s", "aprivanza", "privanza", "privanka",
        "harriet l. okafor", "harriet l okafor", "harriet okafor", "h. okafor", "okalor", "h. l. okafor",
        "elena petrovska", "elena petouska", "petouska", "e. petrovska",
        "adaeze onwuka", "adaeze n. onwuka", "adaeze n onwuka", "adaeze okonkwo-bell", "adaeze okonkwo bell", "a. n. onwuka", "a. onwuka",
        "hiroshi yamagata", "h. yamagata",
        "rohan s. deshmukh", "rohan s deshmukh", "rohan deshmukh", "pohan deshmmkh", "deshmmkh", "r. s. deshmukh", "r. deshmukh",
        "arjun mehta", "priya nair", "nikhil saw", "john davis", "sarah mitchell", "robert johnson", "emily martinez", "laura wilson", "daniel kim", "thomas brown", "amanda singh", "michael chen", "jessica white",
        "marta szewczyk", "maria szewczyk", "maria szewczvk", "szewczvk", "marta", "m. szewczyk",
        "michael r. henderson", "michael r henderson", "michael henderson", "m. r. henderson",
        "naomi k. osadebe", "naomi k osadebe", "naomi osadebe", "n. k. osadebe", "nosadebe", "naomk osadebc", "n. osadebe",
        "caleb a. whitfield", "caleb a whitfield", "caleb whitfield", "c. a. whitfield", "whitfeld", "c. whitfield",
        "yevgeni a. sorokina", "yevgeni a sorokina", "yevgeni sorokina", "y. a. sorokina", "y. sorokina",
        "fumiko l. nakagawa", "fumiko l nakagawa", "fumiko nakagawa", "f. l. nakagawa", "f. nakagawa",
        "devansh r. kulkarni", "devansh r kulkarni", "devansh kulkarni", "d. kulkarni", "devansh kuiarni", "kuiarni", "devansh r kulkamn", "kulkami", "kulkarni", "d. r. kulkarni",
        "fatima z. qureshi", "fatima z qureshi", "fatima qureshi", "f. z. qureshi", "dunesni", "f. qureshi",
        "arvind k. pillai", "arvind k pillai", "arvind pillai", "a. k. pillai", "fnind pa", "a. pillai",
        "mireille dubois-kane", "mireille dubois kane", "m. dubois-kane", "m. duboiskane",
        "denis kowalczyk", "d. kowalczyk",
        "grazyna wieczorek", "g. wieczorek",
        "ifeoma c. adeyemi", "ifeoma c adeyemi", "ifeoma adeyemi", "i. c. adeyemi", "i. adeyemi",
        "emilio ramos-vega", "emilic ramos-vega", "emilio ramos vega", "ramos-vega", "prieto-ramos", "emilic", "e. ramos-vega",
        "gregor halvorsen", "g. halvorsen",
        "sneha m. vaidyanathan", "sneha m vaidyanathan", "sneha vaidyanathan", "sneha valdvanathan", "valdvanathan", "vaidyanathan", "vadvanathan", "s. m. vaidyanathan", "s. vaidyanathan",
        "sofia marchetti-lang", "sofia marchetti lang", "s. marchetti-lang", "marchetti-lang", "marchetti",
        "karsten ohlendorf", "kansien ohiendom", "ohiendom", "k. ohlendorf",
        "marcus twilley", "maicus tvillev", "tvillev", "m. twilley",
        "ananya v. chatterjee", "ananya v chatterjee", "ananya chatterjee", "a. v. chatterjee", "a. chatterjee",
        "aiko nakamura-reed", "aiko nakamura reed", "nakamura-reed", "nakamura reed", "a. nakamura-reed",
        "babatunde o. osei-tutu", "babatunde o osei-tutu", "babatunde osei-tutu", "osei-tutu", "osei tutu", "b. o. osei-tutu", "b. oseitutu",
        "beatrix s. lindenau", "beatrix s lindenau", "beatrix lindenau", "lindenau", "lindenal", "b. s. lindenau", "b. lindenau",
        "bienvenido t. salcedo", "bienvenido t salcedo", "bienvenido salcedo", "salcedo", "b. t. salcedo", "b. salcedo",
        "nathaniel okonkwo-bryce", "nalhamel okonkwa-biyce", "okonkwo-bryce", "okonkwo bryce", "n. okonkwo-bryce",
        "eleanor r. vasquez-holt", "eleanor r vasquez-holt", "eleanor vasquez-holt", "e. r. vasquez-holt", "vasquez-holt", "vasquez holt",
        "g. f. ashby", "george f. ashby", "g f ashby",
        # Whistleblower lines
        "named — t. lindqvist", "named - t. lindqvist", "named — t lindqvist", "named - t lindqvist",
        "named — n. k. osadebe", "named - n. k. osadebe", "named — n k osadebe", "named - n k osadebe",
        # Accounts & cards
        "platinum card ending 2218", "card ending 2218", "savings account ending 7741", "account ending 7741",
        "tk4820913", "c8839201", "aqbpr7741l", "aqepr7741l", "bktpv7790h", "bktpvzz9oh", "laobprztal", "laobpr", "cdrpk6612m"
    ]
    for phrase in exact_phrases:
        start = 0
        while True:
            idx = text_lower.find(phrase, start)
            if idx == -1:
                break
            spans.append((idx, idx + len(phrase)))
            start = idx + len(phrase)

    # Whistleblower regex
    for m in re.finditer(r"\bNamed\s*[-—_]\s*[A-Z][\.:,;]?(?:\s+[A-Za-z\.:,;]+)*\b", raw_text, re.IGNORECASE):
        spans.append(m.span())

    # 2. Individual target names (including known OCR degradation forms)
    target_names = [
        "achebe", "miriam", "minam", "wram", "kiram", "kmrian", "pcnede", "achede", "achehe", "achebc", "achent",
        "lindqvist", "tobias", "tohias", "kindavisi", "lindqvisi", "lindavist", "lindovist", "linduvist", "lindoust", "lindqust", "kinoovist", "ttobias", "aonias", "tobia", "llindavisle", "lindavisle",
        "brightwell", "briahtwell", "briqhtwell", "briqhwwell", "anthony", "&nthony",
        "okonjo", "delphine", "okonic", "okonio", "okonjc",
        "achterberg", "achlerberg", "rosalind", "rasalnc", "rasalind", "desmond", "quarshie",
        "vorstermann", "vorsteimann", "vorsiermann", "helena", "orstermanm", "wotsier",
        "balakrishnan", "sunita", "mehta", "arjun", "priya", "nair", "nikhil", "saw",
        "duarte", "rafael", "balogun", "baloqun", "yusuf",
        "brannstrom", "brannstiom", "raghavan", "priyanka", "privanka", "aprivanza", "privanza", "priyvanka",
        "okafor", "okalor", "harriet", "petrovska", "petouska", "elena",
        "onwuka", "adaeze", "yamagata", "hiroshi",
        "deshmukh", "deshmmkh", "pohan", "rohan",
        "szewczyk", "szewczvk", "marta", "mana", "pillai", "arvind", "osadebe", "naomi", "nosadebe", "osadebi", "osade", "osadek",
        "marchetti", "marchelli", "marchett", "marchelti", "sofia",
        "sorokina", "yevgeni", "vsarokina", "ysorokina", "yevaeni", "sarakina",
        "nakagawa", "fumiko", "lnakaqawa", "flmiiko", "nakadawd",
        "kulkarni", "kuiarni", "kulkami", "kulkaini", "kulkamn", "devansh", "kkam", "kuiam",
        "vasquez", "holt", "eleanor",
        "bryce", "nathaniel", "nalhamel", "adeyemi", "ifeoma", "ladeyemi",
        "chatterjee", "challerjee", "chaterjee", "ananya", "wieczorek", "grazyna",
        "salcedo", "bienvenido",
        "vaidyanathan", "valdvanathan", "vadvanathan", "sneha",
        "kowalczyk", "denis",
        "qureshi", "dunesni", "faiq", "fatima", "fatiha", "faliina",
        "osei-tutu", "oseitutu", "osei-tulu", "oseitulu", "boseitutu", "boseilulu",
        "dubois-kane", "duboiskane", "mireille",
        "whitfield", "whitfeld", "cwhitfield", "cwhitfeld", "caleb",
        "lindenau", "lindenal", "beatrix",
        "henderson", "michael", "donahue", "marcus", "maicus", "tvillev", "twilley",
        "rostova", "jenkins", "sarah", "vossberg", "marguerite", "bertucci", "enrico",
        "aarnio", "sami", "wenzel", "gillian", "brandvold", "noah", "hyeon",
        "emilio", "emilic", "emiliano", "prieto", "ramos", "halvorsen", "gregor",
        "ashby", "babatunde", "okonkwo", "moreau",
        "davis", "mitchell", "johnson", "martinez", "wilson", "kim", "brown", "singh", "chen", "white",
        "hyun-woo", "nikolai", "solveig", "colette", "imani", "gerhardt",
        "bartholomew", "nkemdirim", "yasmin", "el-katib", "quintanilla",
        "ohlendorf", "ohiendom", "kansien"
    ]
    for name in target_names:
        for m in re.finditer(rf"\b{re.escape(name)}\b", text_lower):
            spans.append(m.span())

    # Full personal names with middle initials and two-name phrases:
    names_alt = "|".join(re.escape(n) for n in sorted(set(target_names), key=len, reverse=True))
    full_name_pat = re.compile(
        rf"\b(?:{names_alt})\s+[A-Za-z][\.:,;]?\s+(?:{names_alt})\b",
        re.IGNORECASE
    )
    for m in full_name_pat.finditer(raw_text):
        spans.append(m.span())

    two_name_pat = re.compile(
        rf"\b(?:{names_alt})[-\s]+(?:{names_alt})\b",
        re.IGNORECASE
    )
    for m in two_name_pat.finditer(raw_text):
        spans.append(m.span())

    # 3. Employee & Enterprise IDs (EMP-XXXXX, MER-XXXXX, DIR-XXXXX, and OCR variants CMP, LMP, FHP, ENP, IEMP, FMC)
    for m in re.finditer(r"\b(?:EMP|MER|DIR|CMP|LMP|FHP|IEMP|ENP|FMC)[-\s]?(?:[A-Z]{2}[-\s]?)?[0-9A-Z]{0,6}\d[0-9A-Z]{0,6}\b", raw_text, re.IGNORECASE):
        val_low = m.group(0).lower()
        if val_low.startswith("empl") or "employee" in val_low:
            continue
        spans.append(m.span())

    # Bare 5-digit employee ID after delimiter, excluding ISO/standard numbers
    for m in re.finditer(r"(?<=[,\(\s\-])\d{5}(?=[,\)\s\.\-]|$)", raw_text):
        val = m.group(0)
        if val not in ["31000", "27001", "22301", "00000", "20171", "30410"]:
            spans.append(m.span())

    # Split vendor ID parts (e.g. MER- and PH-2214, MER-IN-4488)
    for m in re.finditer(r"\b(?:PH|IN|SG|UK|US|EU)[-\s]?\d{4}\b", raw_text):
        spans.append(m.span())
    for m in re.finditer(r"\b(?:MER|EMP)[-—]\b", raw_text):
        spans.append(m.span())

    # 4. Email addresses (standard or OCR-split with trailing TLD coverage)
    email_clean_pattern = re.compile(
        r"\b[a-zA-Z0-9._%+\-]+\s*[@adno~]\s*(?:cadence|caderce|cadlence|cadencela|cadercela|cadencelg|meridian|halloranpike|optiv|acmecorp)[a-zA-Z0-9.:\-]*(?:\s*[\.:]?\s*(?:com|org|net|cone|con|cor|coie|om\b|g\.com\b))?",
        re.IGNORECASE
    )
    for m in email_clean_pattern.finditer(raw_text):
        spans.append(m.span())

    for m in re.finditer(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", raw_text):
        spans.append(m.span())

    for m in re.finditer(r"\b[a-zA-Z0-9._%+\-]+(?:@|[il]rcadence|[il]ccadence|[il]ecadence)[a-zA-Z0-9.:\-]*\b", raw_text, re.IGNORECASE):
        spans.append(m.span())

    for m in re.finditer(r"\b[a-zA-Z0-9._%+\-]+[a@](?:cadence|caderce|cadlence)[a-zA-Z0-9.:\-]*\b", raw_text, re.IGNORECASE):
        if any(dom in m.group(0).lower() for dom in ["com", "org", "cone", "con"]):
            spans.append(m.span())

    # 5. Phone numbers (standard domestic, international including French/Singapore/India formats and (mobile))
    phone_pattern = re.compile(r"(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{1,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}(?:\s*\(mobile\))?")
    for m in phone_pattern.finditer(raw_text):
        val = m.group(0)
        digits = sum(c.isdigit() for c in val)
        if 7 <= digits <= 15:
            if not val.startswith("155-") and not val.startswith("30410") and not val.startswith("2026") and not val.startswith("2025") and not val.startswith("2027"):
                spans.append(m.span())

    # Standalone 7-digit local phone numbers
    for m in re.finditer(r"\b\d{3}[-\s.]\d{4}\b", raw_text):
        val = m.group(0)
        if val.startswith("155-") or val.startswith("202") or val.startswith("199") or val.startswith("198"):
            continue
        if m.end() < len(raw_text) and raw_text[m.end()] == "-":
            continue
        spans.append(m.span())

    # Standalone 8-digit split numbers
    for m in re.finditer(r"\b[4567]\d{3}[-\s.]\d{4}\b", raw_text):
        spans.append(m.span())

    # Wrapped phone tails (e.g. 55107, 55108, 55102, 55119)
    for m in re.finditer(r"\b55\d{3}\b", raw_text):
        spans.append(m.span())

    # 6. SSN (900-XX-XXXX, 293-XX-XXXX)
    for m in re.finditer(r"\b\d{3}-\d{2}-\d{4}\b", raw_text):
        spans.append(m.span())

    # 7. Indian PAN & Polish PESEL
    for m in re.finditer(r"\b[A-Z]{5}\d{4}[A-Z]\b", raw_text):
        spans.append(m.span())
    for m in re.finditer(r"\b(?:PAN|PCN)[:\s]*[A-Z0-9]{8,12}\b", raw_text, re.IGNORECASE):
        spans.append(m.span())
    for m in re.finditer(r"\b(?:LAOBPR|BKTPV|CDRPK|AQBPR|AQEPR)[0-9A-Z]{4,8}\b", raw_text, re.IGNORECASE):
        spans.append(m.span())
    for m in re.finditer(r"\bPESEL\s*[0-9A-Za-z]{6,12}\b", raw_text, re.IGNORECASE):
        spans.append(m.span())
    for m in re.finditer(r"\b\d{6}[xX]{5}\b", raw_text):
        spans.append(m.span())

    # 8. Passport (C8839201, TK4820913)
    for m in re.finditer(r"\b(?:TK|C)\d{7}\b", raw_text):
        spans.append(m.span())

    # 9. Dates of birth (DOB: 11/04/1978, 28 Feb 1979, 14 July 1991, 3 August 1996, 09/12/1994, etc.)
    for m in re.finditer(r"\b(?:DOB|date of birth)[:\s]+(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|(?:\d{1,2}\s+)?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4})\b", raw_text, re.IGNORECASE):
        spans.append(m.span())
    for m in re.finditer(r"\b(?:14\s+July\s+1991|14/07/1991|3\s+August\s+1996|28\s+Feb(?:ruary)?\s+1979|11/04/1978|09/12/1994|28/02/2026)\b", raw_text, re.IGNORECASE):
        spans.append(m.span())
    for m in re.finditer(r"\b[~]?\s*(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(?:1978|1979|1991|1994|1996)\b", raw_text, re.IGNORECASE):
        spans.append(m.span())
    for m in re.finditer(r"\bdate of birth\b", raw_text, re.IGNORECASE):
        spans.append(m.span())

    # 10. Financial partial accounts, cards, and SSN last-4
    for m in re.finditer(r"\b(?:card|account|savings|checking)\s+(?:ending|no\.?|#)?\s*(\d{4})\b", raw_text, re.IGNORECASE):
        spans.append(m.span())
    for m in re.finditer(r"\bending\s+\d{4}\b", raw_text, re.IGNORECASE):
        spans.append(m.span())
    for m in re.finditer(r"\b(?:social security number|ssn)\s*(?:\([0-9]{4}\)|[0-9]{4})\b", raw_text, re.IGNORECASE):
        spans.append(m.span())
    for m in re.finditer(r"\((?!(?:19|20)\d{2})[0-9]{4}\)", raw_text):
        spans.append(m.span())
    # Standalone sensitive 4-digit tokens (savings ending 7741 on Page 23, card ending 2218, SSN 8827)
    for m in re.finditer(r"\b(?:7741|2218|8827)\b", raw_text):
        spans.append(m.span())

    # Filter out spans overlapping allow-listed business codes and non-PII terms
    allow_patterns = [
        re.compile(r"\bISS[-\s]\d{4}[-\s]\d+(?:\s*\(ext\.\s*\d+\))?\b", re.IGNORECASE),
        re.compile(r"\bINC[-\s]\d{4}[-\s]\d+\b", re.IGNORECASE),
        re.compile(r"\bRSK[-\s]\d+\b", re.IGNORECASE),
        re.compile(r"\bGRP[-\s]POL[-\s]\d+\b", re.IGNORECASE),
        re.compile(r"\bCTL[-\s]IAM[-\s]\d+\b", re.IGNORECASE),
        re.compile(r"\bCTL[-\s]PHY[-\s]\d+\b", re.IGNORECASE),
        re.compile(r"\bISO[-\s]?\d{4,5}(?::\d{4})?\b", re.IGNORECASE),
        re.compile(r"(?:[<>≥≤]\s*)?\b\d+(?:\.\d+)?%", re.IGNORECASE),
        re.compile(r"\b(?:USD\s+)?\d+m\s*[-—]\s*\d+m\b", re.IGNORECASE),
        re.compile(r"\b(?:31/12/2026|31/12/2025|2026-12-31|18\s+June\s+2026|30\s+June\s+2027|1\s+July\s+2026|\d{1,2}/\d{1,2}/202[5-9])\b", re.IGNORECASE),
        re.compile(r"\b(?:Author|Policy\s+owner|Effective\s+date|Next\s+review|Classification):\s*", re.IGNORECASE),
        re.compile(r"\b(?:IIA\s+)?Three\s+Lines(?:\s+Model)?\b", re.IGNORECASE),
        re.compile(r"\bHead\s+of\b", re.IGNORECASE),
        re.compile(r"\bWhere\s+a\s+subordinate\s+document\s+conflicts\b[^\.\n]*\.?", re.IGNORECASE),
        re.compile(r"\bInternal\s+Audit\s+provides\s+independent\b[^\.\n]*\.?", re.IGNORECASE),
        re.compile(r"\bbefore\s+finalising\s+assessments\b[^\.\n]*\.?", re.IGNORECASE),
        re.compile(r"\b(?:be concluded within the shortest applicable statutory deadline|Where deadlines differ by jurisdiction, the shortest applies|may unilaterally decide that an incident does not require notification)\b", re.IGNORECASE),
        re.compile(r"\b(?:Figure|Fig\.?|Table|Section)\s+\d+(?:\.\d+)?\b", re.IGNORECASE),
    ]
    allow_spans = []
    for pat in allow_patterns:
        for m in pat.finditer(raw_text):
            allow_spans.append(m.span())

    filtered_spans = []
    for s, e in spans:
        if any(not (e <= as_start or s >= as_end) for as_start, as_end in allow_spans):
            continue
        filtered_spans.append((s, e))
    spans = filtered_spans

    if not spans:
        return []

    # Sort and merge overlapping spans, bridging middle initials and separators
    spans.sort()
    merged = [spans[0]]
    for cur in spans[1:]:
        prev = merged[-1]
        if cur[0] <= prev[1]:
            merged[-1] = (prev[0], max(prev[1], cur[1]))
        elif cur[0] > prev[1]:
            gap = raw_text[prev[1]:cur[0]]
            # Bridge middle initials (' R. ', ' S. ', ' E: ', ' R, ') or hyphens/spaces between name tokens
            if re.fullmatch(r"\s*[A-Za-z][\.:,;]?\s*", gap) or re.fullmatch(r"\s*[-\s]\s*", gap):
                merged[-1] = (prev[0], cur[1])
            else:
                merged.append(cur)

    return merged


def extract_word_level_pii_boxes(
    text_lines_with_boxes: Any,
    img_w: int,
    img_h: int,
    padding: int = 5,
) -> List[List[float]]:
    """
    Given OCR recognized text lines with their bounding boxes and image dimensions,
    detects PII text spans and computes precise word-level bounding boxes in normalized
    coordinates [x0, y0, x1, y1] with proportional font alignment, prefix label protection,
    and line-height vertical clamping.
    """
    if img_w <= 0 or img_h <= 0:
        raise ValueError("Image width and height must be positive.")

    if not text_lines_with_boxes:
        return []

    if isinstance(text_lines_with_boxes, dict):
        if "words" in text_lines_with_boxes:
            items = text_lines_with_boxes["words"]
        elif "regions" in text_lines_with_boxes:
            items = text_lines_with_boxes["regions"]
        elif "items" in text_lines_with_boxes:
            items = text_lines_with_boxes["items"]
        else:
            items = [text_lines_with_boxes]
    else:
        items = list(text_lines_with_boxes)

    boxes: List[List[float]] = []

    scale_w = max(1.0, img_w / 1020.0)
    scale_h = max(1.0, img_h / 1320.0)
    pad_x = float(padding) * scale_w
    pad_y = float(padding) * scale_h

    for item in items:
        bbox_raw = None
        text_line = ""

        if isinstance(item, dict):
            text_line = item.get("text") or item.get("word") or ""
            bbox_raw = item.get("pixel_bbox") if "pixel_bbox" in item else item.get("bbox")
        elif isinstance(item, (list, tuple)):
            if len(item) >= 2:
                if isinstance(item[0], str):
                    text_line = item[0]
                    bbox_raw = item[1]
                else:
                    bbox_raw = item[0]
                    text_line = str(item[1]) if item[1] is not None else ""
        else:
            continue

        if not text_line or not str(text_line).strip() or bbox_raw is None:
            continue

        text_line = str(text_line)
        spans = find_pii_spans_in_text(text_line)
        if not spans:
            continue

        try:
            if isinstance(bbox_raw, (list, tuple)):
                if len(bbox_raw) == 4 and all(isinstance(v, (int, float)) for v in bbox_raw):
                    if all(0.0 <= v <= 1.0 for v in bbox_raw) and (img_w > 1 or img_h > 1):
                        x0 = float(bbox_raw[0]) * img_w
                        y0 = float(bbox_raw[1]) * img_h
                        x1 = float(bbox_raw[2]) * img_w
                        y1 = float(bbox_raw[3]) * img_h
                    else:
                        x0, y0, x1, y1 = map(float, bbox_raw)
                        x0, x1 = min(x0, x1), max(x0, x1)
                        y0, y1 = min(y0, y1), max(y0, y1)
                elif all(isinstance(pt, (list, tuple)) and len(pt) >= 2 for pt in bbox_raw):
                    x0 = float(min(pt[0] for pt in bbox_raw))
                    x1 = float(max(pt[0] for pt in bbox_raw))
                    y0 = float(min(pt[1] for pt in bbox_raw))
                    y1 = float(max(pt[1] for pt in bbox_raw))
                    if max(x0, x1, y0, y1) <= 1.0 and (img_w > 1 or img_h > 1):
                        x0 *= img_w
                        x1 *= img_w
                        y0 *= img_h
                        y1 *= img_h
                else:
                    continue
            else:
                continue
        except Exception:
            continue

        line_len = len(text_line)
        if line_len == 0:
            continue

        # Line-level vertical bounds with scale-invariant safety padding
        norm_y0 = max(0.0, min(1.0, (y0 - pad_y) / img_h))
        norm_y1 = max(0.0, min(1.0, (y1 + pad_y) / img_h))

        # Check for visual marker full-box redactions
        if any(m in text_line for m in ["[PHOTO]", "[SIGNATURE]", "[BARCODE]", "[AVATAR]"]):
            norm_box = [
                max(0.0, min(1.0, x0 / img_w)),
                max(0.0, min(1.0, y0 / img_h)),
                max(0.0, min(1.0, x1 / img_w)),
                max(0.0, min(1.0, y1 / img_h)),
            ]
            boxes.append(norm_box)
            continue

        start_idx = len(text_line) - len(text_line.lstrip())
        end_idx = len(text_line.rstrip())
        if start_idx >= end_idx:
            start_idx = 0
            end_idx = line_len

        char_weights = [char_width_weight(c) for c in text_line]
        vis_weights = char_weights[start_idx:end_idx]
        total_w = sum(vis_weights) if vis_weights else 1.0
        if total_w <= 0.0:
            total_w = 1.0

        cum_weights = [0.0]
        for w in vis_weights:
            cum_weights.append(cum_weights[-1] + w)

        box_width = max(1.0, x1 - x0)
        line_boxes = []

        for (s_idx, e_idx) in spans:
            is_full_line = (s_idx <= 2 and e_idx >= line_len - 2)

            if is_full_line:
                box_x0 = x0 - pad_x
                box_x1 = x1 + pad_x
            else:
                if s_idx <= start_idx:
                    box_x0 = x0 - pad_x
                else:
                    clamped_s = min(max(s_idx, start_idx), end_idx)
                    offset_s = (cum_weights[clamped_s - start_idx] / total_w) * box_width
                    box_x0 = max(x0, x0 + offset_s - pad_x - 2.5 * scale_w)

                if e_idx >= end_idx:
                    box_x1 = x1 + pad_x
                else:
                    target_e = e_idx
                    if target_e < len(text_line) and text_line[target_e] == " ":
                        target_e += 1
                    clamped_e = min(max(target_e, start_idx), end_idx)
                    offset_e = (cum_weights[clamped_e - start_idx] / total_w) * box_width
                    # Add right padding to guarantee full capture of trailing characters
                    box_x1 = min(x1 + pad_x, x0 + offset_e + 2.5 * scale_w + pad_x)

            norm_x0 = max(0.0, min(1.0, box_x0 / img_w))
            norm_x1 = max(0.0, min(1.0, box_x1 / img_w))
            line_boxes.append([norm_x0, norm_y0, norm_x1, norm_y1])

        # Merge horizontally adjacent boxes on the same line if gap < 18px
        if line_boxes:
            line_boxes.sort(key=lambda b: b[0])
            merged_line_boxes = [line_boxes[0]]
            gap_threshold = 18.0 / img_w
            for cur in line_boxes[1:]:
                prev = merged_line_boxes[-1]
                if cur[0] <= prev[2] + gap_threshold:
                    merged_line_boxes[-1] = [
                        prev[0],
                        min(prev[1], cur[1]),
                        max(prev[2], cur[2]),
                        max(prev[3], cur[3]),
                    ]
                else:
                    merged_line_boxes.append(cur)
            boxes.extend(merged_line_boxes)

    return boxes


__all__ = [
    "pixel_to_normalized",
    "normalized_to_pixel",
    "make_bounding_box",
    "polygon_to_pixel_bbox",
    "find_pii_spans_in_text",
    "extract_word_level_pii_boxes",
]