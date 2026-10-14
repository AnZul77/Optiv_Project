import fitz
import easyocr
import re
from PIL import Image

doc = fitz.open('data/outputs/sanitized_Cadence_Group_Risk_Management_Policy__v6.0.pdf')
reader = easyocr.Reader(['en'], gpu=False)

names_to_check = [
    'Brightwell', 'Lindqvist', 'Achterberg', 'Quarshie', 'Dubois-Kane', 'Dubois',
    'Kulkarni', 'Chatterjee', 'Nakamura-Reed', 'Yamagata', 'Deshmukh', 'Marchetti',
    'Vorstermann', 'Achebe', 'Mehta', 'Vasquez-Holt', 'Vasquez', 'Adeyemi',
    'Okonjo', 'Szewczyk', 'Salcedo', 'Balogun', 'Raghavan', 'Osei-Tutu',
    'Ashby', 'Whitfield', 'Lindenau', 'Nair', 'Babatunde'
]

email_pattern = re.compile(r'[a-zA-Z0-9_.+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-.]+')
phone_pattern = re.compile(r'(?:\+\d{1,3}[\s-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}')
id_pattern = re.compile(r'\b(?:EMP|MER|DIR|CMP|LMP|FHP)[-\s]?\d{4,6}\b', re.IGNORECASE)

print('=== SCANNING SANITIZED PDF FOR KNOWN LEAKS ===')
pages_to_check = [27, 33]

for p_num in pages_to_check:
    pix = doc[p_num - 1].get_pixmap(dpi=150)
    img_bytes = pix.tobytes('png')
    results = reader.readtext(img_bytes)
    
    leaks = []
    for bbox, text, prob in results:
        # check names
        for n in names_to_check:
            if re.search(rf'\b{re.escape(n)}\b', text, re.IGNORECASE):
                leaks.append(('NAME', n, text, bbox))
        # check emails
        if email_pattern.search(text) and 'example.com' not in text.lower():
            leaks.append(('EMAIL', text, text, bbox))
        # check IDs
        for m in id_pattern.finditer(text):
            leaks.append(('ID', m.group(0), text, bbox))
            
    if leaks:
        print(f'\n[!] PAGE {p_num}: Found {len(leaks)} potential leaks:')
        for ltype, token, full_text, bbox in leaks:
            print(f'    - [{ltype}] {token} in "{full_text}" at bbox {bbox}')
    else:
        print(f'[OK] Page {p_num:2d}: 0 leaks detected')
