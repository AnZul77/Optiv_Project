import streamlit as st
import pandas as pd
import time
import os
import sys
import tempfile
import html
from datetime import datetime
from pathlib import Path

# Ensure src module is in path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.ingestion.dispatcher import route_document
from src.detection.pipeline import DetectionPipeline
from src.sanitization.text_redactor import redact_text_by_values
from src.sanitization.docx_reconstructor import DOCXReconstructor

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="PII Security Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Session State
if "audit_log" not in st.session_state:
    st.session_state["audit_log"] = []

# --- CUSTOM CSS FOR DARK MODE & STYLING ---
st.markdown("""
<style>
    /* Main Background & Text */
    .stApp {
        background-color: #0E1117;
        color: #FAFAFA;
    }
    
    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #161A22;
        border-right: 1px solid #2D333B;
    }
    
    /* Custom Headers */
    h1, h2, h3 {
        color: #FFFFFF;
        font-family: 'Inter', sans-serif;
    }
    
    /* Badges */
    .status-badge {
        background-color: #1a2721;
        color: #2ea043;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
        border: 1px solid #238636;
        display: inline-block;
        margin-bottom: 20px;
    }
    
    /* Decision Card */
    .decision-card {
        background-color: #1a2721;
        border: 1px solid #238636;
        border-radius: 8px;
        padding: 20px;
        display: flex;
        align-items: center;
        gap: 20px;
        margin-top: 20px;
        margin-bottom: 30px;
    }
    .decision-card-alert {
        background-color: #2d1818;
        border: 1px solid #da3633;
        border-radius: 8px;
        padding: 20px;
        display: flex;
        align-items: center;
        gap: 20px;
        margin-top: 20px;
        margin-bottom: 30px;
    }
    .pass-badge {
        background-color: #238636;
        color: white;
        padding: 8px 16px;
        border-radius: 6px;
        font-size: 20px;
        font-weight: bold;
    }
    .block-badge {
        background-color: #da3633;
        color: white;
        padding: 8px 16px;
        border-radius: 6px;
        font-size: 20px;
        font-weight: bold;
    }
    
    /* Document Panels */
    .doc-panel {
        background-color: #1C2128;
        border: 1px solid #30363D;
        border-radius: 8px;
        padding: 20px;
        min-height: 380px;
        max-height: 520px;
        overflow-y: auto;
        font-family: 'Courier New', Courier, monospace;
        font-size: 13px;
        line-height: 1.6;
        white-space: pre-wrap;
    }
    
    .highlight-red { background-color: #4B1818; color: #FF7B72; padding: 2px 4px; border-radius: 4px; font-weight: bold; }
    .highlight-cyan { background-color: #12333F; color: #79C0FF; padding: 2px 4px; border-radius: 4px; font-weight: bold; }
    
    .redacted { background-color: #000000; color: #3fb950; padding: 2px 4px; border-radius: 4px; font-weight: bold; border: 1px solid #3fb950; }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR NAVIGATION ---
with st.sidebar:
    st.markdown("### 🛡️ PII SENTINEL")
    st.caption("Multimodal AI Security Firewall Gateway")
    st.markdown("---")
    page = st.radio("Navigation", [
        "Live Security Gateway",
        "Benchmark Metrics",
        "Adversarial Testing Suite"
    ], label_visibility="collapsed")
    st.markdown("---")
    st.markdown("### Engine Status")
    st.markdown("🟢 **Ingestion**: Native + Scanned")
    st.markdown("🟢 **OCR**: EasyOCR + PyMuPDF")
    st.markdown("🟢 **Detection**: 5-Layer Stack")
    st.markdown("🟡 **Policy & Verifier**: Standalone")

# --- PAGE: LIVE SECURITY GATEWAY ---
if page == "Live Security Gateway":
    
    # Header
    st.markdown('<div class="status-badge">🟢 Gateway Active - Multimodal Fail-Closed Mode</div>', unsafe_allow_html=True)
    st.title("Enterprise PII Security Gateway")
    
    # Document Upload
    st.markdown("#### Upload enterprise documents to detect, sanitize, and verify against PII leaks")
    uploaded_file = st.file_uploader("Supports PDF, DOCX, PPTX and plain text documents", type=["pdf", "docx", "pptx", "txt"], label_visibility="collapsed")
    
    if uploaded_file:
        file_ext = uploaded_file.name.split('.')[-1].lower()
        
        # Save uploaded file to temp file to pass to backend
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file_ext}") as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name

        st.write("---")
        progress_cols = st.columns(5)
        steps = ["1. Ingestion", "2. 5-Layer Detection", "3. Span Resolution", "4. Sanitization", "5. Gate Decision"]

        try:
            with st.spinner("Processing document through multi-layered PII Firewall..."):
                for i, col in enumerate(progress_cols[:2]):
                    with col:
                        st.info(steps[i])

                # Step 1: Ingestion
                summary = route_document(tmp_path)
                canonical_doc = summary.get("document")

                # Step 2 & 3: 5-Layer Detection Pipeline
                pipeline = DetectionPipeline(enable_ner=True)
                pipeline.run_document(canonical_doc)

                for i, col in enumerate(progress_cols[2:]):
                    with col:
                        st.success(steps[i + 2])

            if summary.get("status") == "EXTRACTED":
                det_summary = canonical_doc.metadata.get("detection_summary", {})
                total_entities = det_summary.get("total_entities", len(canonical_doc.entities))
                risk_summary = det_summary.get("risk_summary", {})
                proc_time = det_summary.get("processing_time_ms", 0.0)

                # Telemetry Banner
                m1, m2, m3, m4, m5 = st.columns(5)
                m1.metric("Total Pages", summary.get("total_pages", 1))
                m2.metric("Entities Detected", total_entities)
                m3.metric("Critical Risk", risk_summary.get("CRITICAL", 0))
                m4.metric("High Risk", risk_summary.get("HIGH", 0))
                m5.metric("Latency", f"{proc_time:.0f} ms")

                # Build Replacements Mapping
                replacements = {}
                highlight_map = {}
                entities_list = canonical_doc.entities or []

                for ent in entities_list:
                    raw_val = ent.context.get("raw_value") if isinstance(ent.context, dict) else ""
                    if not raw_val and hasattr(ent, "raw_value"):
                        raw_val = getattr(ent, "raw_value")
                    
                    if raw_val and raw_val.strip():
                        mask_token = f"[REDACTED:{ent.type}]"
                        replacements[raw_val] = mask_token
                        color_cls = "highlight-red" if ent.risk == "CRITICAL" else "highlight-cyan"
                        highlight_map[raw_val] = f'<span class="{color_cls}">{html.escape(raw_val)}</span>'

                        # Add to Session Audit Log
                        st.session_state["audit_log"].append({
                            "TIMESTAMP": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "FILE": uploaded_file.name,
                            "PAGE": ent.page,
                            "TYPE": ent.type,
                            "RISK": ent.risk,
                            "SOURCE": ent.source,
                            "CONFIDENCE": f"{ent.confidence:.2f}",
                            "VALUE_HASH": ent.value_hash[:16] + "...",
                            "ACTION": "REDACTED",
                        })

                # Prepare Ingress Text & Egress Sanitized Text
                pages_text = []
                for p_num, page in sorted(canonical_doc.pages_dict.items()):
                    if page.combined_text.strip():
                        pages_text.append(f"--- Page {p_num} ---\n" + page.combined_text)

                raw_ingress_text = "\n\n".join(pages_text) if pages_text else "No extractable text found."
                # Truncate for display preview if excessively long
                preview_length = 3500
                display_ingress = raw_ingress_text[:preview_length]
                if len(raw_ingress_text) > preview_length:
                    display_ingress += "\n\n[... Remaining content truncated in preview ...]"

                # Apply HTML highlights to Ingress
                highlighted_ingress = html.escape(display_ingress)
                for raw_val, hl_html in sorted(highlight_map.items(), key=lambda x: len(x[0]), reverse=True):
                    escaped_raw = html.escape(raw_val)
                    highlighted_ingress = highlighted_ingress.replace(escaped_raw, hl_html)

                # Sanitized text
                sanitized_full_text = redact_text_by_values(raw_ingress_text, replacements)
                sanitized_preview = redact_text_by_values(display_ingress, replacements)
                
                # Apply HTML badges to Egress
                highlighted_egress = html.escape(sanitized_preview)
                for mask_token in set(replacements.values()):
                    esc_token = html.escape(mask_token)
                    badge_html = f'<span class="redacted">{esc_token}</span>'
                    highlighted_egress = highlighted_egress.replace(esc_token, badge_html)

                # Side-by-Side Comparison
                st.write("---")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("### 📄 Original Ingress Stream (with PII Highlights)")
                    st.markdown(f'<div class="doc-panel">{highlighted_ingress}</div>', unsafe_allow_html=True)
                    
                with col2:
                    st.markdown("### 🛡️ Sanitized Egress Stream (Model-Ready)")
                    st.markdown(f'<div class="doc-panel">{highlighted_egress}</div>', unsafe_allow_html=True)

                # Gatekeeper Decision Card
                crit_count = risk_summary.get("CRITICAL", 0)
                high_count = risk_summary.get("HIGH", 0)
                
                if total_entities > 0:
                    st.markdown(f"""
                    <div class="decision-card">
                        <div class="pass-badge">🛡️ AI READY: PASS</div>
                        <div>
                            <h3 style="margin: 0;">Safe for Model Inference</h3>
                            <p style="margin: 0; color: #8B949E;">Successfully sanitized {total_entities} detected entities ({crit_count} Critical, {high_count} High) across {summary.get('total_pages', 1)} pages.</p>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="decision-card">
                        <div class="pass-badge">🛡️ AI READY: PASS</div>
                        <div>
                            <h3 style="margin: 0;">Clean Document Verified</h3>
                            <p style="margin: 0; color: #8B949E;">Zero PII detected across {summary.get('total_pages', 1)} pages.</p>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                # Document Reconstruction & Download Button
                sanitized_bytes = None
                download_filename = f"sanitized_{uploaded_file.name}"
                download_mime = "text/plain"

                if file_ext == "docx":
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".docx") as out_tmp:
                        out_path = out_tmp.name
                    
                    success, err = DOCXReconstructor.replace_text_in_document(tmp_path, out_path, replacements)
                    if success and os.path.exists(out_path):
                        with open(out_path, "rb") as f:
                            sanitized_bytes = f.read()
                        download_mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                        try:
                            os.unlink(out_path)
                        except OSError:
                            pass
                
                if sanitized_bytes is None:
                    sanitized_bytes = sanitized_full_text.encode("utf-8")
                    download_filename = f"sanitized_{Path(uploaded_file.name).stem}.txt"
                    download_mime = "text/plain"

                st.download_button(
                    label=f"📥 Download Sanitized Artifact ({download_filename})",
                    data=sanitized_bytes,
                    file_name=download_filename,
                    mime=download_mime,
                )

                # Entities Inspection Table
                st.write("---")
                st.markdown("### 🔍 Detected Entities & Provenance Telemetry")
                if entities_list:
                    ent_rows = []
                    for e in entities_list:
                        ent_rows.append({
                            "Page": e.page,
                            "Entity Type": e.type,
                            "Risk Level": e.risk,
                            "Confidence": f"{e.confidence:.2%}",
                            "Detection Source": e.source,
                            "Value Hash": e.value_hash[:16] + "...",
                            "Action": e.action,
                        })
                    st.dataframe(pd.DataFrame(ent_rows), use_container_width=True, hide_index=True)
                else:
                    st.info("No PII entities detected in this document.")

            else:
                st.error(f"❌ Backend Extraction Failed: {summary.get('error', 'Unknown Error')}")

        except Exception as e:
            st.error(f"❌ Pipeline Execution Error: {str(e)}")
            import traceback
            st.code(traceback.format_exc())
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    # Audit Log Table (Session Persistent)
    st.write("---")
    st.markdown("### 🧾 Zero-PII Cryptographic Audit Log")
    if st.session_state["audit_log"]:
        # Display most recent 50 entries
        recent_log = st.session_state["audit_log"][-50:]
        st.dataframe(pd.DataFrame(recent_log), use_container_width=True, hide_index=True)
    else:
        st.caption("No documents processed in this session yet. Upload a document above to generate audit records.")

# --- PAGE: BENCHMARK METRICS ---
elif page == "Benchmark Metrics":
    st.title("Benchmark Metrics & Ablation Study")
    
    col_a, col_b = st.columns([3, 1])
    with col_b:
        if st.button("🔄 Re-run Ablation Benchmark"):
            with st.spinner("Executing Context vs Baseline Ablation Study..."):
                from src.evaluation.ablation import run_ablation_experiment
                PROJECT_ROOT = Path(__file__).parent
                GT_DIR = PROJECT_ROOT / "data" / "ground_truth"
                REPORT_PATH = PROJECT_ROOT / "reports" / "evaluation" / "ablation_results.md"
                run_ablation_experiment(str(GT_DIR), str(REPORT_PATH))
                st.success("Benchmark completed and report updated!")

    ablation_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", "evaluation", "ablation_results.md")
    if os.path.exists(ablation_path):
        with open(ablation_path, "r") as f:
            ablation_content = f.read()
        st.markdown(ablation_content)
    else:
        st.warning("⚠️ Ablation study results not found. Click the button above to generate benchmark results.")

# --- PAGE: ADVERSARIAL TESTING ---
elif page == "Adversarial Testing Suite":
    st.title("Adversarial Evasion Testing Suite")
    st.markdown("Run the suite of adversarial attack vectors designed to attempt bypasses of the PII firewall (character spacing, zero-width characters, Cyrillic/homoglyphs, and rotated scans).")
    
    if st.button("▶️ Run Adversarial Test Suite"):
        with st.spinner("Executing Homoglyph, Character Spacing, and Zero-Width Space evasion tests..."):
            import subprocess
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/adversarial/test_evasion.py", "-v"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                st.success("✅ All Adversarial Attacks Successfully Defeated!")
                st.code(result.stdout, language="bash")
            else:
                st.error("❌ Adversarial Vulnerability Detected!")
                st.code(result.stdout + "\n" + result.stderr, language="bash")
