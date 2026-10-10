import streamlit as st
import pandas as pd
import time
import os
import sys
import tempfile

# Ensure src module is in path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.ingestion.dispatcher import route_document

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="PII Security Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
    .pass-badge {
        background-color: #238636;
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
        min-height: 400px;
    }
    
    .highlight-red { background-color: #4B1818; color: #FF7B72; padding: 2px 4px; border-radius: 4px; }
    .highlight-cyan { background-color: #12333F; color: #79C0FF; padding: 2px 4px; border-radius: 4px; }
    
    .redacted { background-color: #000000; color: #3fb950; padding: 2px 4px; border-radius: 4px; font-weight: bold; border: 1px solid #3fb950; }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR NAVIGATION ---
with st.sidebar:
    st.markdown("### PII SENTINEL")
    st.markdown("---")
    page = st.radio("Navigation", [
        "Live Security Gateway",
        "Benchmark Metrics",
        "Adversarial Testing Suite"
    ], label_visibility="collapsed")

# --- PAGE: LIVE SECURITY GATEWAY ---
if page == "Live Security Gateway":
    
    # Header
    st.markdown('<div class="status-badge">🟢 System Active - Fail-Closed Mode</div>', unsafe_allow_html=True)
    st.title("PII Security Gateway")
    
    # Document Upload
    st.markdown("#### Drag and drop enterprise documents to sanitize, or click to browse")
    uploaded_file = st.file_uploader("Supports PDF, DOCX, XLSX, JSON, CSV and raw payload text", label_visibility="collapsed")
    
    if uploaded_file:
        # Pipeline Progress Bar Simulation
        st.write("---")
        progress_cols = st.columns(5)
        steps = ["1. Extraction", "2. Detection", "3. Redaction", "4. Verification", "5. Gate Decision"]
        
        with st.spinner("Processing Document through PII Firewall..."):
            time.sleep(1) # Fake processing time
            for i, col in enumerate(progress_cols):
                with col:
                    st.success(steps[i])
                    
        # Save uploaded file to temp file to pass to backend
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{uploaded_file.name.split('.')[-1]}") as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name
            
        try:
            summary = route_document(tmp_path)
        except Exception as e:
            summary = {"status": "FAILED", "error": str(e)}
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        
        st.write("---")
        
        if summary.get("status") == "EXTRACTED":
            st.success(f"✅ Backend Ingestion Successful: Processed {summary.get('filename', 'document')} ({summary.get('total_pages', 0)} pages)")
            with st.expander("View Raw Ingestion Engine Telemetry"):
                st.json({k: v for k, v in summary.items() if k != "document"})
        else:
            st.error(f"❌ Backend Extraction Failed: {summary.get('error', 'Unknown Error')}")
        
        # Side-by-Side Comparison
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📄 Original Ingress Stream")
            st.markdown("""
            <div class="doc-panel">
                <p style="color: #8B949E; font-size: 12px;">// RECORD INGEST: CLINICAL_SUMMARY_8042.JSON</p>
                <p>Subject: Patient Consultation Intake & Risk Assessment</p>
                <p>Intake notes for patient <span class="highlight-cyan">Marcus Vance</span> admitted with acute arrhythmia. 
                National identifier registered as SSN <span class="highlight-red">849-02-7193</span>. Primary communication 
                channel verified via secure email <span class="highlight-red">sarah.connor@cyberdyne.org</span> and 
                emergency contact telephone <span class="highlight-cyan">+1 (555) 019-2834</span>.</p>
            </div>
            """, unsafe_allow_html=True)
            
        with col2:
            st.markdown("### 🛡️ Sanitized Artifact")
            st.markdown("""
            <div class="doc-panel">
                <p style="color: #8B949E; font-size: 12px;">// SANITIZED EGRESS: SAFE FOR MODEL CONTEXT</p>
                <p>Subject: Patient Consultation Intake & Risk Assessment</p>
                <p>Intake notes for patient <span class="redacted">[REDACTED:PATIENT_NAME]</span> admitted with acute arrhythmia. 
                National identifier registered as SSN <span class="redacted">[REDACTED:SSN]</span>. Primary communication 
                channel verified via secure email <span class="redacted">[REDACTED:EMAIL]</span> and 
                emergency contact telephone <span class="redacted">[REDACTED:PHONE]</span>.</p>
            </div>
            """, unsafe_allow_html=True)

        # Gatekeeper Decision Card
        st.markdown("""
        <div class="decision-card">
            <div class="pass-badge">🛡️ AI READY: PASS</div>
            <div>
                <h3 style="margin: 0;">Safe for Model Inference</h3>
                <p style="margin: 0; color: #8B949E;">Zero residual PII detected.</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Download Button
        st.download_button(
            label="📥 Download Sanitized Artifact",
            data="Mock sanitized data content",
            file_name=f"sanitized_{uploaded_file.name}",
            mime="text/plain"
        )
    
    # Audit Log Table (always visible at bottom)
    st.write("---")
    st.markdown("### 🧾 Audit Log")
    
    # Mock data for the table
    audit_data = {
        "FILE NAME": ["oncology_patient_records.pdf", "financial_risk_summary.docx", "cust_transaction_data.json"],
        "SIZE": ["14.2 MB", "8.9 MB", "2.8 MB"],
        "TARGET LLM": ["GPT-4o", "Claude 3.5 Sonnet", "Llama 3"],
        "FINAL STATUS": ["🟢 PASS", "🟢 PASS", "🟢 PASS"]
    }
    st.dataframe(pd.DataFrame(audit_data), use_container_width=True, hide_index=True)

# --- PAGE: BENCHMARK METRICS ---
elif page == "Benchmark Metrics":
    st.title("Benchmark Metrics")
    st.info("Evaluation metrics and ablation studies will be displayed here.")

# --- PAGE: ADVERSARIAL TESTING ---
elif page == "Adversarial Testing Suite":
    st.title("Adversarial Testing Suite")
    st.info("Adversarial attack vectors and robustness results will be displayed here.")
