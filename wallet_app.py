import streamlit as st
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import hashlib
import json
from datetime import datetime


class RiskEngine:
    def __init__(self):
        self.user_avg_amount = 450.0  # Baseline B = KSh 450.00
        self.user_trusted_locations = ['Home', 'Office', 'Local Grocery']

    def evaluate_transaction(self, tx):
        score = 0
        reasons = []

        # 1. Amount Deviation Check (Max +40)
        if tx['amount'] > self.user_avg_amount * 5:
            score += 40
            reasons.append("High transaction amount (>5x baseline)")
        elif tx['amount'] > self.user_avg_amount * 2:
            score += 15
            reasons.append("Moderately elevated amount (>2x baseline)")

        # 2. Location Trust Vector (+25)
        if tx['location'] not in self.user_trusted_locations:
            score += 25
            reasons.append(f"Untrusted location ({tx['location']})")

        # 3. Temporal Anomaly Vector (+20) -> Off-hours (23:00 - 05:00)
        tx_hour = tx['hour']
        if tx_hour >= 23 or tx_hour <= 5:
            score += 20
            reasons.append("Off-hours window (23:00 - 05:00)")

        # 4. Device Integrity Vector (Max +60)
        if tx['device_root_status'] == 'compromised':
            score += 60
            reasons.append("Device environment compromised/rooted")
        elif tx['device_vpn_active']:
            score += 15
            reasons.append("VPN active on unknown network")

        final_score = min(score, 100)

        # Policy Mapping
        if final_score >= 85 or tx['device_root_status'] == 'compromised':
            auth_tier = "Blocked (Critical Threat)"
            action = "BLOCK_TRANSACTION"
        elif final_score >= 60:
            auth_tier = "Out-of-Band MFA / SMS OTP Required"
            action = "STEP_UP_HIGH"
        elif final_score >= 25:
            auth_tier = "Biometric Auth Needed (Fingerprint/Face ID)"
            action = "STEP_UP_MEDIUM"
        else:
            auth_tier = "Silent / Instant Approval"
            action = "ALLOW_SILENT"

        return {
            "risk_score": final_score,
            "auth_tier": auth_tier,
            "action": action,
            "triggered_rules": ", ".join(reasons) if reasons else "Normal behavioral baseline"
        }


def build_hashed_csv(df, audit_cols):
    """Attaches chained SHA-256 hashes exclusively to the exported CSV audit file."""
    export_df = df[audit_cols + ["user_id"]].copy()
    prev_hashes = []
    record_hashes = []
    prev_hash = "GENESIS_0000000000000000"

    for _, row in export_df.iterrows():
        prev_hashes.append(prev_hash)
        payload = {
            "tx_id": str(row["tx_id"]),
            "user_id": str(row["user_id"]),
            "timestamp": str(row["timestamp"]),
            "amount": float(row["amount"]),
            "location": str(row["location"]),
            "device_root_status": str(row["device_root_status"]),
            "risk_score": int(row["risk_score"]),
            "triggered_rules": str(row["triggered_rules"]),
            "status": str(row["status"]),
            "prev_hash": str(prev_hash)
        }
        canonical_str = json.dumps(payload, sort_keys=True)
        curr_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        record_hashes.append(curr_hash)
        prev_hash = curr_hash

    export_df["prev_hash"] = prev_hashes
    export_df["sha256_hash"] = record_hashes
    return export_df.to_csv(index=False).encode("utf-8")


def save_to_history(record):
    for i, existing in enumerate(st.session_state.history):
        if existing["tx_id"] == record["tx_id"]:
            st.session_state.history[i] = record
            return
    st.session_state.history.append(record)


# --- Session State Initialization ---
st.set_page_config(page_title="KES Mobile Wallet RBA", layout="wide")

if "user_id" not in st.session_state:
    st.session_state.user_id = "User_9921"
if "balance" not in st.session_state:
    st.session_state.balance = 20000.0
if "history" not in st.session_state:
    st.session_state.history = []
if "pending_tx" not in st.session_state:
    st.session_state.pending_tx = None

engine = RiskEngine()

st.title("Mobile Wallet Transaction RBA Prototype")

# Header Metrics
col1, col2 = st.columns(2)
col1.metric(label="Active User Identifier", value=st.session_state.user_id)
col2.metric(label="Current Wallet Balance", value=f"KSh {st.session_state.balance:,.2f}")

# Sidebar Context Simulator & Demo Reset Controls
st.sidebar.header("Device & Context Simulator")
location = st.sidebar.selectbox("Current Location", ["Home", "Office", "Local Grocery", "Coffee Shop", "Suspicious IP Address"])
vpn_active = st.sidebar.checkbox("VPN Active", value=False)
root_status = st.sidebar.selectbox("Device Integrity", ["secure", "compromised"])
hour = st.sidebar.slider("Simulated Hour of Day (0 - 23)", 0, 23, 15)

st.sidebar.divider()
st.sidebar.subheader("Demo Controls")
if st.sidebar.button("Reset Wallet & History", type="secondary", use_container_width=True):
    st.session_state.balance = 20000.0
    st.session_state.history = []
    st.session_state.pending_tx = None
    st.rerun()

# 1. Initiate Transaction
st.subheader("1. Initiate Transaction")
with st.form("tx_form"):
    description = st.text_input("Description", value="Local grocery checkout")
    amount = st.number_input("Amount (KSh)", min_value=10.0, value=250.0, step=50.0)
    submitted = st.form_submit_button("Submit Transaction")

if submitted:
    tx = {
        "tx_id": f"TX_{len(st.session_state.history) + 1:03d}",
        "user_id": st.session_state.user_id,
        "timestamp": f"{hour:02d}:{datetime.now().strftime('%M:%S')}",
        "amount": float(amount),
        "location": location,
        "hour": hour,
        "device_root_status": root_status,
        "device_vpn_active": vpn_active,
        "description": description
    }
    eval_res = engine.evaluate_transaction(tx)
    record = {**tx, **eval_res}

    if record["action"] == "ALLOW_SILENT":
        if st.session_state.balance >= amount:
            st.session_state.balance -= amount
            record["status"] = "SUCCESS (Silent)"
            save_to_history(record)
            st.success(f"Approved silently! Risk Score: {record['risk_score']}")
        else:
            record["status"] = "FAILED (Insufficient Funds)"
            save_to_history(record)
            st.error("Insufficient funds.")
        st.session_state.pending_tx = None

    elif record["action"] == "BLOCK_TRANSACTION":
        record["status"] = "BLOCKED (Critical Risk)"
        save_to_history(record)
        st.session_state.pending_tx = None
        st.error(f"Transaction Blocked! Score: {record['risk_score']} | Reasons: {record['triggered_rules']}")

    else:
        if st.session_state.balance >= amount:
            record["status"] = f"PENDING ({record['auth_tier']})"
            save_to_history(record)
            st.session_state.pending_tx = record
            st.warning(f"Step-Up Required! Score: {record['risk_score']} | Reasons: {record['triggered_rules']}")
        else:
            record["status"] = "FAILED (Insufficient Funds)"
            save_to_history(record)
            st.error("Insufficient funds.")

# 2. Step-Up Authentication Challenge
if st.session_state.pending_tx:
    st.subheader("2. Step-Up Authentication Challenge")
    ptx = st.session_state.pending_tx
    st.info(f"Action Required: **{ptx['auth_tier']}** for KSh {ptx['amount']:,.2f} ({ptx['tx_id']})")

    col_auth, col_cancel = st.columns(2)
    with col_auth:
        if ptx["action"] == "STEP_UP_MEDIUM":
            if st.button("Simulate Biometric Scan (Fingerprint / Face ID)"):
                st.session_state.balance -= ptx["amount"]
                ptx["status"] = "SUCCESS (Biometric Verified)"
                save_to_history(ptx)
                st.session_state.pending_tx = None
                st.rerun()
        elif ptx["action"] == "STEP_UP_HIGH":
            otp = st.text_input("Enter 6-Digit SMS OTP (Use test code: 123456)")
            if st.button("Verify OTP"):
                if otp == "123456":
                    st.session_state.balance -= ptx["amount"]
                    ptx["status"] = "SUCCESS (MFA/OTP Verified)"
                    save_to_history(ptx)
                    st.session_state.pending_tx = None
                    st.rerun()
                else:
                    st.error("Invalid OTP code. Try 123456.")
    with col_cancel:
        if st.button("Cancel Transaction"):
            ptx["status"] = "CANCELLED (User Aborted)"
            save_to_history(ptx)
            st.session_state.pending_tx = None
            st.rerun()

# 3. Prototype Telemetry Journal & Security Monitoring
if st.session_state.history:
    st.subheader("3. Prototype Telemetry Journal & Security Monitoring")
    df = pd.DataFrame(st.session_state.history)
    audit_cols = ["tx_id", "timestamp", "amount", "location", "device_root_status", "risk_score", "triggered_rules", "status"]

    flagged_df = df[df["status"].str.contains("PENDING|BLOCKED", na=False) | (df["device_root_status"] == "compromised")]

    tab_all, tab_alerts = st.tabs([f"All Transactions ({len(df)})", f"Security Operator Alerts ({len(flagged_df)})"])

    with tab_all:
        st.dataframe(df[audit_cols], use_container_width=True)

    with tab_alerts:
        if not flagged_df.empty:
            st.warning(f"Active Investigation Queue: {len(flagged_df)} flagged event(s) require operator review.")
            st.dataframe(flagged_df[audit_cols], use_container_width=True)
        else:
            st.success("No high-risk anomalies, pending step-ups, or compromised devices detected.")

    # CSV Audit Log Export (SHA-256 included exclusively in downloaded CSV)
    csv_data = build_hashed_csv(df, audit_cols)
