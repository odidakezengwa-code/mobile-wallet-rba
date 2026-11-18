import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
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

        # 3. Temporal Anomaly Vector (+20) -> Fixed to include 23:00 to 05:00
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

        # Policy Mapping (Section 2.4.2 + Critical Device Safeguard)
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


class MobileWallet:
    """Models Section 2.3 & 2.5: State persistence, telemetry, and transaction register."""
    def __init__(self, user_id="User_9921", initial_balance=20000.0):
        self.user_id = user_id
        self.balance = initial_balance
        self.history = []
        self.pending_tx = None

    def log_transaction(self, record):
        # Update existing pending record if it already exists in history
        for i, existing in enumerate(self.history):
            if existing["tx_id"] == record["tx_id"]:
                self.history[i] = record
                return
        self.history.append(record)

    def process_transaction(self, tx, engine):
        if self.balance < tx["amount"]:
            eval_res = engine.evaluate_transaction(tx)
            record = {**tx, **eval_res, "status": "FAILED (Insufficient Funds)"}
            self.log_transaction(record)
            return record

        eval_res = engine.evaluate_transaction(tx)
        record = {**tx, **eval_res}

        if record["action"] == "ALLOW_SILENT":
            self.balance -= tx["amount"]
            record["status"] = "SUCCESS (Silent)"
            self.pending_tx = None
        elif record["action"] == "BLOCK_TRANSACTION":
            record["status"] = "BLOCKED (Critical Risk)"
            self.pending_tx = None
        else:
            record["status"] = f"PENDING ({record['auth_tier']})"
            self.pending_tx = record

        # Log immediately so PENDING states are visible to security monitoring (Section 2.5 II)
        self.log_transaction(record)
        return record

    def complete_step_up(self, method_label):
        if not self.pending_tx:
            return False
        if self.balance >= self.pending_tx["amount"]:
            self.balance -= self.pending_tx["amount"]
            self.pending_tx["status"] = f"SUCCESS ({method_label})"
            self.log_transaction(self.pending_tx)
            self.pending_tx = None
            return True
        else:
            self.pending_tx["status"] = "FAILED (Insufficient Funds)"
            self.log_transaction(self.pending_tx)
            self.pending_tx = None
            return False


# --- Streamlit UI Initialization ---
st.set_page_config(page_title="KES Mobile Wallet RBA", layout="wide")

if "wallet" not in st.session_state:
    st.session_state.wallet = MobileWallet(user_id="User_9921", initial_balance=20000.0)

wallet = st.session_state.wallet
engine = RiskEngine()

st.title("Mobile Wallet Transaction RBA Prototype")

# Header Metrics (Section 2.3.1 Structural Attributes)
col1, col2 = st.columns(2)
col1.metric(label="Active User Identifier", value=wallet.user_id)
col2.metric(label="Current Wallet Balance", value=f"KSh {wallet.balance:,.2f}")

# Sidebar Context Simulator
st.sidebar.header("Device & Context Simulator")
location = st.sidebar.selectbox("Current Location", ["Home", "Office", "Local Grocery", "Coffee Shop", "Suspicious IP Address"])
vpn_active = st.sidebar.checkbox("VPN Active", value=False)
root_status = st.sidebar.selectbox("Device Integrity", ["secure", "compromised"])
hour = st.sidebar.slider("Simulated Hour of Day (0 - 23)", 0, 23, 15)

# 1. Initiate Transaction
st.subheader("1. Initiate Transaction")
with st.form("tx_form"):
    description = st.text_input("Description", value="Local grocery checkout")
    amount = st.number_input("Amount (KSh)", min_value=10.0, value=250.0, step=50.0)
    submitted = st.form_submit_button("Submit Transaction")

if submitted:
    tx = {
        "tx_id": f"TX_{len(wallet.history) + 1:03d}",
        "user_id": wallet.user_id,
        "timestamp": f"{hour:02d}:{datetime.now().strftime('%M:%S')}",
        "amount": float(amount),
        "location": location,
        "hour": hour,
        "device_root_status": root_status,
        "device_vpn_active": vpn_active,
        "description": description
    }
    record = wallet.process_transaction(tx, engine)

    if "SUCCESS" in record["status"]:
        st.success(f"Approved silently! Risk Score: {record['risk_score']}")
    elif "BLOCKED" in record["status"]:
        st.error(f"Transaction Blocked! Score: {record['risk_score']} | Reasons: {record['triggered_rules']}")
    elif "FAILED" in record["status"]:
        st.error("Insufficient funds.")
    else:
        st.warning(f"Step-Up Required! Score: {record['risk_score']} | Reasons: {record['triggered_rules']}")

# 2. Step-Up Authentication Challenge
if wallet.pending_tx:
    st.subheader("2. Step-Up Authentication Challenge")
    ptx = wallet.pending_tx
    st.info(f"Action Required: **{ptx['auth_tier']}** for KSh {ptx['amount']:,.2f} ({ptx['tx_id']})")

    col_auth, col_cancel = st.columns([3, 1])
    with col_auth:
        if ptx["action"] == "STEP_UP_MEDIUM":
            if st.button("Simulate Biometric Scan (Fingerprint / Face ID)"):
                wallet.complete_step_up("Biometric Verified")
                st.rerun()
        elif ptx["action"] == "STEP_UP_HIGH":
            otp = st.text_input("Enter 6-Digit SMS OTP (Use test code: 123456)")
            if st.button("Verify OTP"):
                if otp == "123456":
                    wallet.complete_step_up("MFA/OTP Verified")
                    st.rerun()
                else:
                    st.error("Invalid OTP code. Try 123456.")
    with col_cancel:
        if st.button("Cancel Transaction"):
            ptx["status"] = "CANCELLED (User Aborted)"
            wallet.log_transaction(ptx)
            wallet.pending_tx = None
            st.rerun()

# 3. Prototype Telemetry Journal (Section 2.5 Full Audit Footprint)
if wallet.history:
    st.subheader("3. Prototype Telemetry Journal & Security Monitoring")
    df = pd.DataFrame(wallet.history)
    audit_cols = [
        "tx_id", "timestamp", "amount", "location",
        "device_root_status", "risk_score", "triggered_rules", "status"
    ]
    st.dataframe(df[audit_cols], use_container_width=True)

    # 4. Risk Diagnostics
    st.subheader("4. Risk Diagnostics Across Events")
    sns.set_theme(style="whitegrid")
    fig, ax = plt.subplots(figsize=(8, 3.5))
    sns.barplot(x="tx_id", y="risk_score", data=df, hue="tx_id", palette="RdYlGn_r", legend=False, ax=ax)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Evaluated Threat Index (0 - 100)")
    ax.set_xlabel("Transaction ID")
    for p in ax.patches:
        ax.annotate(f"{p.get_height():.0f}", (p.get_x() + p.get_width() / 2., p.get_height() + 2), ha="center", fontweight="bold")
    st.pyplot(fig)
