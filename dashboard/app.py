import os
import json
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple
import streamlit as st
import pandas as pd

# Optional Plotly import with fallback
try:
    import plotly.express as px
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

# Database and HTTP clients
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

import requests

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="Shadow AI & DLP Governance Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Configuration from Environment (Docker Compose)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://admin:secret@db:5432/shadow_ai")
JUDGE_URL = os.getenv("JUDGE_URL", "http://judge:8000")

# Security Policy Signatures Reference
BLOCK_PATTERNS = {
    # Credentials & Hard Secrets
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "API Secret Key": r"sk-[a-zA-Z0-9]{20,}",
    "Private Key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Database URL": r"(?:postgres|mysql|mongodb)://[^\s]+:[^\s]+@[^\s]+",

    # Prompt Injection & Jailbreak Defense
    "Prompt Injection (Instruction Override)": r"(?i)(?:ignore|disregard|forget|bypass)\s+...instructions",
    "Prompt Injection (System Prompt Leak)": r"(?i)(?:reveal|show|display|output|print)\s+...system prompt",
    "Prompt Injection (Jailbreak Persona)": r"(?i)\b(?:DAN mode|jailbreak|do anything now|unrestricted ai)\b",
    "Prompt Injection (Roleplay Exploit)": r"(?i)(?:pretend you have no rules|act as unfiltered)",
}

REDACT_PATTERNS = {
    "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "AMKA (Greek Social Security)": r"\b\d{6}[-\s]?\d{5}\b (11 digits: DDMMYYXXXXX)",
    "AFM (Greek Tax ID)": r"\b\d{9}\b (9 digits / ΑΦΜ)",
    "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "PHONE": r"\b(?:\+?30[-.\s]?)?[26]\d{9}\b (Greek landline / mobile)",
}

BLOCKED_AI_DOMAINS = [
    "chatgpt.com",
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "perplexity.ai",
    "poe.com",
    "deepseek.com",
]


# ---------------------------------------------------------
# Data Layer: Fetch from PostgreSQL or Judge API
# ---------------------------------------------------------
def get_db_connection():
    if not HAS_PSYCOPG2:
        return None
    try:
        return psycopg2.connect(DATABASE_URL, connect_timeout=3)
    except Exception:
        try:
            local_url = DATABASE_URL.replace("@db:", "@localhost:")
            return psycopg2.connect(local_url, connect_timeout=2)
        except Exception:
            return None


def fetch_incidents(limit=1000) -> Tuple[List[Dict[str, Any]], str]:
    # 1. Try Direct PostgreSQL Connection
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM incident_logs ORDER BY timestamp DESC LIMIT %s;",
                    (limit,),
                )
                rows = cur.fetchall()
                results = []
                for r in rows:
                    item = dict(r)
                    if isinstance(item.get("timestamp"), datetime):
                        item["timestamp"] = item["timestamp"].isoformat()
                    if isinstance(item.get("findings"), str):
                        try:
                            item["findings"] = json.loads(item["findings"])
                        except Exception:
                            item["findings"] = [item["findings"]]
                    elif item.get("findings") is None:
                        item["findings"] = []
                    results.append(item)
                conn.close()
                return results, "PostgreSQL (db:5432)"
        except Exception:
            conn.close()

    # 2. Try Judge API HTTP
    for base_url in [JUDGE_URL, "http://localhost:8000"]:
        try:
            resp = requests.get(f"{base_url}/logs?limit={limit}", timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                logs = data.get("logs", [])
                for item in logs:
                    if isinstance(item.get("findings"), str):
                        try:
                            item["findings"] = json.loads(item["findings"])
                        except Exception:
                            item["findings"] = [item["findings"]]
                return logs, f"Judge API ({base_url})"
        except Exception:
            pass

    # 3. In-session logs if running standalone
    if "session_logs" not in st.session_state:
        st.session_state["session_logs"] = []
    return st.session_state["session_logs"], "Session Storage"


def clear_all_records():
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE incident_logs;")
                conn.commit()
            conn.close()
        except Exception:
            conn.close()
    st.session_state["session_logs"] = []


# ---------------------------------------------------------
# Sidebar Controls & Filters
# ---------------------------------------------------------
with st.sidebar:
    st.image(
        "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/shield/materialicons/48dp/2x/baseline_shield_black_48dp.png",
        width=48,
    )
    st.title("Governance Console")
    st.caption("Corporate AI Security & Audit Operations")
    st.divider()

    # Load live records
    incidents, conn_source = fetch_incidents(limit=1000)

    # Connection Badge
    if "PostgreSQL" in conn_source:
        st.success(f"🟢 **Connected:** {conn_source}")
    elif "Judge API" in conn_source:
        st.info(f"🟡 **Connected:** {conn_source}")
    else:
        st.warning(f"⚪ **Status:** {conn_source}")

    st.caption(f"Total Incident Records: **{len(incidents)}**")

    # Refresh
    col_ref1, col_ref2 = st.columns([1, 1])
    with col_ref1:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
    with col_ref2:
        auto_ref = st.checkbox("Live Poll", value=False)

    if auto_ref:
        st.caption("Auto-polling every 5s...")
        import time
        time.sleep(5)
        st.rerun()

    st.divider()
    st.subheader("🔍 Filter Incidents")

    # Time Filter
    selected_time = st.selectbox(
        "⏱️ Time Range:",
        ["All Time", "Last 15 Minutes", "Last 1 Hour", "Today (Since 00:00)"],
        index=0,
    )

    # Action Filter
    selected_action = st.selectbox(
        "Action Status:",
        ["ALL", "BLOCK", "REDACT", "ALLOW"],
        index=0,
    )

    # User Filter
    all_users = sorted(list(set(i.get("username", "anonymous") for i in incidents)))
    selected_users = st.multiselect("Filter by User:", all_users, default=[])

    # Finding Filter
    all_findings_set = set()
    for inc in incidents:
        f_list = inc.get("findings", [])
        if isinstance(f_list, list):
            for f in f_list:
                all_findings_set.add(f)
    selected_findings = st.multiselect("Filter by Finding:", sorted(list(all_findings_set)), default=[])

    # Keyword Search
    search_query = st.text_input("Search Prompt Text:", placeholder="Keyword, IP, pattern...")

    st.divider()
    st.subheader("📥 Export & Compliance")
    if incidents:
        csv_data = pd.DataFrame(incidents).to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Export Compliance Audit CSV",
            data=csv_data,
            file_name=f"shadow_ai_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    st.subheader("⚙️ Maintenance")
    if st.button("🗑️ Clear All Incident Logs", use_container_width=True):
        clear_all_records()
        st.warning("Cleared all incident logs.")
        st.rerun()


# ---------------------------------------------------------
# Filter Dataset
# ---------------------------------------------------------
filtered_incidents = []
now_utc = datetime.now(timezone.utc)

for inc in incidents:
    action = inc.get("action", "ALLOW")
    user = inc.get("username", "anonymous")
    prompt = str(inc.get("original_prompt", ""))
    ts_str = str(inc.get("timestamp", ""))
    f_list = inc.get("findings", [])
    if not isinstance(f_list, list):
        f_list = [str(f_list)]

    # Time Filter
    if ts_str and selected_time != "All Time":
        try:
            inc_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            diff_sec = (now_utc - inc_dt).total_seconds()
            if selected_time == "Last 15 Minutes" and diff_sec > 15 * 60:
                continue
            elif selected_time == "Last 1 Hour" and diff_sec > 60 * 60:
                continue
            elif selected_time == "Today (Since 00:00)" and inc_dt.date() != now_utc.date():
                continue
        except Exception:
            pass

    if selected_action != "ALL" and action != selected_action:
        continue
    if selected_users and user not in selected_users:
        continue
    if selected_findings and not any(sf in f_list for sf in selected_findings):
        continue
    if search_query and (search_query.lower() not in prompt.lower() and search_query.lower() not in user.lower() and search_query.lower() not in str(inc.get("client_ip", "")).lower()):
        continue

    filtered_incidents.append(inc)

df_all = pd.DataFrame(incidents) if incidents else pd.DataFrame()
df_filtered = pd.DataFrame(filtered_incidents) if filtered_incidents else pd.DataFrame()

# ---------------------------------------------------------
# Main UI Header
# ---------------------------------------------------------
st.title("🛡️ Shadow AI & DLP Governance Dashboard")
st.markdown(
    "Central security console monitoring prompts routed from **Employee Workstations (`host:8501`)** through the **AI Gateway (`judge:8000`)**."
)

# Executive KPI Cards
total_count = len(incidents)
block_count = sum(1 for i in incidents if i.get("action") == "BLOCK")
redact_count = sum(1 for i in incidents if i.get("action") == "REDACT")
allow_count = sum(1 for i in incidents if i.get("action") == "ALLOW")
injection_count = sum(1 for i in incidents if any("Prompt Injection" in str(f) for f in i.get("findings", [])))
flagged_users = len(set(i.get("username") for i in incidents if i.get("action") in ["BLOCK", "REDACT"]))

block_pct = (block_count / total_count * 100) if total_count > 0 else 0
redact_pct = (redact_count / total_count * 100) if total_count > 0 else 0
allow_pct = (allow_count / total_count * 100) if total_count > 0 else 0

kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)
with kpi1:
    st.metric("Total Inspected", f"{total_count}", help="Prompts received by the AI Gateway")
with kpi2:
    st.metric("Critical Blocked", f"{block_count}", f"{block_pct:.1f}%", delta_color="inverse", help="Hard secrets & DNS violations blocked with 403")
with kpi3:
    st.metric("Injections Halted", f"{injection_count}", help="Adversarial prompt injection & jailbreak attacks")
with kpi4:
    st.metric("PII Redacted", f"{redact_count}", f"{redact_pct:.1f}%", delta_color="off", help="Prompts sanitized before reaching the model")
with kpi5:
    st.metric("Compliant Allowed", f"{allow_count}", f"{allow_pct:.1f}%", help="Clean requests forwarded as-is")
with kpi6:
    st.metric("Flagged Users", f"{flagged_users}", help="Unique employee accounts involved in policy violations")

st.divider()

# ---------------------------------------------------------
# Tabs Navigation
# ---------------------------------------------------------
tab_analytics, tab_logs, tab_policies = st.tabs([
    "📊 Threat Analytics & Trends",
    "📋 Real-Time Incident Stream",
    "📜 Active Policies & Architecture",
])

# ---------------------------------------------------------
# TAB 1: THREAT ANALYTICS
# ---------------------------------------------------------
with tab_analytics:
    if total_count == 0:
        st.info("No incident records yet. Send a prompt from the **Employee Workstation (`http://localhost:8501`)** to see live analytics.")
    else:
        chart_col1, chart_col2 = st.columns([1, 1])

        with chart_col1:
            st.markdown("#### 🎯 Incident Actions Distribution")
            action_counts = {
                "BLOCK": block_count,
                "REDACT": redact_count,
                "ALLOW": allow_count,
            }
            if HAS_PLOTLY:
                fig_action = px.pie(
                    names=list(action_counts.keys()),
                    values=list(action_counts.values()),
                    hole=0.45,
                    color=list(action_counts.keys()),
                    color_discrete_map={
                        "BLOCK": "#EF4444",
                        "REDACT": "#F59E0B",
                        "ALLOW": "#10B981",
                    },
                )
                fig_action.update_traces(textposition='inside', textinfo='percent+label')
                fig_action.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=300)
                st.plotly_chart(fig_action, use_container_width=True)
            else:
                st.bar_chart(pd.DataFrame.from_dict(action_counts, orient="index", columns=["Count"]))

        with chart_col2:
            st.markdown("#### 🚨 Top Detected Vulnerabilities & Findings")
            findings_counter: Dict[str, int] = {}
            for inc in incidents:
                f_list = inc.get("findings", [])
                if isinstance(f_list, list):
                    for f in f_list:
                        findings_counter[f] = findings_counter.get(f, 0) + 1

            if findings_counter:
                df_findings = pd.DataFrame(
                    list(findings_counter.items()), columns=["Vulnerability / Finding", "Occurrences"]
                ).sort_values("Occurrences", ascending=True)

                if HAS_PLOTLY:
                    fig_findings = px.bar(
                        df_findings,
                        x="Occurrences",
                        y="Vulnerability / Finding",
                        orientation="h",
                        color="Occurrences",
                        color_continuous_scale="Reds",
                    )
                    fig_findings.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=300, coloraxis_showscale=False)
                    st.plotly_chart(fig_findings, use_container_width=True)
                else:
                    st.bar_chart(df_findings.set_index("Vulnerability / Finding"))
            else:
                st.caption("No specific findings detected across logs.")

        st.divider()

        row2_col1, row2_col2 = st.columns([1, 1])

        with row2_col1:
            st.markdown("#### 👥 Top Users by Policy Violations")
            user_violations: Dict[str, int] = {}
            for inc in incidents:
                if inc.get("action") in ["BLOCK", "REDACT"]:
                    u = inc.get("username", "anonymous")
                    user_violations[u] = user_violations.get(u, 0) + 1

            if user_violations:
                df_users = pd.DataFrame(
                    list(user_violations.items()), columns=["User", "Violations"]
                ).sort_values("Violations", ascending=False)
                if HAS_PLOTLY:
                    fig_user = px.bar(
                        df_users,
                        x="User",
                        y="Violations",
                        color="Violations",
                        color_continuous_scale="Oranges",
                    )
                    fig_user.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=300, coloraxis_showscale=False)
                    st.plotly_chart(fig_user, use_container_width=True)
                else:
                    st.bar_chart(df_users.set_index("User"))
            else:
                st.caption("No user policy violations recorded.")

        with row2_col2:
            st.markdown("#### ⏱️ Threat Activity Timeline")
            try:
                timeline_data = []
                for inc in incidents:
                    ts_str = inc.get("timestamp")
                    if ts_str:
                        clean_ts = ts_str.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(clean_ts)
                        timeline_data.append({
                            "Time": dt.strftime("%H:%M:%S"),
                            "Action": inc.get("action", "ALLOW"),
                            "Count": 1,
                        })
                if timeline_data:
                    df_time = pd.DataFrame(timeline_data)
                    df_pivot = df_time.pivot_table(index="Time", columns="Action", values="Count", aggfunc="sum", fill_value=0)
                    if HAS_PLOTLY:
                        fig_time = px.line(
                            df_pivot,
                            color_discrete_map={"BLOCK": "#EF4444", "REDACT": "#F59E0B", "ALLOW": "#10B981"}
                        )
                        fig_time.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=300)
                        st.plotly_chart(fig_time, use_container_width=True)
                    else:
                        st.line_chart(df_pivot)
                else:
                    st.caption("No timestamp data available.")
            except Exception as e:
                st.caption(f"Timeline format notice: {e}")


# ---------------------------------------------------------
# TAB 2: INCIDENT LOG EXPLORER & DEEP INSPECTOR
# ---------------------------------------------------------
with tab_logs:
    st.markdown(f"### 📋 Incident Stream ({len(filtered_incidents)} of {len(incidents)} shown)")

    if not filtered_incidents:
        st.warning("No incidents match current filter criteria. Send prompts via Workstation (`host:8501`) to view live streams.")
    else:
        table_rows = []
        for inc in filtered_incidents:
            act = inc.get("action", "ALLOW")
            is_inj = any("Prompt Injection" in str(f) for f in inc.get("findings", []))
            if act == "BLOCK":
                badge = "🟣 BLOCK (INJECTION)" if is_inj else "🔴 BLOCK"
            elif act == "REDACT":
                badge = "🟡 REDACT"
            else:
                badge = "🟢 ALLOW"

            f_str = ", ".join(inc.get("findings", [])) if inc.get("findings") else "—"
            prompt_preview = str(inc.get("original_prompt", ""))
            if len(prompt_preview) > 65:
                prompt_preview = prompt_preview[:62] + "..."

            table_rows.append({
                "ID": inc.get("id"),
                "Time": inc.get("timestamp", "")[:19].replace("T", " "),
                "User": inc.get("username", "anonymous"),
                "IP Address": inc.get("client_ip", "unknown"),
                "Status": badge,
                "Detected Findings": f_str,
                "Prompt Preview": prompt_preview,
            })

        df_display = pd.DataFrame(table_rows)
        st.dataframe(df_display, use_container_width=True, hide_index=True)

        st.divider()

        # Detailed Row Inspector
        st.markdown("#### 🔬 Deep Incident Inspector (Prompt Diff)")
        incident_ids = [str(inc.get("id")) for inc in filtered_incidents]
        selected_id_str = st.selectbox("Select Incident ID to Inspect:", incident_ids, index=0)

        selected_inc = next((i for i in filtered_incidents if str(i.get("id")) == selected_id_str), None)

        if selected_inc:
            action_val = selected_inc.get("action", "ALLOW")
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.write(f"**Incident ID:** `#{selected_inc.get('id')}`")
            with c2:
                st.write(f"**Timestamp:** `{selected_inc.get('timestamp')}`")
            with c3:
                st.write(f"**Employee:** `{selected_inc.get('username')}` ({selected_inc.get('client_ip')})")
            with c4:
                if action_val == "BLOCK":
                    st.error("🛑 Action: **BLOCKED (403)**")
                elif action_val == "REDACT":
                    st.warning("⚠️ Action: **REDACTED & FORWARDED**")
                else:
                    st.success("✅ Action: **ALLOWED AS-IS**")

            findings_list = selected_inc.get("findings", [])
            if findings_list:
                st.markdown(f"**Detected Threat Signatures:** `{', '.join(findings_list)}`")

            comp1, comp2 = st.columns(2)
            with comp1:
                st.markdown("##### 📥 Original Employee Input (Prompt)")
                st.code(selected_inc.get("original_prompt", ""), language="text")
            with comp2:
                st.markdown("##### 📤 Forwarded to LLM (Sanitized)")
                if action_val == "BLOCK":
                    st.error("⛔ PROMPT WAS BLOCKED - NEVER REACHED THE LLM")
                    st.caption("Perimeter security policy terminated the request at the gateway.")
                else:
                    st.code(selected_inc.get("forwarded_prompt", ""), language="text")

            llm_reply = selected_inc.get("response")
            if llm_reply:
                st.markdown("##### 🤖 Gemini LLM Response")
                if action_val == "BLOCK":
                    st.warning(llm_reply)
                else:
                    st.success(llm_reply)


# ---------------------------------------------------------
# TAB 3: ACTIVE POLICIES & ARCHITECTURE
# ---------------------------------------------------------
with tab_policies:
    st.markdown("### 📜 Corporate AI Security Policies & Architecture")
    st.markdown("The system separates concerns across dedicated containers in `compose.yaml`:")

    col_pol1, col_pol2 = st.columns(2)

    with col_pol1:
        st.markdown("#### 🛑 High-Severity Block Rules (Hard Stop)")
        st.caption("Prompts matching these regular expressions are immediately blocked with HTTP 403.")
        block_rules_data = []
        for name, pat in BLOCK_PATTERNS.items():
            block_rules_data.append({"Threat Type": name, "Signature Pattern": pat, "Action": "BLOCK"})
        st.table(pd.DataFrame(block_rules_data))

        st.markdown("#### ⚠️ Medium-Severity Redaction Rules (PII Masking)")
        st.caption("Prompts containing these patterns are sanitized with `[REDACTED_<LABEL>]` before reaching the LLM.")
        redact_rules_data = []
        for name, pat in REDACT_PATTERNS.items():
            redact_rules_data.append({"PII Type": name, "Signature Pattern": pat, "Action": "REDACT"})
        st.table(pd.DataFrame(redact_rules_data))

    with col_pol2:
        st.markdown("#### 🚫 Blocked Shadow AI Domains (DNS Sinkhole)")
        st.caption("Direct DNS queries from internal workstations to unauthorized consumer AI domains resolve to `0.0.0.0`.")
        domains_data = [{"Unauthorized AI Service": d, "Resolution Policy": "Sinkhole (0.0.0.0) + Webhook Alert"} for d in BLOCKED_AI_DOMAINS]
        st.table(pd.DataFrame(domains_data))

        st.markdown("#### 🏛️ Containerized Microservices Layout")
        st.markdown("""
        1. **`host` (`localhost:8501`)**: Employee laptop simulator on `corp_internal` isolated network.
        2. **`judge` (`localhost:8000`)**: Governed AI Gateway (`gpt.company.com:8000`) evaluating prompts via `dlp.py`.
        3. **`db` (`db:5432`)**: PostgreSQL 16 storing all audit trails in `incident_logs`.
        4. **`dashboard` (`localhost:8502`)**: Central security governance, analytics, and compliance export console.
        5. **`dnsBlocker` (`port 53/udp`)**: DNS Sinkhole catching rogue AI domain requests.
        """)

    st.divider()
    st.markdown("### ⚙️ Manager Policy Rule Editor (Dynamic DLP)")
    st.caption("Define custom corporate rules to **BLOCK** or **REDACT** proprietary information before prompts reach any AI model.")

    RULES_FILE_PATH = os.path.join(os.path.dirname(__file__), "..", "rules.json")

    def get_manager_rules():
        try:
            resp = requests.get(f"{JUDGE_URL}/rules", timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                if "rules" in data:
                    return data["rules"]
        except Exception:
            pass
        candidates = [RULES_FILE_PATH, os.path.join(os.getcwd(), "rules.json"), "/app/rules.json"]
        for p in candidates:
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass
        return []

    def save_manager_rules(rules):
        try:
            for r in rules:
                requests.post(f"{JUDGE_URL}/rules", json=r, timeout=1)
        except Exception:
            pass
        candidates = [RULES_FILE_PATH, os.path.join(os.getcwd(), "rules.json"), "/app/rules.json"]
        for p in candidates:
            try:
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(rules, f, indent=2, ensure_ascii=False)
                return True
            except Exception:
                pass
        return False

    with st.expander("➕ Deploy New Corporate Policy Rule", expanded=False):
        c_r1, c_r2 = st.columns([2, 1])
        with c_r1:
            nr_name = st.text_input("Policy / Threat Name", placeholder="e.g. Confidential Project Titan")
        with c_r2:
            nr_action = st.selectbox("Action", ["BLOCK", "REDACT"], index=0)

        nr_pattern = st.text_input("Match Pattern / Keyword (Regex supported)", placeholder="e.g. (?i)\\bProject\\s*Titan\\b or confidential-keyword")
        nr_desc = st.text_input("Description", placeholder="e.g. Prevents leaking unannounced internal project details")

        if st.button("🚀 Deploy Rule to Gateway", type="primary"):
            if nr_name and nr_pattern:
                try:
                    re.compile(nr_pattern)
                    curr_rules = get_manager_rules()
                    new_rule = {
                        "id": f"rule-{int(datetime.now().timestamp())}",
                        "name": nr_name,
                        "action": nr_action,
                        "pattern": nr_pattern,
                        "description": nr_desc,
                        "enabled": True,
                    }
                    curr_rules.append(new_rule)
                    save_manager_rules(curr_rules)
                    st.success(f"✅ Policy '{nr_name}' deployed to AI Gateway!")
                    st.rerun()
                except Exception as err:
                    st.error(f"Invalid pattern: {err}")
            else:
                st.warning("Please enter both Policy Name and Match Pattern.")

    curr_rules = get_manager_rules()
    if curr_rules:
        st.markdown("#### 📋 Corporate Policy Rules & Controls")
        st.caption("Managers can edit signatures, pause/enable rules temporarily, or delete obsolete policies.")

        if "editing_rule_id" not in st.session_state:
            st.session_state.editing_rule_id = None

        for idx, r in enumerate(curr_rules):
            r_id = r.get("id", f"rule-{idx}")
            is_enabled = r.get("enabled", True)
            action_badge = "🛑 BLOCK" if r.get("action") == "BLOCK" else "🟡 REDACT"
            status_badge = "🟢 ACTIVE" if is_enabled else "⏸️ PAUSED"

            col_info, col_actions = st.columns([2.5, 1.5])
            with col_info:
                st.markdown(f"**{r.get('name')}** &nbsp; `{action_badge}` &nbsp; `{status_badge}`")
                st.caption(f"Pattern: `{r.get('pattern')}` | {r.get('description', 'Custom DLP Rule')}")
            with col_actions:
                b1, b2, b3 = st.columns([1, 1, 1])
                with b1:
                    toggle_label = "⏸️ Pause" if is_enabled else "▶️ Enable"
                    if st.button(toggle_label, key=f"tog_{r_id}", use_container_width=True):
                        r["enabled"] = not is_enabled
                        save_manager_rules(curr_rules)
                        st.rerun()
                with b2:
                    if st.button("✏️ Edit", key=f"edit_{r_id}", use_container_width=True):
                        st.session_state.editing_rule_id = r_id
                        st.rerun()
                with b3:
                    if st.button("🗑️ Del", key=f"del_{r_id}", use_container_width=True):
                        updated = [x for x in curr_rules if x.get("id") != r_id]
                        save_manager_rules(updated)
                        if st.session_state.editing_rule_id == r_id:
                            st.session_state.editing_rule_id = None
                        st.rerun()

            # Inline Edit Form
            if st.session_state.editing_rule_id == r_id:
                with st.form(key=f"edit_form_{r_id}"):
                    st.markdown(f"**✏️ Edit Policy:** `{r.get('name')}`")
                    e1, e2 = st.columns([2, 1])
                    with e1:
                        ed_name = st.text_input("Policy Name", value=r.get("name", ""))
                    with e2:
                        ed_action = st.selectbox("Action", ["BLOCK", "REDACT"], index=0 if r.get("action") == "BLOCK" else 1)
                    ed_pattern = st.text_input("Match Pattern (Regex)", value=r.get("pattern", ""))
                    ed_desc = st.text_input("Description", value=r.get("description", ""))

                    fb1, fb2 = st.columns([1, 1])
                    with fb1:
                        if st.form_submit_button("💾 Save Changes", type="primary", use_container_width=True):
                            try:
                                re.compile(ed_pattern)
                                r["name"] = ed_name
                                r["action"] = ed_action
                                r["pattern"] = ed_pattern
                                r["description"] = ed_desc
                                save_manager_rules(curr_rules)
                                st.session_state.editing_rule_id = None
                                st.success("Policy updated!")
                                st.rerun()
                            except Exception as err:
                                st.error(f"Invalid regex pattern: {err}")
                    with fb2:
                        if st.form_submit_button("Cancel", use_container_width=True):
                            st.session_state.editing_rule_id = None
                            st.rerun()
            st.divider()
    else:
        st.info("No custom manager rules deployed yet. Use the form above to deploy one.")
