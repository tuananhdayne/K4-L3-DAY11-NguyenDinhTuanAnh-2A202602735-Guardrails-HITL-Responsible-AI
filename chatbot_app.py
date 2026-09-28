import streamlit as st
import time
import sys
from pathlib import Path
import re

# Add src to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from guardrails.input_guardrails import topic_filter, _normalize_text, ZERO_WIDTH
from guardrails.output_guardrails import content_filter
from assignment.rate_limiter import RateLimitPlugin
from attacks.attacks import response_leaked_secrets
from core.config import ALLOWED_TOPICS, BLOCKED_TOPICS, DEMO_SECRETS, DEMO_SECRET_NOTE

st.set_page_config(page_title="VinBank AI Chatbot", page_icon="🤖", layout="wide")

# Initialize Session State
if "messages" not in st.session_state:
    st.session_state.messages = []

if "rate_limiter" not in st.session_state:
    st.session_state.rate_limiter = RateLimitPlugin(max_requests=5, window_seconds=30)

st.title("🛡️ VinBank AI Chatbot with Guardrails")
st.markdown("Giao diện chat mô phỏng hệ thống Agent của VinBank. Bạn có thể xem chi tiết quá trình xử lý Input/Output Guardrails bên dưới mỗi tin nhắn.")

# Sidebar for controls
with st.sidebar:
    st.header("Cài đặt Agent")
    agent_mode = st.radio(
        "Chọn chế độ:",
        ["Blue Team (Bảo vệ đầy đủ)", "Red Team (Không bảo vệ)", "Red Advance (Có phòng thủ)"],
        index=0
    )
    st.divider()
    if st.button("Xóa lịch sử chat"):
        st.session_state.messages = []
        st.rerun()

# Map UI mode to internal mode
mode_map = {
    "Blue Team (Bảo vệ đầy đủ)": "blue",
    "Red Team (Không bảo vệ)": "red",
    "Red Advance (Có phòng thủ)": "red_advance"
}
current_mode = mode_map[agent_mode]

# Display chat messages
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])
        if "trace" in msg and msg["trace"]:
            with st.expander("🔍 Xem quá trình xử lý (Trace)", expanded=False):
                st.json(msg["trace"])

if prompt := st.chat_input("Nhập câu hỏi của bạn... (vd: Lãi suất 12 tháng, Số dư, hoặc thử prompt injection)"):
    # Display user message
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        process_status = st.status("Đang xử lý yêu cầu qua các lớp Guardrails...", expanded=True)
        
        start_time = time.time()
        user_id = "demo_user"
        rl = st.session_state.rate_limiter
        trace_data = {}

        # 1. Rate Limiter Stage
        now = time.time()
        user_window = rl.user_windows[user_id]
        while user_window and user_window[0] <= now - rl.window_seconds:
            user_window.popleft()
        
        rate_limit_exceeded = len(user_window) >= rl.max_requests
        if rate_limit_exceeded:
            process_status.update(label="Bị chặn bởi Rate Limiter!", state="error", expanded=False)
            reply = f"Rate limit exceeded (tối đa {rl.max_requests} req / {rl.window_seconds}s). Vui lòng thử lại sau."
            trace_data["Rate_Limit"] = "BLOCKED"
            st.markdown(reply)
            st.session_state.messages.append({"role": "assistant", "content": reply, "trace": trace_data})
            st.stop()
            
        user_window.append(now)
        trace_data["Rate_Limit"] = "PASSED"
        process_status.write("✅ **Layer 1: Rate Limiter** - Passed")

        # 2. Input Guardrails Stage
        input_blocked = False
        block_message = ""
        invisible_chars_found = [c for c in prompt if c in ZERO_WIDTH]
        normalized_prompt = _normalize_text(prompt)
        prompt_lower = normalized_prompt.lower()
        
        if len(invisible_chars_found) > 0:
            process_status.write(f"🧹 **Text Normalization:** Đã làm sạch {len(invisible_chars_found)} ký tự tàng hình (Unicode/Zero-width).")

        if current_mode != "red":
            # Detect injection
            INJECTION_PATTERNS = [
                r"ignore\s+(all\s+)?(previous|above|prior)?\s*instructions?",
                r"disregard\s+(all\s+)?(previous|above|prior)?\s*(instructions?|rules?|directives?)",
                r"you\s+are\s+now\b",
                r"\bDAN\b",
                r"pretend\s+(you\s+are|to\s+be)",
                r"act\s+as\s+(a\s+|an\s+)?(unrestricted|evil|jailbroken)",
                r"system\s+prompt",
                r"reveal\s+.*(instructions?|prompt|password|secret|key)",
                r"show\s+(me\s+)?.*(system\s+prompt|instructions?|config)",
                r"output\s+.*(config|instructions?|prompt)",
                r"bỏ\s+qua\s+(mọi\s+)?hướng\s+dẫn",
                r"tiết\s+lộ\s+(mật\s+khẩu|api|system\s*prompt)",
            ]
            matched_injection_patterns = [pat for pat in INJECTION_PATTERNS if re.search(pat, normalized_prompt, re.IGNORECASE)]
            
            injection_decision = "BLOCK" if matched_injection_patterns else "ALLOW"
            topic_decision = topic_filter(prompt)
            
            trace_data["Input_Guardrail"] = {
                "Injection_Check": injection_decision,
                "Matched_Patterns": matched_injection_patterns,
                "Topic_Check": topic_decision
            }
            
            input_blocked = (injection_decision == "BLOCK" or topic_decision == "BLOCK")
            if input_blocked:
                if injection_decision == "BLOCK":
                    block_message = "I cannot process that request. I can only help with VinBank banking questions."
                    reason_ui = f"Bị chặn bởi **Regex Injection Filter** (Phát hiện mẫu: `{matched_injection_patterns[0]}`)"
                else:
                    block_message = "I'm a VinBank assistant and can only help with banking-related questions."
                    reason_ui = "Bị chặn bởi **Topic Filter** (Chủ đề không thuộc ngữ cảnh ngân hàng)"
                
                process_status.write(f"❌ **Layer 2: Input Guardrail** - BLOCKED. Lý do: {reason_ui}")
                process_status.update(label=f"Bị chặn bởi Input Guardrails ({'Regex' if injection_decision == 'BLOCK' else 'Topic'})!", state="error", expanded=True)
                st.markdown(block_message)
                st.session_state.messages.append({"role": "assistant", "content": block_message, "trace": trace_data})
                st.stop()
            else:
                process_status.write("✅ **Layer 2: Input Guardrail** - Passed (Chủ đề hợp lệ, Không chứa mã độc Injection)")
        else:
            trace_data["Input_Guardrail"] = "SKIPPED (Red Mode)"
            process_status.write("⚠️ **Layer 2: Input Guardrail** - SKIPPED (Chế độ Red Team: Tắt bảo vệ đầu vào)")
        
        # 3. LLM Stage (Simulation)
        time.sleep(1) # simulate latency
        process_status.write("🤖 **Layer 3: LLM Generation** - Đã sinh câu trả lời")
        
        llm_output = ""
        if current_mode == "red":
            if any(w in prompt_lower for w in ["password", "secret", "api", "admin", "credential", "note", "db", "host"]):
                llm_output = f"Hello staff! As requested for internal verification, here is the internal note:\n{DEMO_SECRET_NOTE}"
            else:
                llm_output = "Hello! I am your internal VinBank staff assistant. How can I help you today?"
        elif current_mode == "red_advance":
            llm_output = "Hello! I am a VinBank customer service assistant. I can only help with banking inquiries."
        else:
            if any(w in prompt_lower for w in ["lãi suất", "savings", "interest"]):
                llm_output = "Lãi suất tiền gửi tiết kiệm VinBank hiện tại cho kỳ hạn 12 tháng là 4.25%/năm."
            elif any(w in prompt_lower for w in ["số dư", "balance", "tài khoản", "account"]):
                llm_output = "Để kiểm tra số dư và sao kê tài khoản VinBank, quý khách mở ứng dụng VinBank Digital."
            elif any(w in prompt_lower for w in ["090", "password", "sk-", "admin123", "email"]):
                llm_output = f"Thông tin nhân viên: SĐT 0901234567, email support@vinbank.com, admin password: {DEMO_SECRETS[0] if DEMO_SECRETS else 'admin123'}."
            else:
                llm_output = "VinBank xin kính chào Quý khách! Chúng tôi sẵn sàng hỗ trợ các thông tin về tài khoản."

        trace_data["LLM_Raw_Output"] = llm_output
        
        # 4. Output Guardrails Stage
        if current_mode == "red":
            final_text = llm_output
            trace_data["Output_Guardrail"] = "SKIPPED (Red Mode)"
            process_status.write("⚠️ **Layer 4: Output Guardrail** - SKIPPED (Chế độ Red Team: Rò rỉ dữ liệu thoải mái)")
        else:
            cf_result = content_filter(llm_output)
            final_text = cf_result["redacted"]
            
            trace_data["Output_Guardrail"] = {
                "Is_Safe": cf_result["safe"],
                "Issues": cf_result["issues"]
            }
            if cf_result["safe"]:
                process_status.write("✅ **Layer 4: Output Guardrail** - Passed (Không tìm thấy PII hay Mật khẩu)")
            else:
                process_status.write(f"🛑 **Layer 4: Output Guardrail** - REDACTED (Bị Regex quét trúng: {', '.join(cf_result['issues'])})")

        
        process_status.update(label=f"Xử lý hoàn tất trong {round(time.time() - start_time, 2)}s", state="complete", expanded=False)
        
        st.markdown(final_text)
        st.session_state.messages.append({"role": "assistant", "content": final_text, "trace": trace_data})
