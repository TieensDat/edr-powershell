import os
import json
from typing import Any, Dict, List, Optional, TypedDict

from dotenv import load_dotenv
from openai import OpenAI
from langgraph.graph import StateGraph, START, END

from prompts import SYSTEM_PROMPT, REPORT_INSTRUCTION
from tools import (
    read_events,
    read_cpp_log,
    infer_intent,
    generate_investigation_queries,
    filter_events,
    correlate_cpp_context,
    build_context,
)

load_dotenv()

DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash")
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
MAX_CONTEXT_EVENTS = int(os.environ.get("MAX_CONTEXT_EVENTS", "10"))
MAX_OUTPUT_TOKENS = int(os.environ.get("MAX_OUTPUT_TOKENS", "1600"))

print("[ENV] DEEPSEEK_API_KEY exists:", bool(os.environ.get("DEEPSEEK_API_KEY")))
print("[ENV] DEEPSEEK_MODEL:", DEEPSEEK_MODEL)
print("[ENV] DEEPSEEK_BASE_URL:", DEEPSEEK_BASE_URL)


class InvestigationState(TypedDict, total=False):
    question: str
    intent: str
    investigation: Dict[str, Any]
    all_events: List[Dict[str, Any]]
    cpp_records: List[Dict[str, Any]]
    selected_events: List[Dict[str, Any]]
    correlated_events: List[Dict[str, Any]]
    context: Dict[str, Any]
    answer: str
    error: str


def parse_intent_node(state: InvestigationState) -> InvestigationState:
    question = state.get("question", "")
    return {
        "intent": infer_intent(question),
    }


def generate_investigation_queries_node(state: InvestigationState) -> InvestigationState:
    question = state.get("question", "")
    intent = state.get("intent", "general_explain")

    investigation = generate_investigation_queries(question, intent)

    print("[QUERY PLAN]", json.dumps(investigation, ensure_ascii=False, indent=2))

    return {
        "investigation": investigation
    }


def load_python_events_node(state: InvestigationState) -> InvestigationState:
    events = read_events()

    if not events:
        return {
            "all_events": [],
            "error": "Không tìm thấy event nào trong edr_events.jsonl."
        }

    return {
        "all_events": events
    }


def load_cpp_log_node(state: InvestigationState) -> InvestigationState:
    cpp_records = read_cpp_log()
    return {
        "cpp_records": cpp_records
    }


def select_events_node(state: InvestigationState) -> InvestigationState:
    events = state.get("all_events", [])
    question = state.get("question", "")
    intent = state.get("intent", "general_explain")
    investigation = state.get("investigation", {})

    selected = filter_events(events, question, intent, investigation)

    if not selected:
        return {
            "selected_events": [],
            "error": "Không tìm thấy event phù hợp với câu hỏi."
        }

    return {
        "selected_events": selected
    }


def correlate_events_node(state: InvestigationState) -> InvestigationState:
    selected = state.get("selected_events", [])
    cpp_records = state.get("cpp_records", [])

    correlated = correlate_cpp_context(selected, cpp_records)

    return {
        "correlated_events": correlated
    }


def build_context_node(state: InvestigationState) -> InvestigationState:
    correlated = state.get("correlated_events", [])
    investigation = state.get("investigation", {})

    context = build_context(
        correlated,
        investigation=investigation,
        limit=MAX_CONTEXT_EVENTS
    )

    return {
        "context": context
    }


def generate_answer_node(state: InvestigationState) -> InvestigationState:
    if state.get("error"):
        return {
            "answer": state["error"]
        }

    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        return {
            "answer": (
                "Chưa cấu hình DEEPSEEK_API_KEY. "
                "Hãy đặt biến môi trường hoặc file .env trước khi chạy agent."
            )
        }

    question = state.get("question", "")
    intent = state.get("intent", "")
    context = state.get("context", {})

    client = OpenAI(
        api_key=api_key,
        base_url=DEEPSEEK_BASE_URL,
    )

    user_prompt = f"""
Câu hỏi người dùng:
{question}

Intent đã phân loại:
{intent}

Context log đã được truy xuất, lọc và tương quan từ Mini EDR:
{json.dumps(context, ensure_ascii=False, indent=2)}

Yêu cầu bắt buộc:
- Nếu câu hỏi có PID, thời gian, process, sensor, verdict hoặc keyword cụ thể, hãy nói rõ điều kiện đó đã được dùng để lọc log.
- Nếu câu hỏi có khoảng thời gian, hãy ghi rõ khoảng thời gian người dùng yêu cầu và khoảng thời gian thực tế của các event được tìm thấy.
- Không được tự đổi khoảng truy vấn. Nếu một phần khoảng thời gian không có event, hãy nói rõ.
- Chỉ giải thích các event có trong context.
- Không tự thêm event ngoài context.
- Nếu context có C++ context, hãy giải thích đường đi AMSI/C++/Python tương ứng.
- Nếu context không có C++ context, hãy nói không có dữ liệu C++ Agent tương ứng.
- Nếu context không có event TERMINATE thì không được nói hệ thống đã terminate.
- Nếu chỉ có ALERT thì kết luận là ALERT.
- Nếu dữ liệu chưa đủ, hãy nói rõ chưa đủ dữ liệu.
- Viết ngắn gọn, tối đa khoảng 900 từ.
- Không lặp toàn bộ JSON.

{REPORT_INSTRUCTION if intent in ["generate_report", "build_timeline"] else ""}

Hãy trả lời bằng tiếng Việt.
"""

    try:
        print("[LLM] Calling DeepSeek API...")
        print("[LLM] Model:", DEEPSEEK_MODEL)
        print("[LLM] Context event count:", context.get("event_count"))

        response = client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=MAX_OUTPUT_TOKENS,
        )

        print("[LLM] DeepSeek API response received.")
        print("[LLM] Usage:", getattr(response, "usage", None))

        return {
            "answer": response.choices[0].message.content
        }

    except Exception as e:
        print("[LLM ERROR]", e)
        return {
            "answer": f"Lỗi khi gọi DeepSeek API: {e}"
        }


def build_graph():
    graph = StateGraph(InvestigationState)

    graph.add_node("parse_intent", parse_intent_node)
    graph.add_node("generate_investigation_queries", generate_investigation_queries_node)
    graph.add_node("load_python_events", load_python_events_node)
    graph.add_node("load_cpp_log", load_cpp_log_node)
    graph.add_node("select_events", select_events_node)
    graph.add_node("correlate_events", correlate_events_node)
    graph.add_node("build_context", build_context_node)
    graph.add_node("generate_answer", generate_answer_node)

    graph.add_edge(START, "parse_intent")
    graph.add_edge("parse_intent", "generate_investigation_queries")
    graph.add_edge("generate_investigation_queries", "load_python_events")
    graph.add_edge("load_python_events", "load_cpp_log")
    graph.add_edge("load_cpp_log", "select_events")
    graph.add_edge("select_events", "correlate_events")
    graph.add_edge("correlate_events", "build_context")
    graph.add_edge("build_context", "generate_answer")
    graph.add_edge("generate_answer", END)

    return graph.compile()


compiled_graph = build_graph()


def ask_agent(question: str) -> str:
    result = compiled_graph.invoke({
        "question": question
    })

    return result.get("answer", "Không có câu trả lời.")    