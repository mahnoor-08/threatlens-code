"""
app.py

ThreatLens - Passive IP, Domain & URL Intelligence.

Responsible for:
- Streamlit UI and form handling
- Calling validation helpers from sources.py
- Iterating through SOURCES to collect evidence
- Building the Gemini prompt and calling Gemini
- Interpreting the Gemini response and rendering the verdict / AI insight
- Generic, source-agnostic rendering of evidence cards
- Application-level error handling
"""

from __future__ import annotations

import json
from typing import Any

import streamlit as st
from google import genai

from sources import SOURCES, validate_target


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

TARGET_TYPES = ["IP Address", "Domain", "URL"]
KNOWLEDGE_LEVELS = ["Beginner", "Intermediate", "Expert"]

VERDICT_DISPLAY = {
    "SAFE": ("🟢", "SAFE"),
    "SUSPICIOUS": ("🟠", "SUSPICIOUS"),
    "MALICIOUS": ("🔴", "MALICIOUS"),
    "UNKNOWN": ("⚪", "UNKNOWN"),
}

GEMINI_MODEL = "gemini-2.0-flash"

PLACEHOLDER_BY_TYPE = {
    "IP Address": "8.8.8.8",
    "Domain": "example.com",
    "URL": "https://example.com/login",
}


# --------------------------------------------------------------------------
# Gemini prompt construction & invocation
# --------------------------------------------------------------------------

def build_gemini_prompt(
    target: str,
    target_type: str,
    knowledge_level: str,
    source_results: dict[str, dict[str, Any]],
) -> str:
    """
    Build a Gemini prompt describing the target and all collected evidence.

    The prompt is generated generically from whatever is present in
    source_results, so newly registered sources are automatically included
    without any change to this function.
    """
    evidence_blob = json.dumps(source_results, indent=2, default=str)

    level_guidance = {
        "Beginner": (
            "Use plain language, avoid unnecessary jargon, and briefly explain "
            "any technical concept you must use."
        ),
        "Intermediate": (
            "Use moderate technical terminology. Discuss detection ratios, "
            "domain age, registrar information, reputation signals, and the "
            "limitations of the evidence."
        ),
        "Expert": (
            "Provide technically detailed analysis: detection consensus, "
            "reputation signals, registration metadata, confidence/uncertainty, "
            "conflicting source results, false-positive possibilities, "
            "limitations of the sources used, and indicators that would "
            "warrant further investigation."
        ),
    }[knowledge_level]

    return f"""You are a cybersecurity analyst assistant embedded in a passive
threat-intelligence tool called ThreatLens.

Target: {target}
Target type: {target_type}
Audience knowledge level: {knowledge_level}

You are given structured evidence collected from a set of intelligence
sources. Each entry is keyed by source name and follows this contract:
{{"source": str, "status": "success"|"error", "verdict": str, "summary": str, "details": dict}}

Evidence collected:
{evidence_blob}

Instructions:
- Analyze ONLY the evidence provided above. Never invent scan results, WHOIS
  records, reputation scores, or any other facts not present in the evidence.
- Clearly distinguish between what the evidence states (fact) and what you
  are inferring from it (inference).
- Explicitly acknowledge uncertainty where the evidence is thin, missing, or
  conflicting.
- Do not claim a target is definitively safe merely because no malicious
  indicators were found; absence of detection is not proof of safety.
- If different sources disagree or one source failed while another
  succeeded, explain what that means for the overall assessment.
- Mention relevant limitations of passive reputation/registration data.
- Provide actionable but safe advice appropriate to the audience's
  knowledge level (no active scanning or intrusive steps).
- {level_guidance}

Respond with a JSON object only, no markdown fences, matching exactly this
shape:
{{
  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN",
  "confidence": "Low" | "Medium" | "High",
  "explanation": "string, written for the specified knowledge level",
  "key_indicators": ["string", ...],
  "recommended_next_step": "string"
}}

If the evidence is insufficient or conflicting, prefer "UNKNOWN" over
inventing certainty.
"""


def call_gemini(prompt: str) -> dict[str, Any]:
    """
    Call the Gemini API with the given prompt and parse a JSON response.

    Raises on any failure; callers are expected to catch and handle errors.
    """
    api_key = st.secrets.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "Gemini API key is not configured. Add GEMINI_API_KEY to secrets."
        )

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
    )

    text = (response.text or "").strip()
    # Defensively strip markdown code fences if the model adds them anyway.
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()

    parsed = json.loads(text)

    verdict = str(parsed.get("verdict", "UNKNOWN")).upper()
    if verdict not in VERDICT_DISPLAY:
        verdict = "UNKNOWN"

    return {
        "verdict": verdict,
        "confidence": parsed.get("confidence", "Low"),
        "explanation": parsed.get("explanation", ""),
        "key_indicators": parsed.get("key_indicators", []) or [],
        "recommended_next_step": parsed.get("recommended_next_step", ""),
    }


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def collect_source_results(target: str, target_type: str) -> dict[str, dict[str, Any]]:
    """
    Iterate through every registered source and collect its normalized
    result. A failure in one source function must not crash the app or
    prevent other sources from running.
    """
    results: dict[str, dict[str, Any]] = {}
    for source_name, source_function in SOURCES.items():
        try:
            results[source_name] = source_function(target, target_type)
        except Exception as exc:  # a source must never crash the app
            results[source_name] = {
                "source": source_name,
                "status": "error",
                "verdict": "unknown",
                "summary": f"Unexpected error while querying {source_name}: {exc}",
                "details": {},
            }
    return results


def any_source_succeeded(source_results: dict[str, dict[str, Any]]) -> bool:
    return any(r.get("status") == "success" for r in source_results.values())


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def render_verdict_card(verdict: str, confidence: str) -> None:
    emoji, label = VERDICT_DISPLAY.get(verdict, VERDICT_DISPLAY["UNKNOWN"])
    st.markdown("#### Threat Assessment")
    with st.container(border=True):
        st.markdown(
            f"<div style='text-align:center; font-size:2rem;'>{emoji} "
            f"<strong>{label}</strong></div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"<div style='text-align:center; color:gray;'>Confidence: {confidence}</div>",
            unsafe_allow_html=True,
        )
    st.caption(
        "This assessment is based on limited passive evidence and may be "
        "incomplete or wrong. It is not a guarantee of safety or maliciousness."
    )


def render_ai_insight_card(insight: dict[str, Any]) -> None:
    st.markdown("#### AI Insight")
    with st.container(border=True):
        explanation = insight.get("explanation") or "No explanation was generated."
        st.write(explanation)

        indicators = insight.get("key_indicators") or []
        if indicators:
            st.markdown("**Key indicators**")
            for item in indicators:
                st.markdown(f"- {item}")

        next_step = insight.get("recommended_next_step")
        if next_step:
            st.markdown("**Recommended next step**")
            st.write(next_step)


def render_source_result(result: dict[str, Any]) -> None:
    """
    Generic renderer for a single normalized source result. Works for any
    source that follows the standard contract, including future sources
    added to SOURCES without any UI changes.
    """
    source_name = result.get("source", "Unknown source")
    status = result.get("status", "unknown")
    verdict = result.get("verdict", "unknown")
    summary = result.get("summary", "")
    details = result.get("details") or {}

    status_icon = "✅" if status == "success" else "⚠️"

    with st.container(border=True):
        st.markdown(f"**{source_name}**  {status_icon}")
        st.markdown(f"Status: `{status}` &nbsp;&nbsp; Verdict: `{verdict}`")
        if summary:
            st.write(summary)
        if details:
            with st.expander("Details"):
                st.json(details)


# --------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------

def render_header() -> None:
    st.set_page_config(page_title="ThreatLens", page_icon="🔎", layout="centered")
    st.title("ThreatLens")
    st.caption("Passive IP, Domain & URL Intelligence")
    st.write(
        "ThreatLens combines reputation and registration information from "
        "multiple sources, then uses AI to produce a plain-language security "
        "assessment. It performs passive lookups only — no active scanning."
    )


def render_input_form() -> tuple[bool, str, str, str]:
    with st.form("threatlens_form"):
        col1, col2 = st.columns(2)
        with col1:
            target_type = st.selectbox("Target type", TARGET_TYPES)
        with col2:
            knowledge_level = st.selectbox("Knowledge level", KNOWLEDGE_LEVELS, index=1)

        target = st.text_input(
            "Target",
            placeholder=PLACEHOLDER_BY_TYPE.get(target_type, ""),
        )
        submitted = st.form_submit_button("Analyze", type="primary")
    return submitted, target, target_type, knowledge_level


def run_analysis(target: str, target_type: str, knowledge_level: str) -> None:
    is_valid, error_message = validate_target(target, target_type)
    if not is_valid:
        st.error(f"Invalid input: {error_message}")
        return

    with st.spinner("Collecting intelligence..."):
        source_results = collect_source_results(target.strip(), target_type)

    if not any_source_succeeded(source_results):
        st.warning(
            "⚪ **UNKNOWN** — No intelligence source returned usable evidence "
            "for this target, so no reliable assessment can be made."
        )
        st.markdown("#### Source Results")
        for result in source_results.values():
            render_source_result(result)
        return

    with st.spinner("Generating AI assessment..."):
        try:
            prompt = build_gemini_prompt(
                target.strip(), target_type, knowledge_level, source_results
            )
            insight = call_gemini(prompt)
        except Exception as exc:
            st.error(f"AI analysis failed: {exc}")
            insight = None

    if insight is not None:
        render_verdict_card(insight["verdict"], insight["confidence"])
        render_ai_insight_card(insight)
    else:
        st.info(
            "AI insight is unavailable, but the underlying evidence collected "
            "below is still shown."
        )

    st.markdown("#### Source Results")
    for result in source_results.values():
        render_source_result(result)


def main() -> None:
    render_header()
    submitted, target, target_type, knowledge_level = render_input_form()
    if submitted:
        run_analysis(target, target_type, knowledge_level)


if __name__ == "__main__":
    main()
