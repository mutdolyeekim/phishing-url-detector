
"""피싱 URL 탐지기: 사용자가 입력한 URL 문자열을 분류하는 Streamlit 앱."""

from pathlib import Path
from urllib.parse import urlsplit
import ipaddress

import joblib
import streamlit as st


# 페이지 설정
st.set_page_config(
    page_title="피싱 URL 탐지기",
    page_icon="🛡️",
    layout="centered",
)

MODEL_PATH = Path(__file__).resolve().parent / "phishing_url_model.joblib"


@st.cache_resource
def load_model():
    """직접 학습한 로컬 모델 파일을 불러옵니다."""
    return joblib.load(MODEL_PATH)


def normalize_url(value: str) -> str:
    value = value.strip()
    if value and "://" not in value:
        value = "https://" + value
    return value


def get_url_hints(url: str) -> list[str]:
    """모델의 예측과 별개로 URL 구조의 참고 사항을 확인합니다."""
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    hints = []

    if parsed.scheme == "http":
        hints.append("HTTPS가 아닌 HTTP 주소입니다. HTTP 자체가 피싱을 뜻하지는 않습니다.")

    try:
        ipaddress.ip_address(host)
        hints.append("도메인 이름 대신 IP 주소를 사용합니다.")
    except ValueError:
        pass

    if "@" in parsed.netloc:
        hints.append("URL 주소 부분에 @ 기호가 있습니다.")

    if len(url) > 100:
        hints.append("URL 길이가 100자를 넘습니다.")

    if any(part.startswith("xn--") for part in host.split(".")):
        hints.append("Punycode가 사용되었습니다. 정상적인 국제화 도메인에서도 쓰입니다.")

    if not hints:
        hints.append("특별한 구조적 경고 징후가 발견되지 않았지만, 안전을 보장하지는 않습니다.")

    return hints


# 화면 디자인: 큰 분석 버튼 + 하단 저작권
st.markdown(
    """
    <style>
        .st-key-analyze_url_button button {
            min-height: 76px !important;
            border-radius: 14px !important;
            font-weight: 800 !important;
            width: 100% !important;
        }
        .st-key-analyze_url_button button p {
            font-size: 24px !important;
            font-weight: 800 !important;
        }
        .app-copyright {
            text-align: center;
            font-size: 14px;
            color: #8c96a8;
            padding: 12px 0 8px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# 브라우저 클립보드 접근용 버튼 (Streamlit Components v2)
paste_button = st.components.v2.component(
    "phishing_url_clipboard_paste",
    html='<button type="button" id="paste-button">📋 붙여넣기</button>',
    css="""
        button {
            width: 100%;
            min-height: 41px;
            border-radius: 9px;
            border: 1px solid var(--st-primary-color);
            background: var(--st-secondary-background-color);
            color: var(--st-text-color);
            font-family: var(--st-font);
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
        }
        button:hover { opacity: 0.85; }
        button:focus-visible {
            outline: 2px solid var(--st-primary-color);
            outline-offset: 2px;
        }
    """,
    js="""
        export default function({ parentElement, setTriggerValue }) {
            const button = parentElement.querySelector('#paste-button');

            button.addEventListener('click', async () => {
                if (!navigator.clipboard?.readText) {
                    setTriggerValue('paste_error', '이 브라우저에서는 자동 붙여넣기를 지원하지 않습니다. Ctrl+V로 입력해 주세요.');
                    return;
                }
                try {
                    const value = (await navigator.clipboard.readText()).trim();
                    if (!value) {
                        setTriggerValue('paste_error', '클립보드에 복사된 내용이 없습니다.');
                        return;
                    }
                    setTriggerValue('pasted_url', value);
                } catch (error) {
                    setTriggerValue('paste_error', '클립보드 접근이 차단되었습니다. 브라우저 권한을 허용하거나 Ctrl+V를 이용해 주세요.');
                }
            });
        }
    """,
)


# 페이지 제목과 안내
st.title("피싱 URL 탐지기")
st.write("URL를 복붙해서 악성 링크인지 확인해보세요!")

if "url_input" not in st.session_state:
    st.session_state.url_input = ""

st.markdown("**URL 복붙하기**")
url_column, paste_column = st.columns([4, 1.4], vertical_alignment="bottom")

# text_input 위젯을 만들기 전에 붙여넣기 결과를 세션 상태에 반영합니다.
with paste_column:
    paste_result = paste_button(
        key="clipboard_paste_button",
        on_pasted_url_change=lambda: None,
        on_paste_error_change=lambda: None,
    )

if paste_result.pasted_url is not None:
    st.session_state.url_input = paste_result.pasted_url

with url_column:
    user_url = st.text_input(
        "URL 복붙하기",
        placeholder="https://example.com/login",
        label_visibility="collapsed",
        key="url_input",
    )

if paste_result.paste_error:
    st.warning(paste_result.paste_error)


# URL 분석
if st.button(
    "🔍 URL 분석하기",
    type="primary",
    use_container_width=True,
    key="analyze_url_button",
):
    url = normalize_url(user_url)

    try:
        parsed = urlsplit(url)
        is_valid = (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and not any(character.isspace() for character in url)
            and len(url) <= 4096
        )
    except ValueError:
        is_valid = False

    if not is_valid:
        st.warning("올바른 HTTP 또는 HTTPS URL을 입력해 주세요.")

    elif not MODEL_PATH.is_file():
        st.error(
            "학습된 모델 파일이 없습니다. "
            "`python train_model.py`를 먼저 실행해 주세요."
        )

    else:
        try:
            model = load_model()
            phishing_index = list(model.classes_).index(1)
            score = float(model.predict_proba([url])[0][phishing_index])

        except Exception as exc:
            st.error("모델 분석에 실패했습니다. 학습 파일과 실행 환경을 확인해 주세요.")
            st.exception(exc)

        else:
            st.divider()
            st.subheader("AI 분석 결과")

            st.metric("피싱 분류 점수", f"{score * 100:.1f}%")

            if score >= 0.8:
                st.error("🔴 피싱 의심 높음 — 링크 접속과 정보 입력을 피하세요.")

            elif score >= 0.5:
                st.warning("🟠 피싱 의심 — 추가 확인이 필요합니다.")

            else:
                st.success("🟢 모델 기준 피싱 의심 낮음 — 안전을 보장하지는 않습니다.")

            st.subheader("URL 구조 확인")

            for hint in get_url_hints(url):
                st.write("• " + hint)

            st.info(
                "이 점수는 학습된 모델의 분류 점수이며 실제 악성 확률을 뜻하지 않습니다. "
                "구조 분석 항목은 모델의 실제 판단 근거와 다를 수 있습니다. "
                "URL에 직접 접속하지 않고 입력한 문자열만 분석합니다."
            )


# 화면 맨 아래 저작권 표시
st.divider()

st.markdown(
    '<div class="app-copyright">© Made by DongGyu Kim - 2026</div>',
    unsafe_allow_html=True,
)
