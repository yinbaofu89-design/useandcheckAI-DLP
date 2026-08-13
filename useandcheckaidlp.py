import streamlit as st
import base64
import json
import uuid
import requests
import os
import mimetypes
from datetime import datetime
import time
import threading
import io
from PIL import Image
import re

# ページ設定
st.set_page_config(
    page_title="DDS + AI 統合ツール",
    page_icon="🔒",
    layout="wide"
)

st.title("🔒 DDS + AI 統合コンテンツ検査ツール")
st.caption("DDSでポリシー違反をチェック後、AI APIで応答を生成")

# ==================== 初期化 ====================
if "messages" not in st.session_state:
    st.session_state.messages = []
if "info_check_results" not in st.session_state:
    st.session_state.info_check_results = []
if "txid" not in st.session_state:
    st.session_state.txid = str(uuid.uuid4())
if "filters" not in st.session_state:
    st.session_state.filters = [
        {"id": "c23de41e-f4a7-4b9e-9c1b-5b4eef283ec0", "name": "PCI"},
        {"id": "e58edfb6-bfa2-4256-ae28-ce929ba46bc8", "name": "source code detection"},
        {"id": "1443472b-c71f-49a0-bb44-06119fe48d0c", "name": "情報漏洩防止"}
    ]
if "dds_configured" not in st.session_state:
    st.session_state.dds_configured = False
if "ai_configured" not in st.session_state:
    st.session_state.ai_configured = False
if "uploaded_file_info" not in st.session_state:
    st.session_state.uploaded_file_info = None
if "file_checked" not in st.session_state:
    st.session_state.file_checked = False
if "file_violations" not in st.session_state:
    st.session_state.file_violations = []
if "file_approved" not in st.session_state:
    st.session_state.file_approved = False
if "file_data" not in st.session_state:
    st.session_state.file_data = None
if "filename" not in st.session_state:
    st.session_state.filename = None
if "ai_api_key" not in st.session_state:
    st.session_state.ai_api_key = "1234"
if "ai_api_url" not in st.session_state:
    st.session_state.ai_api_url = "http://localhost:1234/v1"
if "ai_model" not in st.session_state:
    st.session_state.ai_model = "Qwen3 8B - Q4_K_M"
if "selected_provider" not in st.session_state:
    st.session_state.selected_provider = "ローカル (LM Studio)"
if "debug_mode" not in st.session_state:
    st.session_state.debug_mode = False
if "debug_logs" not in st.session_state:
    st.session_state.debug_logs = []
if "log_counter" not in st.session_state:
    st.session_state.log_counter = 0
if "process_start_time" not in st.session_state:
    st.session_state.process_start_time = None
if "show_debug_panel" not in st.session_state:
    st.session_state.show_debug_panel = False
if "operation_mode" not in st.session_state:
    st.session_state.operation_mode = "Monitor"
if "send_target" not in st.session_state:
    st.session_state.send_target = "both"
if "info_check_done" not in st.session_state:
    st.session_state.info_check_done = False
if "show_dds_response" not in st.session_state:
    st.session_state.show_dds_response = False
if "blocked_content" not in st.session_state:
    st.session_state.blocked_content = False

# 情報チェックリスト項目
if "info_check_items" not in st.session_state:
    st.session_state.info_check_items = [
        {"name": "日本の電話番号情報", "enabled": True},
        {"name": "日本の住所情報", "enabled": True},
        {"name": "日本の名前情報", "enabled": True},
        {"name": "日本の銀行口座情報", "enabled": True},
        {"name": "日本のクレジットカード情報", "enabled": True},
        {"name": "日本のマイナンバー情報", "enabled": True},
    ]

# ==================== AIプロバイダー設定 ====================
AI_PROVIDERS = {
    "DeepSeek": {
        "url": "https://api.deepseek.com/v1/chat/completions",
        "models": ["deepseek-chat", "deepseek-coder"],
        "default_model": "deepseek-chat",
        "api_key_required": True,
        "description": "DeepSeek API",
        "supports_file_upload": False
    },
    "OpenAI": {
        "url": "https://api.openai.com/v1/responses",
        "models": ["gpt-5", "gpt-5-mini"],
        "default_model": "gpt-5-mini",
        "api_key_required": True,
        "description": "OpenAI API",
        "supports_file_upload": True
    },
    "ローカル (LM Studio)": {
        "url": "http://localhost:1234/v1",
        "models": ["Qwen3 8B - Q4_K_M", "llama3-8b", "mistral-7b", "phi-3", "gemma-2b"],
        "default_model": "Qwen3 8B - Q4_K_M",
        "api_key_required": False,
        "default_api_key": "1234",
        "description": "LM Studio ローカルサーバー",
        "supports_file_upload": False
    },
    "ローカル (Ollama)": {
        "url": "http://localhost:11434/v1/chat/completions",
        "models": ["llama3", "mistral", "phi3", "gemma", "qwen", "llama2", "codellama", "llava"],
        "default_model": "llama3",
        "api_key_required": False,
        "default_api_key": "ollama",
        "description": "Ollama ローカルサーバー",
        "supports_file_upload": False
    },
    "Groq": {
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "models": ["llama3-70b-8192", "llama3-8b-8192", "mixtral-8x7b-32768", "gemma2-9b-it"],
        "default_model": "llama3-70b-8192",
        "api_key_required": True,
        "description": "Groq API",
        "supports_file_upload": False
    }
}

# ==================== MIMEタイプ関数 ====================
def get_mime_type(filename):
    ext = os.path.splitext(filename)[1].lower()
    mime_map = {
        '.txt': 'text/plain', '.csv': 'text/csv', '.log': 'text/plain',
        '.ini': 'text/plain', '.cfg': 'text/plain', '.conf': 'text/plain',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.dot': 'application/msword', '.dotx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
        '.docm': 'application/vnd.ms-word.document.macroEnabled.12',
        '.xls': 'application/vnd.ms-excel',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.xlsm': 'application/vnd.ms-excel.sheet.macroEnabled.12',
        '.xlsb': 'application/vnd.ms-excel.sheet.binary.macroEnabled.12',
        '.ppt': 'application/vnd.ms-powerpoint',
        '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        '.pptm': 'application/vnd.ms-powerpoint.presentation.macroEnabled.12',
        '.pps': 'application/vnd.ms-powerpoint', '.ppsx': 'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
        '.pdf': 'application/pdf',
        '.eml': 'message/rfc822', '.msg': 'application/vnd.ms-outlook',
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png', '.gif': 'image/gif',
        '.bmp': 'image/bmp', '.tiff': 'image/tiff', '.tif': 'image/tiff',
        '.webp': 'image/webp', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
        '.zip': 'application/zip', '.7z': 'application/x-7z-compressed',
        '.rar': 'application/vnd.rar', '.tar': 'application/x-tar', '.gz': 'application/gzip',
        '.html': 'text/html', '.htm': 'text/html',
        '.xml': 'text/xml', '.json': 'application/json',
        '.css': 'text/css', '.js': 'application/javascript',
        '.rtf': 'application/rtf',
        '.odt': 'application/vnd.oasis.opendocument.text',
        '.ods': 'application/vnd.oasis.opendocument.spreadsheet',
        '.odp': 'application/vnd.oasis.opendocument.presentation',
    }
    return mime_map.get(ext, 'application/octet-stream')

def is_image_mime(mime_type):
    return bool(mime_type) and mime_type.lower().startswith("image/")

def build_data_url(file_bytes, mime_type):
    encoded = base64.b64encode(file_bytes).decode("utf-8")
    return f"data:{mime_type};base64,{encoded}"

# ==================== デバッグログ関数 ====================
def add_debug_log(step, message, log_type="info", elapsed_time=None, details=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    st.session_state.log_counter += 1
    log_entry = {
        "id": st.session_state.log_counter,
        "timestamp": timestamp,
        "step": step,
        "message": message,
        "type": log_type,
        "elapsed_time": elapsed_time,
        "details": details
    }
    st.session_state.debug_logs.append(log_entry)
    st.session_state.show_debug_panel = True

def clear_debug_logs():
    st.session_state.debug_logs = []
    st.session_state.log_counter = 0
    st.session_state.show_debug_panel = False

def render_debug_logs():
    if not st.session_state.debug_logs:
        st.info("📋 デバッグログはありません")
        return
    
    for log in st.session_state.debug_logs:
        log_id = log["id"]
        timestamp = log["timestamp"]
        step = log["step"]
        message = log["message"]
        log_type = log["type"]
        elapsed = log.get("elapsed_time")
        details = log.get("details")
        
        icon_map = {"info": "ℹ️", "success": "✅", "warning": "⚠️", "error": "❌"}
        color_map = {"info": "#0066cc", "success": "#00aa00", "warning": "#cc8800", "error": "#cc0000"}
        
        icon = icon_map.get(log_type, "ℹ️")
        color = color_map.get(log_type, "#0066cc")
        
        time_info = f"🕐 {timestamp}"
        if elapsed is not None:
            time_info += f" | ⏱️ {elapsed:.3f}秒"
        
        st.markdown(
            f"""
            <div style="border-left: 3px solid {color}; padding: 4px 8px; margin: 2px 0; 
                        background-color: #f8f9fa; border-radius: 3px; font-family: monospace; font-size: 12px;">
                <div><span style="font-weight: bold; color: {color};">[{step}]</span> {icon} {message}</div>
                <div style="font-size: 10px; color: #888;">{time_info}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        
        if details:
            with st.expander(f"📝 詳細 (ID: {log_id})", expanded=False):
                st.json(details)
    
    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🗑️ ログクリア", key="clear_logs_btn_panel", use_container_width=True):
            clear_debug_logs()
            st.rerun()
    with col2:
        if st.button("📋 コピー", key="copy_logs_btn_panel", use_container_width=True):
            log_text = "\n".join([
                f"[{log['timestamp']}] [{log['step']}] {log['message']} (経過: {log.get('elapsed_time', 0):.3f}秒)"
                for log in st.session_state.debug_logs
            ])
            st.code(log_text, language="text")
    
    st.caption(f"📊 ログ件数: {len(st.session_state.debug_logs)} 件")

# ==================== 情報チェックAIプロンプト（修正版：検出項目のみ出力） ====================
def build_information_check_prompt(check_items):
    """情報チェックAIのプロンプトを生成する（修正版：検出項目のみ出力）"""
    items = [x["name"] for x in check_items if x.get("enabled")]
    item_lines = "\n".join(f"- {item}" for item in items)

    return f"""あなたは情報漏えい防止(DLP)の補助分析を行うAIです。
提出されたファイルとメッセージの内容だけを**厳密に**分析してください。

以下の情報チェック項目について、提出されたファイルまたはメッセージに該当情報が**実際に含まれているか**確認してください。

{item_lines}

【最重要規則 - 絶対に厳守すること】
1. **実際に存在する項目だけ**を出力してください。
2. **存在しない項目は絶対に出力しないでください**。
3. 具体的な内容が**明確に確認できる場合だけ**、「ヒットした○○内容-内容」を出力してください。
4. **推測や類推に基づく出力は絶対に行わないでください**。
5. 出力は**検出した項目の行のみ**にしてください。
6. 理由、説明、挨拶、要約、注意事項、Markdownは**一切追加しないでください**。
7. **何も検出されなかった場合は、何も出力しないでください（空文字列を返してください）**。

【出力ルール】
- 検出した項目がある場合 → その項目の行のみを出力
- 検出した項目がない場合 → **何も出力しない**

【出力例（あくまで例であり、実際に出力するかは検出結果に依存します）】
※ 以下の例は「もし検出された場合の形式」を示すものであり、すべてを出力することを意味しません。

検出例1（名前と住所が検出された場合）:
名前情報内包
住所情報内包
ヒットした名前内容-田中一郎
ヒットした住所内容-横浜市北区三丁目3-201

検出例2（電話番号のみが検出された場合）:
電話番号情報内包
ヒットした電話番号内容-090-1234-5678

検出例3（何も検出されなかった場合）:
（何も出力しない）

【重要 - 繰り返し強調】
- **検出された項目だけ**を出力してください。
- **検出されていない項目は絶対に出力しないでください**。
- 上記の例は「形式の例」であり、「出力すべき項目のリスト」ではありません。
- **何も検出されなかった場合は、空文字列（何も出力しない）を返してください。**"""

# ==================== ファイル内容抽出関数 ====================
def extract_file_content(file_bytes, filename, max_chars=5000):
    """ファイルからテキスト内容を抽出する"""
    mime = get_mime_type(filename)
    
    if mime.startswith("text/") or filename.lower().endswith((".txt", ".csv", ".log", ".json", ".xml", ".html", ".htm", ".md")):
        try:
            decoded = file_bytes.decode("utf-8", errors="ignore")
            if len(decoded) > max_chars:
                return decoded[:max_chars] + f"\n... (省略: {len(decoded) - max_chars}文字)"
            return decoded
        except:
            return f"（バイナリファイル: {len(file_bytes)}バイト）"
    
    elif filename.lower().endswith((".docx", ".doc")):
        try:
            try:
                import docx
                doc = docx.Document(io.BytesIO(file_bytes))
                text = "\n".join([para.text for para in doc.paragraphs])
                if len(text) > max_chars:
                    return text[:max_chars] + f"\n... (省略: {len(text) - max_chars}文字)"
                return text
            except ImportError:
                return f"（Wordファイル: {filename}、{len(file_bytes)}バイト）"
        except:
            return f"（Wordファイル: {filename}、{len(file_bytes)}バイト）"
    
    elif filename.lower().endswith(".pdf"):
        try:
            try:
                import PyPDF2
                reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
                text = ""
                for page in reader.pages:
                    text += page.extract_text() + "\n"
                if len(text) > max_chars:
                    return text[:max_chars] + f"\n... (省略: {len(text) - max_chars}文字)"
                return text
            except ImportError:
                return f"（PDFファイル: {filename}、{len(file_bytes)}バイト）"
        except:
            return f"（PDFファイル: {filename}、{len(file_bytes)}バイト）"
    
    else:
        return f"（バイナリファイル: {filename}、{len(file_bytes)}バイト）"

# ==================== 情報チェックAI実行 ====================
def run_information_check_ai(file_bytes, filename, user_message, check_items, additional_context=None):
    """
    情報チェックAIを実行する
    
    Args:
        file_bytes: ファイルデータ
        filename: ファイル名
        user_message: ユーザーメッセージ
        check_items: チェック項目リスト
        additional_context: 追加のコンテキスト情報（AI回答のDDSチェック結果など）
    """
    prompt = build_information_check_prompt(check_items)
    
    # システムメッセージにプロンプトを設定
    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": """以下のファイルとメッセージを厳密に分析してください。

【厳守事項 - 必ず守ること】
1. 実際に存在する情報だけを検出してください。
2. 推測や類推は絶対に行わないでください。
3. 検出した情報がない場合は、何も出力しないでください。
4. 指定された形式以外の出力は絶対に行わないでください。
5. 「可能性がある」「おそらく」といった曖昧な表現は使用しないでください。

分析対象:"""}
    ]
    
    user_content = ""
    if user_message:
        user_content += f"【メッセージ】\n{user_message}\n\n"
    
    if file_bytes and filename:
        user_content += f"【ファイル: {filename}】\n"
        file_text = extract_file_content(file_bytes, filename)
        user_content += file_text
    
    # 追加コンテキストがある場合（AI回答のDDSチェック結果など）
    if additional_context:
        user_content += "\n\n【追加コンテキスト情報】\n"
        user_content += additional_context
    
    if user_content:
        messages.append({"role": "user", "content": user_content})
    else:
        messages.append({"role": "user", "content": "分析する内容がありません。"})
    
    # 最後に再度、出力形式を明確に指示
    messages.append({
        "role": "user", 
        "content": """再度確認します：
- 実際に存在する情報だけを出力してください。
- 存在しない情報は絶対に出力しないでください。
- 何も検出されなかった場合は、空文字列（何も出力しない）を返してください。
- 指定された形式以外の出力は絶対に行わないでください。"""
    })
    
    return call_ai_api(messages, max_tokens=500)

# ==================== AI API呼び出し ====================
def normalize_api_url(url):
    url = url.strip()
    if url.endswith('/v1'):
        return url + '/chat/completions'
    if url.endswith('/v1/'):
        return url + 'chat/completions'
    if not url.endswith('/chat/completions') and not url.endswith('/completions'):
        if not url.endswith('/'):
            return url + '/v1/chat/completions'
        else:
            return url + 'v1/chat/completions'
    return url

def call_ai_api(messages, max_tokens=200):
    start_time = time.time()
    
    try:
        api_key = st.session_state.ai_api_key
        api_url = normalize_api_url(st.session_state.ai_api_url)
        model_name = st.session_state.ai_model
        
        if not api_url or not model_name:
            st.error("AI設定が不完全です。")
            return None, time.time() - start_time
        
        provider = st.session_state.selected_provider
        if provider in AI_PROVIDERS and AI_PROVIDERS[provider].get("api_key_required", True) and not api_key:
            st.error(f"{provider}はAPI Keyが必須です。")
            return None, time.time() - start_time
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": model_name,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.1,  # 温度を下げて確定的な出力に
            "stream": False
        }
        
        if st.session_state.debug_mode:
            add_debug_log("AIリクエスト", f"AI API呼び出し (モデル: {model_name})", "info", 0, {
                "url": api_url,
                "model": model_name,
                "temperature": 0.1,
                "messages": [{"role": m["role"], "content": str(m["content"])[:200]} for m in messages]
            })
        
        response = requests.post(api_url, headers=headers, json=data, timeout=120)
        
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            
            if st.session_state.debug_mode:
                add_debug_log("AIレスポンス", f"AI API応答受信", "success", elapsed, {
                    "response": result
                })
            
            content = None
            
            if "choices" in result and len(result["choices"]) > 0:
                choice = result["choices"][0]
                message = choice.get("message", {})
                content = message.get("content", "")
                
                # 空の応答や余計なテキストを除去
                if content:
                    lines = content.strip().split('\n')
                    filtered_lines = []
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        # 挨拶や説明文をスキップ
                        skip_patterns = ['はい、', 'わかりました', '以下は', '分析結果', '【', '（', '注意', '重要', '確認します']
                        should_skip = False
                        for pattern in skip_patterns:
                            if line.startswith(pattern):
                                should_skip = True
                                break
                        if not should_skip:
                            filtered_lines.append(line)
                    
                    content = '\n'.join(filtered_lines)
                
                if not content:
                    return "（応答がありませんでした）", elapsed
                
                return content, elapsed
            
            elif "response" in result:
                return result["response"], elapsed
            
            else:
                st.error(f"予期しないレスポンス形式: {result}")
                return None, elapsed
                
        else:
            error_msg = f"AI APIエラー: {response.status_code} - {response.text}"
            st.error(error_msg)
            add_debug_log("AIエラー", error_msg, "error", elapsed)
            return None, elapsed
            
    except requests.exceptions.ConnectionError as e:
        error_msg = f"❌ 接続エラー: APIサーバー ({api_url}) に接続できませんでした"
        st.error(error_msg)
        add_debug_log("AIエラー", error_msg, "error", time.time() - start_time)
        return None, time.time() - start_time
    except requests.exceptions.Timeout:
        error_msg = "❌ タイムアウト: サーバーからの応答がありませんでした"
        st.error(error_msg)
        add_debug_log("AIエラー", error_msg, "error", time.time() - start_time)
        return None, time.time() - start_time
    except Exception as e:
        error_msg = f"AI API呼び出しエラー: {e}"
        st.error(error_msg)
        add_debug_log("AIエラー", error_msg, "error", time.time() - start_time)
        return None, time.time() - start_time

# ==================== OpenAIファイル送信 ====================
def call_openai_with_file(messages, file_bytes=None, filename=None, mime_type=None, max_tokens=200):
    start_time = time.time()
    try:
        api_key = st.session_state.ai_api_key
        model_name = st.session_state.ai_model
        if not api_key or not model_name:
            st.error("OpenAI API Keyまたはモデルが設定されていません。")
            return None, time.time() - start_time

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        input_items = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            input_items.append({
                "role": role,
                "content": [{"type": "input_text", "text": str(content)}]
            })

        if file_bytes is not None and filename:
            mime = mime_type or get_mime_type(filename)
            if is_image_mime(mime):
                image_url = build_data_url(file_bytes, mime)
                input_items.append({
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": f"添付ファイル: {filename}"},
                        {"type": "input_image", "image_url": image_url}
                    ]
                })
            else:
                upload_headers = {"Authorization": f"Bearer {api_key}"}
                files = {
                    "file": (filename, file_bytes, mime)
                }
                upload_data = {"purpose": "user_data"}
                upload_response = requests.post(
                    "https://api.openai.com/v1/files",
                    headers=upload_headers,
                    data=upload_data,
                    files=files,
                    timeout=120
                )
                if upload_response.status_code not in (200, 201):
                    st.error(f"OpenAI Files APIエラー: {upload_response.status_code} - {upload_response.text}")
                    return None, time.time() - start_time

                file_id = upload_response.json().get("id")
                if not file_id:
                    st.error("OpenAI Files APIからfile_idを取得できませんでした。")
                    return None, time.time() - start_time

                input_items.append({
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": f"添付ファイル {filename} を読み取り、ユーザーの質問に答えてください。"},
                        {"type": "input_file", "file_id": file_id}
                    ]
                })

        payload = {
            "model": model_name,
            "input": input_items,
            "max_output_tokens": max_tokens
        }

        response = requests.post(
            "https://api.openai.com/v1/responses",
            headers=headers,
            json=payload,
            timeout=120
        )
        elapsed = time.time() - start_time

        if response.status_code != 200:
            st.error(f"OpenAI Responses APIエラー: {response.status_code} - {response.text}")
            return None, elapsed

        result = response.json()
        output_text = result.get("output_text")
        if output_text:
            return output_text, elapsed

        texts = []
        for item in result.get("output", []):
            for content in item.get("content", []):
                if content.get("type") == "output_text" and content.get("text"):
                    texts.append(content["text"])
        return ("\n".join(texts) if texts else "（応答がありませんでした）"), elapsed

    except requests.exceptions.Timeout:
        st.error("❌ OpenAI APIタイムアウト")
        return None, time.time() - start_time
    except requests.exceptions.ConnectionError as e:
        st.error(f"❌ OpenAI API接続エラー: {e}")
        return None, time.time() - start_time
    except Exception as e:
        st.error(f"❌ OpenAIファイル送信エラー: {e}")
        return None, time.time() - start_time

# ==================== AIファイル送信（統合） ====================
def call_ai_with_file(messages, file_bytes=None, filename=None, mime_type=None, max_tokens=200):
    provider = st.session_state.selected_provider
    
    if provider == "OpenAI":
        return call_openai_with_file(messages, file_bytes, filename, mime_type, max_tokens)
    else:
        if file_bytes and filename:
            file_text = extract_file_content(file_bytes, filename)
            for i, msg in enumerate(messages):
                if msg.get("role") == "user":
                    messages[i] = {
                        "role": "user",
                        "content": msg.get("content", "") + f"\n\n【ファイル: {filename}】\n{file_text}"
                    }
                    break
        return call_ai_api(messages, max_tokens)

# ==================== DDS送信関数 ====================
def send_detection_request(file_obj, source_type, dds_url, verify_ssl, data_type="DIM", content_block_id=None, mime_type=None):
    start_time = time.time()
    
    try:
        file_obj.seek(0)
        file_bytes = file_obj.read()
        b64_data = base64.b64encode(file_bytes).decode('utf-8')
        
        context = [
            {"name": "common.dataType", "value": [data_type]},
            {"name": "common.application", "value": [st.session_state.get("dlp_application", "securlet.box")]},
            {"name": "common.transactionId", "value": [st.session_state.txid]},
            {"name": "common.filter", "value": [f["id"] for f in st.session_state.filters]},
            {"name": "common.expectActionsAck", "value": ["true"]},
        ]
        
        if st.session_state.get("client_domain"):
            context.append({"name": "client.domain", "value": [st.session_state.client_domain]})
        if st.session_state.get("client_user"):
            context.append({"name": "client.user.id", "value": [st.session_state.client_user]})
        
        if source_type == "file":
            file_mime = get_mime_type(file_obj.name)
            if hasattr(file_obj, 'type') and file_obj.type and file_obj.type != 'application/octet-stream':
                file_mime = file_obj.type
            
            block_id = re.sub(r'[^a-zA-Z0-9-]', '-', file_obj.name) + "-001"
            
            request_data = {
                "context": context,
                "subject": {
                    "contentBlockId": "subject-001",
                    "mimeType": "text/plain",
                    "data": base64.b64encode(f"ファイル: {file_obj.name}".encode('utf-8')).decode('utf-8')
                },
                "attachments": [
                    {
                        "contentBlockId": block_id,
                        "mimeType": file_mime,
                        "data": b64_data,
                        "name": file_obj.name
                    }
                ]
            }
            
        else:
            block_id = content_block_id or "message-001"
            mime = mime_type or "text/plain"
            
            request_data = {
                "context": context,
                "subject": {
                    "contentBlockId": block_id,
                    "mimeType": "text/plain",
                    "data": b64_data
                }
            }
        
        json_data = json.dumps(request_data, ensure_ascii=False)
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        if st.session_state.debug_mode:
            add_debug_log("DDSリクエスト", f"リクエスト送信 (タイプ: {source_type})", "info", 0, {
                "url": dds_url,
                "source_type": source_type,
                "data_type": data_type,
                "request_data": request_data
            })
        
        response = requests.post(
            dds_url,
            data=json_data,
            headers=headers,
            verify=not verify_ssl,
            timeout=60
        )
        
        elapsed = time.time() - start_time
        
        try:
            response_json = response.json()
            
            if st.session_state.debug_mode:
                add_debug_log("DDSレスポンス", f"ステータス: {response.status_code}", 
                             "success" if response.status_code == 201 else "error", elapsed, {
                                "status_code": response.status_code,
                                "response": response_json
                            })
            
            if response.status_code == 201:
                violations = response_json.get("violation", [])
                if violations is None:
                    violations = []
                request_id = response_json.get("requestId")
                return violations, request_id, response_json, None, elapsed
            else:
                error_info = {
                    "status_code": response.status_code,
                    "response_text": response.text,
                    "headers": dict(response.headers)
                }
                return [], None, None, error_info, elapsed
                
        except Exception as e:
            error_info = {
                "status_code": response.status_code,
                "response_text": response.text,
                "error": str(e)
            }
            return [], None, None, error_info, elapsed
            
    except requests.exceptions.ConnectionError as e:
        error_info = {
            "error_type": "ConnectionError",
            "message": str(e),
            "dds_url": dds_url
        }
        return [], None, None, error_info, time.time() - start_time
    except requests.exceptions.Timeout as e:
        error_info = {
            "error_type": "Timeout",
            "message": str(e)
        }
        return [], None, None, error_info, time.time() - start_time
    except Exception as e:
        error_info = {
            "error_type": "Exception",
            "message": str(e)
        }
        import traceback
        error_info["traceback"] = traceback.format_exc()
        return [], None, None, error_info, time.time() - start_time

# ==================== MessageWrapperクラス ====================
class MessageWrapper:
    def __init__(self, content, name):
        self.content = content
       
