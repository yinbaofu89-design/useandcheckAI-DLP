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
        {"id": "e58edfb6-bfa2-4256-ae28-ce929ba46bc8", "name": "source code detection"}
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

# ==================== 情報チェックAIプロンプト ====================
def build_information_check_prompt(check_items):
    items = [x["name"] for x in check_items if x.get("enabled")]
    item_lines = "\n".join(f"- {item}" for item in items)

    return f"""あなたは情報漏えい防止(DLP)の補助分析を行うAIです。
提出されたファイルとメッセージの内容だけを分析してください。

以下の情報チェック項目について、提出されたファイルまたはメッセージに該当情報が含まれているか確認してください。

{item_lines}

【出力規則 - 厳守】
1. 該当する項目がある場合だけ、その項目の「内包」行を出力してください。
2. 該当しない項目は絶対に出力しないでください。
3. 該当項目の具体的な内容を確認できる場合だけ、最後に「ヒットした○○内容-内容」の形式で出力してください。
4. 出力は下記の形式以外を絶対に追加しないでください。
5. 理由、説明、判定、挨拶、要約、注意事項、Markdown、箇条書き記号は追加しないでください。
6. 同じ情報を重複して出力しないでください。
7. 情報を推測して作らないでください。提出された内容に実際に存在する情報だけを出力してください。
8. 追加項目についても同じ規則を適用してください。

【出力形式 - この形式以外は絶対に出力しないでください】
電話番号情報内包
住所情報内包
名前情報内包
銀行口座情報内包
クレジットカード情報内包
マイナンバー情報内包

ヒットした電話番号内容-XXXXXXXX
ヒットした住所内容-XXXXXXXX
ヒットした名前内容-XXXXXXXX
ヒットした銀行口座内容-XXXXXXXX
ヒットしたクレジットカード内容-XXXXXXXX
ヒットしたマイナンバー内容-XXXXXXXX

【重要】
上記は形式の例です。実際には検知された項目だけを出力してください。
「情報内包」行は、項目名に対応する短い固定表現にしてください。
具体的なヒット内容が確認できない場合、その「ヒットした...内容-」行は出力しないでください。
これ以外の内容は絶対に追加しないでください。"""

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
def run_information_check_ai(file_bytes, filename, user_message, check_items):
    prompt = build_information_check_prompt(check_items)
    
    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": "以下のファイルとメッセージを分析して、指定された固定フォーマットで出力してください。"}
    ]
    
    user_content = ""
    if user_message:
        user_content += f"【メッセージ】\n{user_message}\n\n"
    
    if file_bytes and filename:
        user_content += f"【ファイル: {filename}】\n"
        file_text = extract_file_content(file_bytes, filename)
        user_content += file_text
    
    if user_content:
        messages.append({"role": "user", "content": user_content})
    else:
        messages.append({"role": "user", "content": "分析する内容がありません。"})
    
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
            "temperature": 0.7,
            "stream": False
        }
        
        if st.session_state.debug_mode:
            add_debug_log("AIリクエスト", f"AI API呼び出し (モデル: {model_name})", "info", 0, {
                "url": api_url,
                "model": model_name,
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
        self.name = name
        self.type = "text/plain"
        self.size = len(content)
    def read(self):
        return self.content.encode('utf-8')
    def seek(self, pos):
        pass

class BytesWrapper:
    def __init__(self, data, name, mime_type="application/octet-stream"):
        self.data = data
        self.name = name
        self.type = mime_type
        self.size = len(data)
    def read(self):
        return self.data
    def seek(self, pos):
        pass

# ==================== コンテンツ取得関数 ====================
def get_content_for_dds(file_data, filename, user_message, send_target):
    content = ""
    if send_target in ["message", "both"] and user_message:
        content += f"【メッセージ】\n{user_message}\n"
    if send_target in ["file", "both"] and file_data and filename:
        content += f"【ファイル: {filename}】\n"
        file_text = extract_file_content(file_data, filename)
        content += file_text
    return content

# ==================== 履歴クリア関数 ====================
def clear_conversation():
    st.session_state.messages = []
    st.session_state.info_check_results = []
    st.session_state.txid = str(uuid.uuid4())

# ==================== DDSレスポンス整形関数 ====================
def format_dds_response(response_data, violations, request_id):
    """DDSレスポンスを整形して表示用の文字列を生成"""
    if not response_data:
        return "（DDSレスポンスなし）"
    
    lines = []
    lines.append("📋 **DDSレスポンス詳細**")
    lines.append("")
    
    if request_id:
        lines.append(f"🆔 Request ID: `{request_id}`")
    
    if violations and len(violations) > 0:
        lines.append(f"⚠️ 違反件数: {len(violations)}件")
        lines.append("")
        for i, v in enumerate(violations, 1):
            v_name = v.get("name", "不明")
            v_id = v.get("id", "不明")
            v_severity = v.get("severity", "不明")
            lines.append(f"  {i}. **{v_name}**")
            lines.append(f"     - ID: `{v_id}`")
            lines.append(f"     - 重大度: {v_severity}")
    else:
        lines.append("✅ 違反なし")
    
    lines.append("")
    lines.append("---")
    lines.append("📄 **JSONレスポンス:**")
    lines.append("```json")
    lines.append(json.dumps(response_data, ensure_ascii=False, indent=2))
    lines.append("```")
    
    return "\n".join(lines)

# ==================== サイドバー設定 ====================
with st.sidebar:
    st.header("⚙️ 設定")
    
    st.subheader("👤 クライアント情報")
    client_domain = st.text_input(
        "ドメイン",
        value=st.session_state.get("client_domain", "tds-cnx.com"),
        key="client_domain_input"
    )
    client_user = st.text_input(
        "ユーザー名",
        value=st.session_state.get("client_user", "Baofu"),
        key="client_user_input"
    )
    dlp_application = st.text_input(
        "Application",
        value=st.session_state.get("dlp_application", "securlet.box"),
        key="dlp_application_input"
    )
    st.session_state.client_domain = client_domain
    st.session_state.client_user = client_user
    st.session_state.dlp_application = dlp_application

    st.divider()

    st.subheader("🔄 動作モード")
    operation_mode = st.radio(
        "モード選択",
        ["Monitor", "Inline"],
        index=0 if st.session_state.operation_mode == "Monitor" else 1,
        horizontal=True
    )
    st.session_state.operation_mode = operation_mode
    
    st.subheader("📤 送信ターゲット")
    send_target = st.radio(
        "送信内容",
        ["ファイルのみ", "メッセージのみ", "両方"],
        index=2,
        horizontal=True
    )
    target_map = {"ファイルのみ": "file", "メッセージのみ": "message", "両方": "both"}
    st.session_state.send_target = target_map[send_target]

    st.divider()

    st.subheader("🔎 情報チェックAI")
    st.caption("AIによるDLP補助分析。初期状態では全項目ONです。")

    for idx, item in enumerate(st.session_state.info_check_items):
        item["enabled"] = st.checkbox(
            item["name"],
            value=item.get("enabled", True),
            key=f"info_check_{idx}"
        )

    with st.expander("➕ 検知項目を追加"):
        new_info_item = st.text_input(
            "追加する検知内容",
            key="new_info_item",
            placeholder="例：社内機密コード"
        )
        if st.button("追加", key="add_info_item_btn", use_container_width=True):
            if new_info_item.strip():
                st.session_state.info_check_items.append(
                    {"name": new_info_item.strip(), "enabled": True}
                )
                st.rerun()

    st.divider()

    st.subheader("🔍 DDS設定")
    dds_host = st.text_input("DDSサーバーIP", value="192.168.2.132")
    dds_port = st.text_input("ポート", value="443")
    use_ssl = st.checkbox("SSL/TLSを使用", value=False)
    protocol = "https" if use_ssl else "http"
    dds_url = f"{protocol}://{dds_host}:{dds_port}/v2.0/DetectionRequests"
    st.session_state.dds_url = dds_url
    st.session_state.verify_ssl = use_ssl
    
    st.divider()
    
    st.subheader("🤖 AI設定")
    
    provider_options = list(AI_PROVIDERS.keys())
    default_index = provider_options.index("ローカル (LM Studio)") if "ローカル (LM Studio)" in provider_options else 0
    
    selected_provider = st.selectbox(
        "AIプロバイダー",
        provider_options,
        index=default_index
    )
    st.session_state.selected_provider = selected_provider
    
    provider_config = AI_PROVIDERS[selected_provider]
    st.caption(f"📌 {provider_config.get('description', '')}")
    
    st.session_state.ai_api_url = provider_config["url"]
    st.info(f"📡 API URL: {provider_config['url']}")
    
    model_options = provider_config["models"].copy() if provider_config["models"] else []
    model_options.append("その他 (カスタム)")
    
    current_model = st.session_state.ai_model
    if current_model not in model_options:
        current_display = "その他 (カスタム)"
    else:
        current_display = current_model
    
    selected_model = st.selectbox(
        "モデル",
        model_options,
        index=model_options.index(current_display) if current_display in model_options else 0
    )
    
    if selected_model == "その他 (カスタム)":
        custom_model = st.text_input(
            "カスタムモデル名",
            value=st.session_state.ai_model if st.session_state.ai_model not in provider_config["models"] else "",
            placeholder="モデル名を自由に入力してください"
        )
        if custom_model:
            st.session_state.ai_model = custom_model
    else:
        st.session_state.ai_model = selected_model
    
    if provider_config.get("api_key_required", True):
        st.session_state.ai_api_key = st.text_input(
            "API Key",
            value=st.session_state.ai_api_key,
            type="password",
            placeholder="APIキーを入力してください"
        )
    else:
        default_key = provider_config.get("default_api_key", "")
        st.session_state.ai_api_key = default_key
        st.info(f"🔑 API Key: {default_key} (自動設定)")
    
    st.divider()
    
    st.subheader("🐛 デバッグ設定")
    debug_mode = st.checkbox(
        "デバッグモードを有効にする",
        value=st.session_state.debug_mode
    )
    st.session_state.debug_mode = debug_mode
    
    if st.session_state.debug_logs:
        show_panel = st.checkbox(
            "📋 デバッグパネルを表示",
            value=st.session_state.get("show_debug_panel", True)
        )
        st.session_state.show_debug_panel = show_panel
    else:
        st.info("📋 デバッグログがありません")
    
    st.divider()
    
    if st.button("🔗 AI接続テスト", use_container_width=True):
        if st.session_state.ai_api_url and st.session_state.ai_model:
            test_result, elapsed = call_ai_api([
                {"role": "user", "content": "Hello, this is a test. Please respond with 'OK'."}
            ], max_tokens=10)
            if test_result:
                st.success(f"✅ AI接続成功！ (モデル: {st.session_state.ai_model})")
                st.caption(f"⏱️ 応答時間: {elapsed:.2f}秒")
                st.session_state.ai_configured = True
            else:
                st.error("❌ AI接続失敗。設定を確認してください。")
        else:
            st.warning("⚠️ API URLとモデル名を確認してください")
    
    st.divider()
    
    st.subheader("📋 検出フィルター")
    st.caption("最大10個")
    
    filters_to_remove = []
    for i, f in enumerate(st.session_state.filters):
        cols = st.columns([3, 1])
        with cols[0]:
            st.text_input(
                f"フィルター {i+1}",
                value=f["id"],
                key=f"filter_{i}",
                label_visibility="collapsed"
            )
            st.caption(f"📌 {f.get('name', '')}")
        with cols[1]:
            if st.button("🗑️", key=f"remove_filter_{i}"):
                filters_to_remove.append(i)
    
    for idx in sorted(filters_to_remove, reverse=True):
        st.session_state.filters.pop(idx)
        st.rerun()
    
    if len(st.session_state.filters) < 10:
        with st.expander("➕ フィルターを追加"):
            new_filter_id = st.text_input("フィルターID (GUID)", key="new_filter_id")
            new_filter_name = st.text_input("フィルター名", key="new_filter_name")
            if st.button("追加", key="add_filter_btn", use_container_width=True):
                if new_filter_id:
                    st.session_state.filters.append({
                        "id": new_filter_id,
                        "name": new_filter_name or f"フィルター {len(st.session_state.filters)+1}"
                    })
                    st.rerun()
    
    st.divider()
    
    st.text_input("トランザクションID", value=st.session_state.txid, disabled=True)
    if st.button("🔄 新しいIDを生成", key="generate_txid_btn", use_container_width=True):
        st.session_state.txid = str(uuid.uuid4())
        st.rerun()
    
    st.divider()
    
    if st.button("🗑️ 会話履歴をクリア", key="clear_conversation_btn", use_container_width=True):
        clear_conversation()
        st.rerun()
    
    st.divider()
    st.caption(f"📡 プロバイダー: **{st.session_state.get('selected_provider', '未設定')}**")
    st.caption(f"🤖 モデル: **{st.session_state.get('ai_model', '未設定')}**")

# ==================== メインコンテンツ ====================
show_debug = st.session_state.get("show_debug_panel", False) and len(st.session_state.debug_logs) > 0

if show_debug:
    main_col, debug_col = st.columns([2, 1])
else:
    main_col = st.container()
    debug_col = None

with main_col:
    if st.session_state.debug_logs:
        st.info(f"📋 デバッグログ: {len(st.session_state.debug_logs)}件")
    
    mode_color = "🟢" if st.session_state.operation_mode == "Monitor" else "🔵"
    st.caption(f"{mode_color} 現在のモード: **{st.session_state.operation_mode}** | 送信ターゲット: **{send_target}**")
    
    # チャット履歴表示
    chat_container = st.container()
    with chat_container:
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])
                if "violations" in message and message["violations"]:
                    st.error(f"🚫 ポリシー違反: {', '.join([v['name'] for v in message['violations']])}")
                # DDSレスポンス詳細があれば表示
                if "dds_response" in message and message["dds_response"]:
                    with st.expander("📋 DDSレスポンス詳細", expanded=False):
                        st.markdown(message["dds_response"])

    st.subheader("📎 ファイルアップロード")
    
    uploaded_file = st.file_uploader(
        "ファイル選択",
        type=[".txt", ".csv", ".log", ".doc", ".docx", ".xls", ".xlsx", 
              ".ppt", ".pptx", ".pdf", ".eml", ".msg",
              ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".svg", ".ico",
              ".zip", ".7z", ".rar", ".tar", ".gz",
              ".html", ".htm", ".xml", ".json", ".css", ".js",
              ".rtf", ".odt", ".ods", ".odp"],
        key="file_uploader",
        label_visibility="collapsed"
    )

    if uploaded_file:
        if st.session_state.filename != uploaded_file.name:
            st.session_state.file_checked = False
            st.session_state.file_violations = []
            st.session_state.file_approved = False
            st.session_state.filename = uploaded_file.name
            uploaded_file.seek(0)
            st.session_state.file_data = uploaded_file.read()
            st.session_state.file_checked = False
        
        file_mime = get_mime_type(uploaded_file.name)
        if uploaded_file.type and uploaded_file.type != 'application/octet-stream':
            file_mime = uploaded_file.type
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.info(f"📎 {st.session_state.filename}")
        with col2:
            st.info(f"📊 {len(st.session_state.file_data)/1024:.1f} KB")
        with col3:
            st.info(f"📝 {file_mime}")
        with col4:
            ext = st.session_state.filename.split('.')[-1].upper() if '.' in st.session_state.filename else "不明"
            st.info(f"📄 {ext}")
        
        if file_mime and file_mime.startswith('image/'):
            try:
                image = Image.open(io.BytesIO(st.session_state.file_data))
                st.image(image, caption=f"画像プレビュー: {st.session_state.filename}", width=300)
            except:
                pass
        
        elif file_mime and "text" in file_mime:
            try:
                content = st.session_state.file_data.decode('utf-8', errors='ignore')
                st.text_area("📄 ファイル内容プレビュー", content[:1000], height=150)
                if len(content) > 1000:
                    st.caption(f"... 他 {len(content) - 1000} 文字")
            except:
                pass

    st.divider()

    user_input = st.chat_input("メッセージを入力してください...")

    # ==================== 送信処理 ====================
    if user_input:
        st.session_state.process_start_time = time.time()
        
        with st.chat_message("user"):
            st.write(user_input)
            if uploaded_file:
                st.write(f"📎 {st.session_state.filename}")
        
        file_data = st.session_state.file_data if uploaded_file else None
        filename = st.session_state.filename if uploaded_file else None
        send_target = st.session_state.send_target
        
        if send_target == "message" and not user_input:
            st.error("❌ メッセージが入力されていません")
            st.stop()
        if send_target == "file" and not file_data:
            st.error("❌ ファイルがアップロードされていません")
            st.stop()
        if send_target == "both" and not user_input and not file_data:
            st.error("❌ メッセージとファイルの両方がありません")
            st.stop()
        
        # ==================== Monitorモード ====================
        if st.session_state.operation_mode == "Monitor":
            st.info(f"📊 **Monitorモード**で実行します")
            st.info("🔄 1つ目のリクエスト: 元の内容 → DDS → AI → DDS再検査")
            
            # ============================================================
            # 1つ目のリクエスト: 元の内容をDDSに送信 → AIに送信 → AI回答をDDS再検査
            # ============================================================
            
            # ---- ステップ1: 元の内容をDDSに送信 ----
            step1_start = time.time()
            add_debug_log("Monitor-1-ステップ1", "元の内容をDDSに送信して検査中...", "info")
            status1 = st.info("🔍 [Monitor-1-1] 元の内容をDDSに送信して検査中...")
            
            content_for_dds = get_content_for_dds(file_data, filename, user_input, send_target)
            if not content_for_dds.strip():
                st.error("❌ 送信するコンテンツがありません")
                st.stop()
            
            content_wrapper = MessageWrapper(content_for_dds, "content")
            violations, request_id, response_data, error_info, elapsed1 = send_detection_request(
                content_wrapper,
                "message",
                st.session_state.dds_url,
                st.session_state.verify_ssl,
                data_type="DIM",
                content_block_id="content-001"
            )
            
            if violations is None:
                violations = []
            
            status1.empty()
            st.info(f"✅ [Monitor-1-1] DDS検査完了 (⏱️ {elapsed1:.2f}秒)")
            add_debug_log("Monitor-1-ステップ1", f"DDS検査完了", "success", elapsed1, response_data)
            
            if error_info:
                st.error(f"❌ DDSエラー: {error_info}")
                add_debug_log("Monitor-1-ステップ1", f"エラー: {error_info}", "error", elapsed1)
                st.stop()
            
            if violations and len(violations) > 0:
                policy_names = [v["name"] for v in violations]
                st.warning(f"⚠️ {len(violations)}件のポリシー違反: {', '.join(policy_names)}")
                add_debug_log("Monitor-1-ステップ1", f"ポリシー違反: {', '.join(policy_names)}", "warning", elapsed1)
            else:
                st.success("✅ ポリシー違反はありませんでした")
                add_debug_log("Monitor-1-ステップ1", "ポリシー違反なし", "success", elapsed1)
            
            # ---- ステップ2: AIに送信（元の内容で） ----
            add_debug_log("Monitor-1-ステップ2", "AIにリクエストを送信中...", "info")
            st.info("🤖 [Monitor-1-2] AIにリクエストを送信中...")
            
            ai_messages = []
            for msg in st.session_state.messages:
                if msg["role"] != "assistant" or "violations" not in msg:
                    ai_messages.append({"role": msg["role"], "content": msg["content"]})
            
            current_msg = user_input
            ai_messages.append({"role": "user", "content": current_msg})
            
            start_time = time.time()
            status_placeholder = st.empty()
            status_placeholder.info(f"⏳ AI応答を待っています...")
            
            with st.spinner(f"🤖 {st.session_state.ai_model} に送信中..."):
                if file_data and filename:
                    ai_response, ai_elapsed = call_ai_with_file(
                        ai_messages,
                        file_bytes=file_data,
                        filename=filename,
                        mime_type=get_mime_type(filename),
                        max_tokens=200
                    )
                else:
                    ai_response, ai_elapsed = call_ai_api(ai_messages, max_tokens=200)
            
            status_placeholder.empty()
            elapsed_time = time.time() - start_time
            
            if not ai_response:
                st.error(f"❌ AIからの応答がありませんでした")
                add_debug_log("Monitor-1-ステップ2", f"AI応答なし", "error", ai_elapsed if 'ai_elapsed' in locals() else 0)
                st.stop()
            
            st.success(f"✅ [Monitor-1-2] AIからレスポンスを受信 (⏱️ {ai_elapsed:.2f}秒)")
            add_debug_log("Monitor-1-ステップ2", f"AI応答受信", "success", ai_elapsed)
            
            # ---- ステップ3: AI応答をDDSに送信（再検査） ----
            step3_start = time.time()
            add_debug_log("Monitor-1-ステップ3", "AI応答をDDSに送信して再検査中...", "info")
            st.info("🔍 [Monitor-1-3] AI応答をDDSに送信して再検査中...")
            
            ai_message_wrapper = MessageWrapper(ai_response, "ai_response")
            v2, request_id2, response_data2, error_info2, elapsed3 = send_detection_request(
                ai_message_wrapper,
                "message",
                st.session_state.dds_url,
                st.session_state.verify_ssl,
                data_type="DIM",
                content_block_id="ai-response-001"
            )
            
            if v2 is None:
                v2 = []
            
            st.info(f"✅ [Monitor-1-3] DDS再検査完了 (⏱️ {elapsed3:.2f}秒)")
            add_debug_log("Monitor-1-ステップ3", f"DDS再検査完了", "success", elapsed3, response_data2)
            
            if error_info2:
                st.error(f"❌ DDSエラー: {error_info2}")
                add_debug_log("Monitor-1-ステップ3", f"エラー: {error_info2}", "error", elapsed3)
                st.stop()
            
            # DDSレスポンスを整形
            dds_response_text = format_dds_response(response_data2, v2, request_id2)
            
            # ---- ステップ4: 1つ目の結果表示 ----
            if v2 and len(v2) > 0:
                policy_names = [v["name"] for v in v2]
                st.warning(f"⚠️ AI応答に{len(v2)}件のポリシー違反: {', '.join(policy_names)}")
                add_debug_log("Monitor-1-ステップ4", f"AI応答にポリシー違反: {', '.join(policy_names)}", "warning", elapsed3)
                
                error_msg = f"⚠️ AIの回答にDLP違反が検出されました（違反: {', '.join(policy_names)}）\n\n---\n{ai_response}"
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": error_msg,
                    "violations": v2,
                    "dds_response": dds_response_text
                })
                with st.chat_message("assistant"):
                    st.warning(f"⚠️ AIの回答にDLP違反が検出されました")
                    st.write(ai_response)
                    st.caption(f"⏱️ 応答時間: {elapsed_time:.2f}秒")
                    with st.expander("📋 DDSレスポンス詳細", expanded=False):
                        st.markdown(dds_response_text)
            else:
                st.success("✅ AI応答にポリシー違反はありません")
                add_debug_log("Monitor-1-ステップ4", "AI応答にポリシー違反なし", "success", elapsed3)
                
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": ai_response,
                    "violations": [],
                    "dds_response": dds_response_text
                })
                with st.chat_message("assistant"):
                    st.write(ai_response)
                    st.caption(f"⏱️ 応答時間: {elapsed_time:.2f}秒")
                    with st.expander("📋 DDSレスポンス詳細", expanded=False):
                        st.markdown(dds_response_text)
            
            # ============================================================
            # 2つ目のリクエスト: 情報チェックAI分析結果をDDSに送信
            # ============================================================
            st.divider()
            st.info("🔄 2つ目のリクエスト: 情報チェックAI分析結果 → DDS")
            
            # ---- ステップ5: 情報チェックAIを実行 ----
            info_items_enabled = [x for x in st.session_state.info_check_items if x.get("enabled")]
            info_result = None
            info_elapsed = 0
            
            if info_items_enabled:
                add_debug_log("Monitor-2-ステップ1", "情報チェックAIで分析中...", "info")
                st.info("🔍 [Monitor-2-1] 情報チェックAIで分析中...")
                
                info_result, info_elapsed = run_information_check_ai(
                    file_data,
                    filename,
                    user_input,
                    info_items_enabled
                )
                
                if info_result:
                    st.success(f"✅ [Monitor-2-1] 情報チェックAI分析完了 (⏱️ {info_elapsed:.2f}秒)")
                    add_debug_log(
                        "Monitor-2-ステップ1",
                        "情報チェックAI分析完了",
                        "success",
                        info_elapsed,
                        {
                            "check_items": [x["name"] for x in info_items_enabled],
                            "response": info_result
                        }
                    )
                    with st.expander("🔎 情報チェックAI分析結果", expanded=True):
                        st.code(info_result, language="text")
                else:
                    st.warning("⚠️ 情報チェックAIの分析結果を取得できませんでした")
                    add_debug_log("Monitor-2-ステップ1", "分析結果を取得できませんでした", "error", info_elapsed)
            
            # ---- ステップ6: 情報チェックAIの結果をDDSに送信 ----
            if info_result:
                step6_start = time.time()
                add_debug_log("Monitor-2-ステップ2", "情報チェックAI分析結果をDDSに送信...", "info")
                st.info("🔍 [Monitor-2-2] 情報チェックAI分析結果をDDSに送信して検査中...")
                
                info_check_wrapper = MessageWrapper(info_result, "info_check_result")
                v3, request_id3, response_data3, error_info3, elapsed6 = send_detection_request(
                    info_check_wrapper,
                    "message",
                    st.session_state.dds_url,
                    st.session_state.verify_ssl,
                    data_type="DIM",
                    content_block_id="info-check-001"
                )
                
                if v3 is None:
                    v3 = []
                
                st.info(f"✅ [Monitor-2-2] DDS検査完了 (⏱️ {elapsed6:.2f}秒)")
                add_debug_log("Monitor-2-ステップ2", f"情報チェック結果DDS検査完了", "success", elapsed6, response_data3)
                
                if error_info3:
                    st.error(f"❌ DDSエラー: {error_info3}")
                    add_debug_log("Monitor-2-ステップ2", f"エラー: {error_info3}", "error", elapsed6)
                else:
                    # DDSレスポンスを整形（情報チェック用）
                    info_dds_response = format_dds_response(response_data3, v3, request_id3)
                    
                    # 結果表示
                    if v3 and len(v3) > 0:
                        policy_names = [v["name"] for v in v3]
                        st.warning(f"⚠️ 情報チェックAI分析結果に{len(v3)}件のポリシー違反: {', '.join(policy_names)}")
                        add_debug_log("Monitor-2-ステップ3", f"情報チェック結果にポリシー違反: {', '.join(policy_names)}", "warning", elapsed6)
                    else:
                        st.success("✅ 情報チェックAI分析結果にポリシー違反はありません")
                        add_debug_log("Monitor-2-ステップ3", "情報チェック結果にポリシー違反なし", "success", elapsed6)
                    
                    # 情報チェックのDDSレスポンスをメッセージとして追加
                    info_msg = f"📊 **情報チェックAI分析結果のDDS検査**\n\n"
                    if v3 and len(v3) > 0:
                        policy_names = [v["name"] for v in v3]
                        info_msg += f"⚠️ 検出された違反: {', '.join(policy_names)}\n\n"
                    else:
                        info_msg += "✅ 違反は検出されませんでした\n\n"
                    info_msg += "---\n"
                    info_msg += f"**分析結果:**\n```\n{info_result}\n```\n\n"
                    info_msg += "---\n"
                    info_msg += info_dds_response
                    
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": info_msg,
                        "violations": v3,
                        "dds_response": info_dds_response,
                        "is_info_check": True
                    })
                    with st.chat_message("assistant"):
                        st.markdown(info_msg)
            else:
                st.warning("⚠️ 情報チェックAIの結果がないため、DDSへの送信をスキップしました")
            
            st.success(f"✅ **Monitorモード完了** (合計: {time.time() - st.session_state.process_start_time:.2f}秒)")
            add_debug_log("Monitor-完了", f"全ての処理が完了しました", "success", time.time() - st.session_state.process_start_time)
        
        # ==================== Inlineモード ====================
        else:
            st.info(f"📊 **Inlineモード**で実行します")
            
            # ステップ1: AIに送信
            add_debug_log("Inline-ステップ1", "AIにリクエストを送信中...", "info")
            st.info("🤖 [Inline-1] AIにリクエストを送信中...")
            
            ai_messages = []
            for msg in st.session_state.messages:
                if msg["role"] != "assistant" or "violations" not in msg:
                    ai_messages.append({"role": msg["role"], "content": msg["content"]})
            
            current_msg = user_input
            ai_messages.append({"role": "user", "content": current_msg})
            
            start_time = time.time()
            status_placeholder = st.empty()
            status_placeholder.info(f"⏳ AI応答を待っています...")
            
            with st.spinner(f"🤖 {st.session_state.ai_model} に送信中..."):
                if file_data and filename:
                    ai_response, ai_elapsed = call_ai_with_file(
                        ai_messages,
                        file_bytes=file_data,
                        filename=filename,
                        mime_type=get_mime_type(filename),
                        max_tokens=200
                    )
                else:
                    ai_response, ai_elapsed = call_ai_api(ai_messages, max_tokens=200)
            
            status_placeholder.empty()
            elapsed_time = time.time() - start_time
            
            if not ai_response:
                st.error(f"❌ AIからの応答がありませんでした")
                add_debug_log("Inline-ステップ1", f"AI応答なし", "error", ai_elapsed if 'ai_elapsed' in locals() else 0)
                st.stop()
            
            st.success(f"✅ [Inline-1] AIからレスポンスを受信 (⏱️ {ai_elapsed:.2f}秒)")
            add_debug_log("Inline-ステップ1", f"AI応答受信", "success", ai_elapsed)
            
            # ステップ2: AI応答をDDSに送信（結果非表示）
            step2_start = time.time()
            add_debug_log("Inline-ステップ2", "AI応答をDDSに送信（結果非表示）...", "info")
            st.info("🔍 [Inline-2] AI応答をDDSに送信して検査中（結果は非表示）...")
            
            ai_message_wrapper = MessageWrapper(ai_response, "ai_response")
            v2, request_id2, response_data2, error_info2, elapsed2 = send_detection_request(
                ai_message_wrapper,
                "message",
                st.session_state.dds_url,
                st.session_state.verify_ssl,
                data_type="DIM",
                content_block_id="ai-response-001"
            )
            
            if v2 is None:
                v2 = []
            
            if st.session_state.debug_mode:
                add_debug_log("Inline-ステップ2", f"AI応答DDS検査完了 (違反: {len(v2)}件)", 
                             "warning" if v2 else "success", elapsed2, response_data2)
            
            st.info(f"✅ [Inline-2] DDS検査完了 (⏱️ {elapsed2:.2f}秒)")
            
            # 情報チェックAI分析（デバッグログのみ）
            info_items_enabled = [x for x in st.session_state.info_check_items if x.get("enabled")]
            if info_items_enabled:
                add_debug_log("Inline-情報チェックAI", "情報チェックAIで分析中...", "info")
                
                info_result, info_elapsed = run_information_check_ai(
                    file_data,
                    filename,
                    user_input,
                    info_items_enabled
                )
                
                if info_result:
                    add_debug_log(
                        "Inline-情報チェックAI",
                        "情報チェックAI分析完了",
                        "success",
                        info_elapsed,
                        {
                            "check_items": [x["name"] for x in info_items_enabled],
                            "response": info_result
                        }
                    )
            
            # ステップ3: 元の内容をDDSに送信
            step3_start = time.time()
            add_debug_log("Inline-ステップ3", "元の内容をDDSに送信...", "info")
            st.info("🔍 [Inline-3] 元の内容をDDSに送信して検査中...")
            
            content_for_dds = get_content_for_dds(file_data, filename, user_input, send_target)
            if not content_for_dds.strip():
                st.error("❌ 送信するコンテンツがありません")
                st.stop()
            
            content_wrapper = MessageWrapper(content_for_dds, "content")
            violations, request_id, response_data, error_info, elapsed3 = send_detection_request(
                content_wrapper,
                "message",
                st.session_state.dds_url,
                st.session_state.verify_ssl,
                data_type="DIM",
                content_block_id="content-001"
            )
            
            if violations is None:
                violations = []
            
            st.info(f"✅ [Inline-3] DDS検査完了 (⏱️ {elapsed3:.2f}秒)")
            add_debug_log("Inline-ステップ3", f"元の内容DDS検査完了", "success", elapsed3, response_data)
            
            if error_info:
                st.error(f"❌ DDSエラー: {error_info}")
                add_debug_log("Inline-ステップ3", f"エラー: {error_info}", "error", elapsed3)
                st.stop()
            
            # ステップ4: 違反チェック
            if violations and len(violations) > 0:
                policy_names = [v["name"] for v in violations]
                st.error(f"🚫 ポリシー違反が検出されました: {', '.join(policy_names)}")
                st.error("❌ AIを継続で利用できません")
                add_debug_log("Inline-ステップ4", f"ポリシー違反: {', '.join(policy_names)} - AI利用不可", "error", elapsed3)
                
                # DDSレスポンスを整形
                dds_response_text = format_dds_response(response_data, violations, request_id)
                
                error_msg = f"🚫 ポリシー違反が検出されたため、AIを継続で利用できません。\n違反: {', '.join(policy_names)}"
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": error_msg,
                    "violations": violations,
                    "dds_response": dds_response_text
                })
                with st.chat_message("assistant"):
                    st.error(error_msg)
                    with st.expander("📋 DDSレスポンス詳細", expanded=False):
                        st.markdown(dds_response_text)
            else:
                st.success("✅ ポリシー違反はありません - AI回答を表示")
                add_debug_log("Inline-ステップ4", "ポリシー違反なし - AI回答を表示", "success", elapsed3)
                
                # DDSレスポンスを整形
                dds_response_text = format_dds_response(response_data, violations, request_id)
                
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": ai_response,
                    "violations": [],
                    "dds_response": dds_response_text
                })
                with st.chat_message("assistant"):
                    st.write(ai_response)
                    st.caption(f"⏱️ 応答時間: {elapsed_time:.2f}秒")
                    with st.expander("📋 DDSレスポンス詳細", expanded=False):
                        st.markdown(dds_response_text)
            
            st.success(f"✅ **Inlineモード完了** (合計: {time.time() - st.session_state.process_start_time:.2f}秒)")
            add_debug_log("Inline-完了", f"全ての処理が完了しました", "success", time.time() - st.session_state.process_start_time)
        
        st.rerun()

# ==================== デバッグパネル ====================
if show_debug and debug_col is not None:
    with debug_col:
        st.subheader("📋 デバッグログ")
        st.caption(f"🕐 最終更新: {datetime.now().strftime('%H:%M:%S')}")
        st.divider()
        
        if st.button("🗑️ ログクリア", key="clear_logs_top_btn", use_container_width=True):
            clear_debug_logs()
            st.rerun()
        
        st.divider()
        
        with st.container(height=550):
            render_debug_logs()
