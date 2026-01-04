import json
import re
import time
import hmac
import hashlib
from uuid import uuid4
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from .config import Config
from .db import users_collection
from .pipeline import ResponsePipeline, slack_response_formatter
from .training import router as training_router, init_training

app = FastAPI(title="Cyber Awareness Bot", version="2.0")

SLACK_SIGNING_SECRET = Config.slack_signing_secret
SLACK_BOT_TOKEN = Config.slack_bot_token
client = WebClient(token=SLACK_BOT_TOKEN) if SLACK_BOT_TOKEN else None

pipeline = ResponsePipeline()
app.include_router(training_router)


@app.on_event("startup")
async def startup_event():
    await init_training()


MODULE_LIBRARY = [
    {
        "id": "cyber_foundations",
        "title": "Cyber Awareness Foundations",
        "description": "Three quick stages to reinforce phishing defence, password hygiene, and device safety.",
        "completion_badge": "Cyber Foundations Graduate",
        "stages": [
            {
                "id": "phishing_basics",
                "title": "Spotting Phishing Attempts",
                "content": (
                    "Watch for mismatched sender domains, urgent or threatening language, and requests for credentials. "
                    "Always hover over links and verify the sender through a trusted channel."
                ),
                "question": {
                    "prompt": "You receive an email marked URGENT telling you to reset your payroll password via a link. What should you do first?",
                    "options": {
                        "A": "Click the link quickly before the deadline lapses.",
                        "B": "Forward the email to all colleagues as a warning.",
                        "C": "Verify the request with HR or IT using a known channel before acting.",
                        "D": "Reply asking for more information.",
                    },
                    "correct": "C",
                    "explanation": "Always validate unusual requests via an official channel before clicking links or sharing data.",
                },
                "badge": "Phishing Spotter",
            },
            {
                "id": "password_stage",
                "title": "Password & MFA Hygiene",
                "content": (
                    "Use long, unique passwords stored in a manager and enable MFA everywhere. "
                    "Never reuse credentials across services."
                ),
                "question": {
                    "prompt": "What is the safest way to protect multiple work accounts?",
                    "options": {
                        "A": "Memorise one strong password and reuse it.",
                        "B": "Write every password on a desk note for quick access.",
                        "C": "Use a password manager with unique passwords plus MFA on each critical account.",
                        "D": "Rotate between three favourite passwords.",
                    },
                    "correct": "C",
                    "explanation": "Password managers + MFA stop credential stuffing and accidental reuse.",
                },
                "badge": "Credential Guardian",
            },
            {
                "id": "device_stage",
                "title": "Secure Devices & Networks",
                "content": (
                    "Keep software patched, use company VPN on public Wi-Fi, and report lost devices immediately. "
                    "Lock your screen when you step away."
                ),
                "question": {
                    "prompt": "You must reply to email on airport Wi-Fi. What is the safest approach?",
                    "options": {
                        "A": "Connect directly; public Wi-Fi is fine for email.",
                        "B": "Use your company VPN before accessing any corporate systems.",
                        "C": "Create a new password just for the airport.",
                        "D": "Delay patches until you return to the office.",
                    },
                    "correct": "B",
                    "explanation": "A VPN encrypts traffic on untrusted networks and protects company data.",
                },
                "badge": "Secure Connectivity Pro",
            },
        ],
    }
]

MODULES = {module["id"]: module for module in MODULE_LIBRARY}
DEFAULT_MODULE_ID = MODULE_LIBRARY[0]["id"]


async def ensure_user_document(user_id: str) -> dict:
    doc = await users_collection.find_one({"user_id": user_id})
    if doc:
        return doc
    now = time.time()
    doc = {
        "user_id": user_id,
        "created_at": now,
        "updated_at": now,
        "badges": [],
        "module_active_id": None,
        "module_stage_idx": None,
    }
    result = await users_collection.insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc


async def update_user_fields(user_doc: dict, data: dict):
    await users_collection.update_one({"_id": user_doc["_id"]}, {"$set": data})
    user_doc.update(data)


async def award_badge(user_doc: dict, badge: str) -> bool:
    badges = user_doc.get("badges") or []
    if badge in badges:
        return False
    badges.append(badge)
    await update_user_fields(user_doc, {"badges": badges, "updated_at": time.time()})
    return True


def render_stage(module: dict, stage_idx: int) -> str:
    stage = module["stages"][stage_idx]
    question = stage["question"]
    lines = [
        f"Module: {module['title']}",
        f"Stage {stage_idx + 1} of {len(module['stages'])}: {stage['title']}",
        "",
        stage["content"],
        "",
        "Knowledge Check:",
        question["prompt"],
        "",
    ]
    for label, text in question["options"].items():
        lines.append(f"{label}) {text}")
    lines.append("")
    lines.append("Reply with A, B, C, or D to answer.")
    return "\n".join(lines)


def render_badges(user_doc: dict) -> str:
    badges = user_doc.get("badges") or []
    if not badges:
        return "You have not earned any badges yet. Start a module to earn your first badge!"
    lines = ["Your badges:"]
    for badge in badges:
        lines.append(f"- {badge}")
    return "\n".join(lines)


def render_modules() -> str:
    lines = ["Available awareness modules:"]
    for module in MODULE_LIBRARY:
        lines.append(
            f"- {module['id']}: {module['title']} ({len(module['stages'])} stages)"
        )
    return "\n".join(lines)


def extract_choice(text: str) -> str | None:
    cleaned = (text or "").strip().upper()
    if not cleaned:
        return None
    if cleaned in {"A", "B", "C", "D"} and len(cleaned) <= 2:
        return cleaned
    if cleaned.startswith("ANSWER"):
        parts = cleaned.split()
        if len(parts) >= 2 and parts[1] in {"A", "B", "C", "D"}:
            return parts[1]
    if len(cleaned) <= 6 and cleaned[-1:] in {"A", "B", "C", "D"}:
        return cleaned[-1:]
    return None


async def begin_module(user_doc: dict, module_id: str | None) -> str:
    module_key = module_id or DEFAULT_MODULE_ID
    module = MODULES.get(module_key)
    if not module:
        return f"Module `{module_key}` was not found. Use 'list modules' to see available options."

    await update_user_fields(
        user_doc,
        {
            "module_active_id": module_key,
            "module_stage_idx": 0,
            "updated_at": time.time(),
        },
    )
    intro = [
        f"🎯 Starting module: {module['title']}",
        module["description"],
        "",
        "Earn badges by completing each stage's knowledge check.",
        "",
        render_stage(module, 0),
    ]
    return "\n".join(intro)


async def handle_module_answer(user_doc: dict, choice: str) -> str:
    module_id = user_doc.get("module_active_id")
    stage_idx = user_doc.get("module_stage_idx")
    if module_id is None or stage_idx is None:
        return "You do not have an active module. Type 'start module' to begin."

    module = MODULES.get(module_id)
    if not module:
        await update_user_fields(
            user_doc, {"module_active_id": None, "module_stage_idx": None}
        )
        return "Your module configuration changed. Start again with 'start module'."

    stage = module["stages"][stage_idx]
    question = stage["question"]
    correct = question["correct"].upper()

    if choice != correct:
        return (
            f"❌ Not quite. {question['explanation']}\n"
            "Review the stage guidance above and try again."
        )

    badge_name = stage.get("badge")
    badge_msg = ""
    if badge_name:
        earned = await award_badge(user_doc, badge_name)
        if earned:
            badge_msg = f"\n🏅 Badge earned: {badge_name}"

    next_stage_idx = stage_idx + 1
    if next_stage_idx >= len(module["stages"]):
        completion_badge = module.get("completion_badge")
        completion_msg = ""
        if completion_badge:
            earned = await award_badge(user_doc, completion_badge)
            if earned:
                completion_msg = f"\n🎉 Module complete! New badge unlocked: {completion_badge}"
        await update_user_fields(
            user_doc,
            {"module_active_id": None, "module_stage_idx": None, "updated_at": time.time()},
        )
        return (
            f"✅ Correct! You cleared the final stage.{badge_msg}{completion_msg}\n"
            "Type 'start module' to replay or 'badges' to view your achievements."
        )

    await update_user_fields(
        user_doc,
        {"module_stage_idx": next_stage_idx, "updated_at": time.time()},
    )
    next_stage_msg = render_stage(module, next_stage_idx)
    return f"✅ Correct!{badge_msg}\n\n{next_stage_msg}"


async def module_status(user_doc: dict) -> str:
    module_id = user_doc.get("module_active_id")
    stage_idx = user_doc.get("module_stage_idx")
    if module_id is None or stage_idx is None:
        return "You are not in an active module. Type 'start module' to begin."
    module = MODULES.get(module_id)
    if not module:
        return "Active module details were not found. Start a new module with 'start module'."
    return render_stage(module, stage_idx)


async def handle_module_commands(user_doc: dict, text: str):
    normalized = (text or "").strip()
    lower = normalized.lower()
    if not normalized:
        return None, user_doc

    if lower.startswith("list modules"):
        return render_modules(), user_doc

    if lower.startswith("module help"):
        help_text = (
            "Module commands:\n"
            "- 'start module' or 'start module <id>' to begin.\n"
            "- 'list modules' to view available modules.\n"
            "- 'module status' to repeat the current stage.\n"
            "- 'badges' to see badges earned so far.\n"
            "- Answer knowledge checks by replying with A, B, C, or D."
        )
        return help_text, user_doc

    if lower.startswith("badges"):
        return render_badges(user_doc), user_doc

    if lower.startswith("module status"):
        status = await module_status(user_doc)
        return status, user_doc

    if lower.startswith("start module"):
        parts = normalized.split()
        module_id = parts[2] if len(parts) >= 3 else None
        msg = await begin_module(user_doc, module_id)
        return msg, user_doc

    if user_doc.get("module_active_id"):
        choice = extract_choice(normalized)
        if choice:
            msg = await handle_module_answer(user_doc, choice)
            return msg, user_doc

    return None, user_doc


def verify_slack(req: Request, raw_body: bytes):
    timestamp = req.headers.get("X-Slack-Request-Timestamp")
    signature = req.headers.get("X-Slack-Signature")

    if not timestamp or not signature:
        raise HTTPException(status_code=401, detail="Missing Slack headers")

    if abs(time.time() - int(timestamp)) > 300:
        raise HTTPException(status_code=401, detail="Stale timestamp")

    basestring = f"v0:{timestamp}:{raw_body.decode()}"
    computed = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(), basestring.encode(), hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(computed, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/web", response_class=HTMLResponse)
def training_start_page():
    return """
    <html>
      <head>
        <title>Cybersecurity Training Launch</title>
        <style>
          body { font-family: sans-serif; margin: 2rem; max-width: 720px; }
          input { padding: 0.5rem; width: 100%; margin-bottom: 1rem; }
          button { padding: 0.75rem 1.5rem; cursor: pointer; }
          a { margin-left: 1rem; }
        </style>
      </head>
      <body>
        <h1>Cybersecurity Training</h1>
        <p>Enter your email or user ID to begin the 10-question knowledge check.</p>
        <input id="user" value="guest@chatz.com" />
        <button onclick="startTraining()">Start Training</button>
        <a href="/web/chat">Switch to Q&A assistant</a>
        <script>
          function startTraining(){
            const user = encodeURIComponent(document.getElementById('user').value || 'guest@chatz.com');
            window.location.href = `/training?user=${user}`;
          }
        </script>
      </body>
    </html>
    """


@app.get("/web/chat", response_class=HTMLResponse)
def web_chat_ui():
    return """
    <html>
      <head>
        <title>Cyber Awareness Assistant</title>
        <style>
          body { font-family: sans-serif; margin: 2rem; max-width: 800px; }
          textarea { width: 100%; height: 120px; margin-top: 1rem; }
          button { margin-top: 0.5rem; padding: 0.5rem 1rem; }
          pre { background: #f6f6f6; padding: 1rem; border-radius: 4px; white-space: pre-wrap; }
        </style>
      </head>
      <body>
        <h2>Cyber Awareness Assistant</h2>
        <div>
          <label>User ID</label>
          <input id="user" value="web_user_1" />
        </div>
        <textarea id="text" placeholder="Ask a cybersecurity awareness question..."></textarea>
        <button onclick="sendMsg()">Send</button>
        <pre id="resp"></pre>
        <script>
          async function sendMsg(){
            const payload = { user_id: document.getElementById('user').value, text: document.getElementById('text').value };
            const res = await fetch('/web/message', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload)
            });
            const data = await res.json();
            document.getElementById('resp').textContent = data.message || '';
          }
        </script>
      </body>
    </html>
    """



@app.post("/web/message")
async def web_message(payload: dict):
    user = (payload.get("user_id") or "web_user").strip() or "web_user"
    text = (payload.get("text") or "").strip()
    user_doc = await ensure_user_document(user)

    module_msg, user_doc = await handle_module_commands(user_doc, text)
    if module_msg:
        return JSONResponse(
            {"user": user, "message": module_msg, "request_id": str(uuid4())}
        )

    response = pipeline.generate(
        user_input=text,
        channel="web",
        session_id=user,
    )
    formatted = slack_response_formatter(response.info, response.answer, response.sources)
    return JSONResponse({"user": user, "message": formatted, "request_id": response.request_id})


@app.post("/teams/webhook")
async def teams_webhook(req: Request):
    payload = await req.json()
    text = (payload.get("text") or "").strip()
    user = ((payload.get("from") or {}).get("id") or "teams_user").strip()

    response = pipeline.generate(
        user_input=text,
        channel="teams",
        session_id=user,
    )

    formatted = slack_response_formatter(response.info, response.answer, response.sources)
    return {"text": formatted}


@app.post("/slack/events")
async def slack_events(req: Request, bg: BackgroundTasks):
    if not client:
        raise HTTPException(status_code=503, detail="Slack client not configured")

    if req.headers.get("X-Slack-Retry-Num"):
        return {"ok": True}

    raw_body = await req.body()
    verify_slack(req, raw_body)

    data = json.loads(raw_body.decode() or "{}")

    if data.get("type") == "url_verification":
        return {"challenge": data.get("challenge")}

    if data.get("type") != "event_callback":
        return {"ok": True}

    event = data.get("event", {})
    if "bot_id" in event:
        return {"ok": True}

    event_type = event.get("type")
    channel_type = event.get("channel_type")
    if not (
        event_type == "app_mention" or (event_type == "message" and channel_type == "im")
    ):
        return {"ok": True}

    user = event.get("user")
    channel = event.get("channel")
    text = event.get("text", "") or ""
    cleaned = re.sub(r"<@[^>]+>", "", text).strip()

    async def reply():
        try:
            response = pipeline.generate(
                user_input=cleaned,
                channel="slack",
                session_id=user or str(uuid4()),
            )
            formatted = slack_response_formatter(response.info, response.answer, response.sources)
            client.chat_postMessage(channel=channel, text=formatted)
        except SlackApiError as exc:
            print("Slack API error:", exc)
        except Exception as exc:
            print("Slack handler error:", exc)

    bg.add_task(reply)
    return {"ok": True}
