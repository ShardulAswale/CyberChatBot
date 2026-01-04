from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeSerializer
from passlib.context import CryptContext

from .config import Config
from .db import (
    kpi_events_collection,
    training_datasets_collection,
    users_collection,
)
from .kpi import emit_kpi_event

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
session_serializer = URLSafeSerializer(Config.session_secret or "change-me", salt="training-session")

STATUS_NOT_STARTED = "NOT_STARTED"
STATUS_IN_PROGRESS = "IN_PROGRESS"
STATUS_PASSED = "PASSED"

ACTIVE_DATASET_CACHE: Dict[str, Any] | None = None
DATASET_LOCK = asyncio.Lock()


async def load_active_dataset(force: bool = False) -> Dict[str, Any]:
    global ACTIVE_DATASET_CACHE
    if ACTIVE_DATASET_CACHE and not force:
        return ACTIVE_DATASET_CACHE
    async with DATASET_LOCK:
        if ACTIVE_DATASET_CACHE and not force:
            return ACTIVE_DATASET_CACHE
        doc = await training_datasets_collection.find_one({"active": True})
        if not doc:
            raise HTTPException(status_code=503, detail="No active training dataset.")
        levels_raw = doc.get("levels") or {}
        levels: Dict[str, Dict[str, Any]] = {}
        level_sequence: List[str] = []
        for level_key in sorted(levels_raw.keys()):
            level_sequence.append(level_key)
            level_payload = levels_raw[level_key] or {}
            modules = level_payload.get("modules") or {}
            module_items = list(modules.items())
            module_items.sort(key=lambda item: item[1].get("module_name") or item[0])
            parsed_modules: Dict[str, Dict[str, Any]] = {}
            order: List[str] = []
            for module_id, module_data in module_items:
                questions = module_data.get("questions") or []
                questions_sorted = sorted(
                    questions,
                    key=lambda q: q.get("question_index", 0),
                )[:5]
                parsed_modules[module_id] = {
                    "module_id": module_id,
                    "module_name": module_data.get("module_name", module_id),
                    "questions": questions_sorted,
                }
                order.append(module_id)
            levels[level_key] = {
                "badge": level_payload.get("badge", level_key),
                "modules": parsed_modules,
                "order": order,
            }
        version = doc.get("version") or doc.get("dataset_id") or str(doc.get("_id"))
        cache = {
            "version": version,
            "levels": levels,
            "level_sequence": level_sequence,
        }
        ACTIVE_DATASET_CACHE = cache
        return cache


def hash_password(password: str) -> str:
    # bcrypt only supports first 72 bytes; guard to avoid runtime errors
    safe = password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.hash(safe)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(password, hashed)
    except Exception:
        return False


def build_default_progress(dataset: Dict[str, Any]) -> Dict[str, Any]:
    version = dataset["version"]
    modules: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for level in dataset["level_sequence"]:
        modules[level] = {}
        for module_id in dataset["levels"][level]["order"]:
            modules[level][module_id] = {"status": STATUS_NOT_STARTED, "attempts": 0}
    first_level = dataset["level_sequence"][0] if dataset["level_sequence"] else "level_1"
    return {
        "dataset_version": version,
        "unlocked_level": first_level,
        "modules": modules,
        "active_attempt": None,
        "badges": {},
        "preferred_lang": "en",
    }


async def ensure_training_progress(user_doc: Dict[str, Any]) -> Dict[str, Any]:
    dataset = await load_active_dataset()
    progress = user_doc.get("training_progress")
    if not progress or progress.get("dataset_version") != dataset["version"]:
        progress = build_default_progress(dataset)
        await users_collection.update_one(
            {"_id": user_doc["_id"]}, {"$set": {"training_progress": progress}}
        )
        user_doc["training_progress"] = progress
        return progress
    changed = False
    for level in dataset["level_sequence"]:
        if level not in progress["modules"]:
            progress["modules"][level] = {}
            changed = True
        for module_id in dataset["levels"][level]["order"]:
            if module_id not in progress["modules"][level]:
                progress["modules"][level][module_id] = {"status": STATUS_NOT_STARTED, "attempts": 0}
                changed = True
    if changed:
        await users_collection.update_one(
            {"_id": user_doc["_id"]}, {"$set": {"training_progress": progress}}
        )
        user_doc["training_progress"] = progress
    return progress


def set_session_cookie(response: RedirectResponse, user_id: str) -> None:
    token = session_serializer.dumps({"user_id": user_id})
    response.set_cookie(
        "training_session",
        token,
        max_age=7 * 24 * 3600,
        httponly=True,
        samesite="lax",
    )


def clear_session_cookie(response: RedirectResponse) -> None:
    response.delete_cookie("training_session")


async def get_session_user(request: Request) -> Optional[Dict[str, Any]]:
    token = request.cookies.get("training_session")
    if not token:
        return None
    try:
        payload = session_serializer.loads(token)
    except BadSignature:
        return None
    user_id = payload.get("user_id")
    if not user_id:
        return None
    user = await users_collection.find_one({"user_id": user_id})
    if not user:
        return None
    await ensure_training_progress(user)
    return user


async def require_login(request: Request) -> Dict[str, Any]:
    user = await get_session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Login required")
    return user


def render_form_page(title: str, body: str) -> str:
    return f"""
    <html>
      <head>
        <title>{title}</title>
        <style>
          body {{ font-family:'Inter',sans-serif; background:#eef2ff; margin:0; }}
          .card {{ max-width:420px; margin:4rem auto; background:#fff; padding:2rem; border-radius:18px; box-shadow:0 25px 50px rgba(15,45,89,0.15); }}
          input {{ width:100%; padding:0.75rem; margin:0.4rem 0 1rem; border-radius:12px; border:1px solid #ced4f2; }}
          button {{ width:100%; padding:0.85rem; border:none; border-radius:999px; background:#2e7ef9; color:#fff; font-weight:700; cursor:pointer; }}
          a {{ color:#2e7ef9; text-decoration:none; }}
        </style>
      </head>
      <body>
        <div class="card">
          {body}
        </div>
      </body>
    </html>
    """


def render_login_page(error: Optional[str] = None) -> HTMLResponse:
    err_html = f"<p style='color:#d62828;'>{error}</p>" if error else ""
    body = f"""
      <h2>Training Login</h2>
      {err_html}
      <form method="post">
        <label>Email</label>
        <input type="email" name="email" required>
        <label>Password</label>
        <input type="password" name="password" required>
        <button type="submit">Sign in</button>
      </form>
      <p style="margin-top:1rem;">Need an account? <a href="/training/signup">Create one</a></p>
    """
    return HTMLResponse(render_form_page("Training Login", body))


def render_signup_page(error: Optional[str] = None) -> HTMLResponse:
    err_html = f"<p style='color:#d62828;'>{error}</p>" if error else ""
    body = f"""
      <h2>Create account</h2>
      {err_html}
      <form method="post">
        <label>Email</label>
        <input type="email" name="email" required>
        <label>Password</label>
        <input type="password" name="password" required minlength="8">
        <button type="submit">Sign up</button>
      </form>
      <p style="margin-top:1rem;">Already have an account? <a href="/training/login">Sign in</a></p>
    """
    return HTMLResponse(render_form_page("Training Sign Up", body))


def localized_question(question: Dict[str, Any], lang: str) -> Dict[str, Any]:
    languages = question.get("languages") or {}
    payload = languages.get(lang) or languages.get("en") or {}
    options = payload.get("options") or {}
    ordered = [("A", options.get("A", "")), ("B", options.get("B", "")), ("C", options.get("C", "")), ("D", options.get("D", ""))]
    return {
        "info": payload.get("info", ""),
        "question": payload.get("question", ""),
        "options": ordered,
        "correct_option": payload.get("correct_option") or question.get("correct_option"),
        "explanation": payload.get("explanation") or question.get("explanation"),
    }


def render_dashboard(user: Dict[str, Any], dataset: Dict[str, Any]) -> HTMLResponse:
    progress = user["training_progress"]
    lang = progress.get("preferred_lang", "en")
    current_level = progress.get("unlocked_level", dataset["level_sequence"][0])
    level_data = dataset["levels"].get(current_level, {})
    module_cards = ""
    passed_modules = 0
    total_modules = len(level_data.get("order", []))
    for module_id in level_data.get("order", []):
        module_info = level_data["modules"][module_id]
        module_state = progress["modules"][current_level][module_id]
        status = module_state["status"]
        attempts = module_state.get("attempts", 0)
        if status == STATUS_PASSED:
            passed_modules += 1
        button_label = "Resume" if status == STATUS_IN_PROGRESS else "Start"
        disabled = "" if status in {STATUS_NOT_STARTED, STATUS_IN_PROGRESS} else "disabled"
        module_cards += f"""
        <div class="module-card">
          <div>
            <h4>{module_info['module_name']}</h4>
            <p>Status: {status} · Attempts: {attempts}</p>
          </div>
          <form method="post" action="/training/module/start">
            <input type="hidden" name="module_id" value="{module_id}">
            <button type="submit" {disabled}>{button_label}</button>
          </form>
        </div>
        """
    badge = dataset["levels"].get(current_level, {}).get("badge", current_level)
    level_index = dataset["level_sequence"].index(current_level) + 1 if current_level in dataset["level_sequence"] else 1
    html = f"""
    <html>
      <head>
        <title>Training Dashboard</title>
        <style>
          body {{ font-family:'Inter',sans-serif; margin:0; background:#f0f4ff; }}
          header {{ background:#152347; color:#fff; padding:1.5rem; }}
          main {{ max-width:960px; margin:1.5rem auto; }}
          .summary {{ background:#fff; padding:1.5rem; border-radius:20px; box-shadow:0 20px 45px rgba(17,37,86,0.15); margin-bottom:1rem; }}
          .modules {{ background:#fff; padding:1.5rem; border-radius:20px; box-shadow:0 15px 35px rgba(20,44,90,0.12); }}
          .module-card {{ display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #ecf0ff; padding:0.8rem 0; }}
          .module-card:last-child {{ border-bottom:none; }}
          button {{ padding:0.45rem 1.4rem; border:none; border-radius:12px; background:#2e7ef9; color:#fff; cursor:pointer; }}
          button:disabled {{ opacity:0.5; cursor:not-allowed; }}
          form.inline {{ display:inline-block; margin-left:1rem; }}
        </style>
      </head>
      <body>
        <header>
          <h2>Dataset {dataset['version']} · Level {level_index} ({badge.title()})</h2>
          <p>Logged in as {user.get('email') or user.get('user_id')}</p>
          <p><a style="color:#fff;" href="/training/logout">Log out</a> · <a style="color:#fff;" href="/admin/kpi">Admin KPI</a></p>
        </header>
        <main>
          <section class="summary">
            <p>Modules passed in this level: {passed_modules} / {total_modules}</p>
            <form class="inline" method="post" action="/training/language">
              <label>Language:
                <select name="lang" onchange="this.form.submit()">
                  <option value="en" {"selected" if lang=='en' else ""}>English</option>
                  <option value="es" {"selected" if lang=='es' else ""}>Español</option>
                </select>
              </label>
            </form>
          </section>
          <section class="modules">
            <h3>Level modules</h3>
            {module_cards or "<p>No modules configured.</p>"}
          </section>
        </main>
      </body>
    </html>
    """
    return HTMLResponse(html)


def render_question_page(
    user: Dict[str, Any],
    dataset: Dict[str, Any],
    module_id: str,
    question: Dict[str, Any],
    lang_data: Dict[str, Any],
    feedback: Optional[Dict[str, Any]] = None,
) -> HTMLResponse:
    progress = user["training_progress"]
    module_level = feedback.get("level") if feedback else progress["active_attempt"]["level"]
    module_name = dataset["levels"][module_level]["modules"][module_id]["module_name"]
    info = lang_data["info"]
    prompt = lang_data["question"]
    if feedback:
        form_html = f"""
        <form method="post" action="/training/module/next">
          <input type="hidden" name="module_id" value="{module_id}">
          <button type="submit">Next question</button>
        </form>
        """
        options_html = "".join(
            f"<label class='{'correct' if label == feedback.get('correct_option') else ('incorrect' if label == feedback.get('selected_option') else '')}'>({label}) {text}</label>"
            for label, text in lang_data["options"]
        )
    else:
        options_html = "".join(
            f"<label><input type='radio' name='choice' value='{label}' required> ({label}) {text}</label>"
            for label, text in lang_data["options"]
        )
        form_html = f"""
        <form method="post" action="/training/module/answer">
          {options_html}
          <input type="hidden" name="module_id" value="{module_id}">
          <button type="submit">Submit answer</button>
        </form>
        """
        options_html = ""
    feedback_html = ""
    if feedback:
        message = "Correct!"
        explanation = feedback.get("explanation") or ""
        selected_text = next((t for lbl, t in lang_data["options"] if lbl == feedback.get("selected_option")), "")
        correct_text = next((t for lbl, t in lang_data["options"] if lbl == feedback.get("correct_option")), "")
        feedback_html = f"""
        <div class="feedback ok">
          <p>{message}</p>
          <p>Your answer: ({feedback.get('selected_option')}) {selected_text}</p>
          <p>Correct answer: ({feedback.get('correct_option')}) {correct_text}</p>
          <p>{explanation}</p>
        </div>
        """
    html = f"""
    <html>
      <head>
        <title>{module_name}</title>
        <style>
          body {{ font-family:'Inter',sans-serif; margin:0; background:#f5f7ff; }}
          .container {{ max-width:900px; margin:2rem auto; background:#fff; padding:2rem; border-radius:24px; box-shadow:0 25px 55px rgba(20,32,78,0.15); }}
          .info {{ background:#e8f1ff; padding:1rem; border-radius:16px; margin-bottom:1rem; }}
          label {{ display:block; padding:0.75rem; margin:0.5rem 0; border-radius:12px; border:1px solid #dfe5ff; }}
          label.correct {{ border-color:#38b000; background:#e9f7e9; }}
          label.incorrect {{ border-color:#d62828; background:#ffe5e5; }}
          button {{ padding:0.8rem 2rem; border:none; border-radius:999px; background:#2e7ef9; color:#fff; font-weight:700; cursor:pointer; }}
          .feedback {{ border-radius:14px; padding:1rem; margin-top:1rem; }}
          .feedback.ok {{ border:2px solid #38b000; }}
        </style>
      </head>
      <body>
        <div class="container">
          <h2>{module_name}</h2>
          <div class="info">Info: {info}</div>
          <p><strong>{prompt}</strong></p>
          {options_html}
          {form_html}
          {feedback_html}
        </div>
      </body>
    </html>
    """
    return HTMLResponse(html)


def render_module_result_page(
    user: Dict[str, Any],
    dataset: Dict[str, Any],
    level: str,
    module_id: str,
    passed: bool,
    attempts: int,
    message: str,
    detail_html: str = "",
) -> HTMLResponse:
    module_name = dataset["levels"][level]["modules"][module_id]["module_name"]
    html = f"""
    <html>
      <head>
        <title>Module result</title>
        <style>
          body {{ font-family:'Inter',sans-serif; background:#edf2ff; }}
          .card {{ max-width:640px; margin:3rem auto; background:#fff; padding:2rem; border-radius:24px; box-shadow:0 25px 55px rgba(20,50,108,0.2); }}
          .status {{ font-weight:700; color:{"#1b5e20" if passed else "#b71c1c"}; }}
          a.button {{ display:inline-block; margin-top:1rem; padding:0.8rem 2rem; background:#2e7ef9; color:#fff; border-radius:999px; text-decoration:none; }}
        </style>
      </head>
      <body>
        <div class="card">
          <h2>{module_name}</h2>
          <p class="status">{'PASS' if passed else 'FAILED'}</p>
          <p>{message}</p>
          <p>Total attempts: {attempts}</p>
          {detail_html}
          <a class="button" href="/training">Return to dashboard</a>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(html)


async def start_module_attempt(user: Dict[str, Any], module_id: str) -> RedirectResponse:
    dataset = await load_active_dataset()
    progress = user["training_progress"]
    current_level = progress["unlocked_level"]
    level_modules = dataset["levels"].get(current_level, {}).get("modules", {})
    if module_id not in level_modules:
        return RedirectResponse("/training", status_code=303)
    module_state = progress["modules"][current_level][module_id]
    module_state["status"] = STATUS_IN_PROGRESS
    module_state["attempts"] += 1
    question_indexes = [
        q.get("question_index", idx)
        for idx, q in enumerate(level_modules[module_id]["questions"])
    ][:5]
    progress["active_attempt"] = {
        "level": current_level,
        "module_id": module_id,
        "question_index": 0,
        "question_order": question_indexes,
        "answers": [],
    }
    await users_collection.update_one({"_id": user["_id"]}, {"$set": {"training_progress": progress}})
    emit_kpi_event(
        event_type="module_start",
        user_id=user["user_id"],
        dataset_version=dataset["version"],
        level=current_level,
        module_id=module_id,
    )
    return RedirectResponse(f"/training/module/{module_id}", status_code=303)


async def get_current_question(
    user: Dict[str, Any],
    dataset: Dict[str, Any],
) -> Tuple[Dict[str, Any], str, int]:
    progress = user["training_progress"]
    attempt = progress.get("active_attempt") or {}
    level = attempt.get("level")
    module_id = attempt.get("module_id")
    q_idx_pos = attempt.get("question_index", 0)
    order = attempt.get("question_order") or []
    if not level or not module_id or q_idx_pos >= len(order):
        raise HTTPException(status_code=400, detail="No active question.")
    module = dataset["levels"][level]["modules"][module_id]
    question_index = order[q_idx_pos]
    questions = module["questions"]
    match = next((q for q in questions if q.get("question_index") == question_index), None)
    if match is None and question_index < len(questions):
        match = questions[question_index]
    if match is None:
        raise HTTPException(status_code=404, detail="Question not found.")
    return match, module_id, level


async def handle_question_answer(user: Dict[str, Any], choice: str) -> HTMLResponse:
    dataset = await load_active_dataset()
    progress = user["training_progress"]
    attempt = progress.get("active_attempt")
    if not attempt:
        return RedirectResponse("/training", status_code=303)
    question, module_id, level = await get_current_question(user, dataset)
    lang = progress.get("preferred_lang", "en")
    lang_data = localized_question(question, lang)
    is_correct = choice == lang_data["correct_option"]
    emit_kpi_event(
        event_type="question_answered",
        user_id=user["user_id"],
        dataset_version=dataset["version"],
        level=level,
        module_id=module_id,
        question_index=question.get("question_index"),
        correct=is_correct,
    )
    feedback = {
        "is_correct": is_correct,
        "selected_option": choice,
        "correct_option": lang_data["correct_option"],
        "explanation": lang_data.get("explanation"),
        "level": level,
        "module_id": module_id,
    }
    if not is_correct:
        progress["modules"][level][module_id]["status"] = STATUS_NOT_STARTED
        progress["active_attempt"] = None
        await users_collection.update_one({"_id": user["_id"]}, {"$set": {"training_progress": progress}})
        emit_kpi_event(
            event_type="module_failed",
            user_id=user["user_id"],
            dataset_version=dataset["version"],
            level=level,
            module_id=module_id,
        )
        message = "Incorrect answer. Please review the module guidance and try again."
        selected_text = next((t for lbl, t in lang_data["options"] if lbl == choice), "")
        correct_text = next((t for lbl, t in lang_data["options"] if lbl == lang_data["correct_option"]), "")
        detail = f"<p>Your answer: ({choice}) {selected_text}<br>Correct answer: ({lang_data['correct_option']}) {correct_text}</p>"
        return render_module_result_page(
            user,
            dataset,
            level,
            module_id,
            False,
            progress["modules"][level][module_id]["attempts"],
            message,
            detail_html=detail,
        )
    # correct answer
    attempt["question_index"] += 1
    if attempt["question_index"] >= len(attempt["question_order"]):
        progress["modules"][level][module_id]["status"] = STATUS_PASSED
        progress["active_attempt"] = None
        await users_collection.update_one({"_id": user["_id"]}, {"$set": {"training_progress": progress}})
        emit_kpi_event(
            event_type="module_passed",
            user_id=user["user_id"],
            dataset_version=dataset["version"],
            level=level,
            module_id=module_id,
        )
        level_modules = progress["modules"][level]
        if all(m["status"] == STATUS_PASSED for m in level_modules.values()):
            current_index = dataset["level_sequence"].index(level)
            if current_index + 1 < len(dataset["level_sequence"]):
                next_level = dataset["level_sequence"][current_index + 1]
                progress["unlocked_level"] = next_level
                progress["badges"][level] = dataset["levels"][level]["badge"]
                await users_collection.update_one({"_id": user["_id"]}, {"$set": {"training_progress": progress}})
                emit_kpi_event(
                    event_type="level_unlocked",
                    user_id=user["user_id"],
                    dataset_version=dataset["version"],
                    level=next_level,
                )
        message = "All questions correct! Module passed."
        attempts = progress["modules"][level][module_id]["attempts"]
        return render_module_result_page(user, dataset, level, module_id, True, attempts, message)
    await users_collection.update_one({"_id": user["_id"]}, {"$set": {"training_progress": progress}})
    return render_question_page(user, dataset, module_id, question, lang_data, feedback={"is_correct": True, "selected_option": choice, "correct_option": lang_data["correct_option"], "explanation": lang_data.get("explanation"), "level": level})


def require_admin(user: Dict[str, Any]) -> None:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")


async def render_admin_dashboard(user: Dict[str, Any], request: Request) -> HTMLResponse:
    require_admin(user)
    dataset = await load_active_dataset()
    version = request.query_params.get("dataset_version") or dataset["version"]
    days = int(request.query_params.get("days") or 30)
    start_dt = datetime.now(timezone.utc) - timedelta(days=days)
    total_users = await users_collection.count_documents({})
    active_users = len(
        await kpi_events_collection.distinct(
            "user_id", {"timestamp_dt": {"$gte": start_dt}}
        )
    )
    progress_cursor = users_collection.find({"training_progress.dataset_version": version})
    module_stats: Dict[str, Dict[str, Dict[str, Any]]] = {}
    level_completion: Dict[str, Dict[str, int]] = {}
    user_rows = []
    async for doc in progress_cursor:
        progress = doc.get("training_progress") or {}
        modules = progress.get("modules") or {}
        unlocked = progress.get("unlocked_level")
        badges = progress.get("badges") or {}
        # per-user summary
        total_passed = 0
        total_attempts = 0
        for level, module_map in modules.items():
            for module_state in module_map.values():
                total_attempts += module_state.get("attempts", 0)
                if module_state.get("status") == STATUS_PASSED:
                    total_passed += 1
        user_rows.append(
            {
                "user": doc.get("email") or doc.get("user_id"),
                "unlocked": unlocked,
                "badge": badges.get(unlocked) if badges else "",
                "passed": total_passed,
                "attempts": total_attempts,
            }
        )
        for level, module_map in modules.items():
            level_completion.setdefault(level, {"total": 0, "complete": 0})
            stats = level_completion[level]
            statuses = list(module_map.values())
            if statuses:
                stats["total"] += 1
                if all(m.get("status") == STATUS_PASSED for m in statuses):
                    stats["complete"] += 1
            module_stats.setdefault(level, {})
            for module_id, state in module_map.items():
                entry = module_stats[level].setdefault(
                    module_id, {"attempts": 0, "passed": 0, "users": 0}
                )
                entry["attempts"] += state.get("attempts", 0)
                entry["users"] += 1
                if state.get("status") == STATUS_PASSED:
                    entry["passed"] += 1
    failures_pipeline = [
        {"$match": {"event_type": "question_answered", "correct": False, "dataset_version": version}},
        {
            "$group": {
                "_id": {"module_id": "$module_id", "question_index": "$question_index"},
                "failures": {"$sum": 1},
            }
        },
        {"$sort": {"failures": -1}},
        {"$limit": 10},
    ]
    failure_rows = []
    async for row in kpi_events_collection.aggregate(failures_pipeline):
        ref = row["_id"]
        failure_rows.append(f"{ref.get('module_id')} · Q{ref.get('question_index')} – {row['failures']} incorrect")
    qa_total = await kpi_events_collection.count_documents(
        {"event_type": "qa_query_received", "timestamp_dt": {"$gte": start_dt}}
    )
    qa_refused = await kpi_events_collection.count_documents(
        {"event_type": "qa_refused", "timestamp_dt": {"$gte": start_dt}}
    )
    qa_answered = await kpi_events_collection.count_documents(
        {"event_type": "qa_answered", "timestamp_dt": {"$gte": start_dt}}
    )
    web_used = await kpi_events_collection.count_documents(
        {"event_type": "web_search_used", "timestamp_dt": {"$gte": start_dt}}
    )
    refusal_rate = (qa_refused / qa_total * 100) if qa_total else 0
    web_rate = (web_used / qa_answered * 100) if qa_answered else 0
    level_rows = ""
    for level, stats in level_completion.items():
        rate = (stats["complete"] / stats["total"] * 100) if stats["total"] else 0
        level_rows += f"<li>{level}: {rate:.1f}% completion</li>"
    module_rows = ""
    for level, level_modules in module_stats.items():
        module_rows += f"<h4>{level}</h4><ul>"
        for module_id, stats in level_modules.items():
            pass_rate = (stats["passed"] / stats["users"] * 100) if stats["users"] else 0
            avg_attempts = stats["attempts"] / stats["users"] if stats["users"] else 0
            module_rows += f"<li>{module_id}: Pass rate {pass_rate:.1f}% · Avg attempts {avg_attempts:.2f}</li>"
        module_rows += "</ul>"
    user_table = "".join(
        f"<tr><td>{row['user']}</td><td>{row['unlocked']}</td><td>{row['badge']}</td><td>{row['passed']}</td><td>{row['attempts']}</td></tr>"
        for row in user_rows
    )
    html = f"""
    <html>
      <head>
        <title>Admin KPI</title>
        <style>
          body {{ font-family:'Inter',sans-serif; margin:0; background:#f6f9ff; }}
          .card {{ max-width:960px; margin:2rem auto; background:#fff; padding:2rem; border-radius:20px; box-shadow:0 25px 55px rgba(12,40,92,0.15); }}
          ul {{ padding-left:1.2rem; }}
          table {{ width:100%; border-collapse:collapse; margin-top:1rem; }}
          th, td {{ border-bottom:1px solid #e8ecf8; padding:0.6rem; text-align:left; }}
          th {{ background:#f5f7ff; }}
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Admin KPI dashboard</h2>
          <p>Total users: {total_users} · Active last 7 days: {active_users}</p>
          <p>Dataset version: {version}</p>
          <form method="get" style="margin:1rem 0;">
            <label>Days
              <input type="number" name="days" value="{days}" min="1" max="90">
            </label>
            <label style="margin-left:1rem;">Dataset version
              <input type="text" name="dataset_version" value="{version}">
            </label>
            <button type="submit">Apply</button>
          </form>
          <h3>Level completion</h3>
          <ul>{level_rows or "<li>No data</li>"}</ul>
          <h3>Per-module performance</h3>
          {module_rows or "<p>No module data.</p>"}
          <h3>Most failed questions</h3>
          <ul>{"".join(f"<li>{row}</li>" for row in failure_rows) or "<li>No failures recorded.</li>"}</ul>
          <h3>Q&A stats (last {days} days)</h3>
          <p>Total queries: {qa_total} · Refusal rate: {refusal_rate:.1f}% · Web search usage: {web_rate:.1f}%</p>
          <h3>Users (current dataset)</h3>
          <table>
            <thead><tr><th>User</th><th>Unlocked level</th><th>Badge</th><th>Modules passed</th><th>Total attempts</th></tr></thead>
            <tbody>{user_table or "<tr><td colspan='5'>No users</td></tr>"}</tbody>
          </table>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(html)


@router.get("/training/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = await get_session_user(request)
    if user:
        return RedirectResponse("/training", status_code=302)
    return render_login_page()


@router.post("/training/login", response_class=HTMLResponse)
async def login_submit(email: str = Form(...), password: str = Form(...)):
    normalized = email.strip().lower()
    user = await users_collection.find_one({"email": normalized})
    if not user or not verify_password(password, user.get("password_hash", "")):
        return render_login_page("Invalid credentials.")
    await ensure_training_progress(user)
    dataset = await load_active_dataset()
    response = RedirectResponse("/training", status_code=303)
    set_session_cookie(response, user["user_id"])
    emit_kpi_event(
        event_type="training_login",
        user_id=user["user_id"],
        dataset_version=dataset["version"],
    )
    return response


@router.get("/training/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    user = await get_session_user(request)
    if user:
        return RedirectResponse("/training", status_code=302)
    return render_signup_page()


@router.post("/training/signup", response_class=HTMLResponse)
async def signup_submit(email: str = Form(...), password: str = Form(...)):
    normalized = email.strip().lower()
    if len(password.encode("utf-8")) > 72:
        return render_signup_page("Password is too long (max 72 bytes for bcrypt).")
    if len(password) < 8:
        return render_signup_page("Password must be at least 8 characters.")
    existing = await users_collection.find_one({"email": normalized})
    if existing:
        return render_signup_page("Account already exists.")
    dataset = await load_active_dataset()
    user_doc = {
        "user_id": normalized,
        "email": normalized,
        "password_hash": hash_password(password),
        "role": "user",
        "training_progress": build_default_progress(dataset),
        "created_at": datetime.now(timezone.utc).timestamp(),
    }
    await users_collection.insert_one(user_doc)
    response = RedirectResponse("/training", status_code=303)
    set_session_cookie(response, normalized)
    emit_kpi_event(
        event_type="training_login",
        user_id=normalized,
        dataset_version=dataset["version"],
    )
    return response


@router.get("/training/logout")
async def logout():
    response = RedirectResponse("/training/login", status_code=302)
    clear_session_cookie(response)
    return response


@router.get("/training", response_class=HTMLResponse)
async def training_dashboard(request: Request):
    user = await get_session_user(request)
    if not user:
        return RedirectResponse("/training/login", status_code=302)
    dataset = await load_active_dataset()
    await ensure_training_progress(user)
    return render_dashboard(user, dataset)


@router.post("/training/language")
async def update_language(request: Request, lang: str = Form("en")):
    try:
        user = await require_login(request)
    except HTTPException:
        return RedirectResponse("/training/login", status_code=302)
    lang = (lang or "en").lower()
    if lang not in {"en", "es"}:
        lang = "en"
    progress = user["training_progress"]
    progress["preferred_lang"] = lang
    await users_collection.update_one({"_id": user["_id"]}, {"$set": {"training_progress": progress}})
    return RedirectResponse("/training", status_code=303)


@router.post("/training/module/start")
async def module_start(request: Request, module_id: str = Form(...)):
    try:
        user = await require_login(request)
    except HTTPException:
        return RedirectResponse("/training/login", status_code=302)
    return await start_module_attempt(user, module_id)


@router.get("/training/module/{module_id}", response_class=HTMLResponse)
async def module_question(request: Request, module_id: str):
    try:
        user = await require_login(request)
    except HTTPException:
        return RedirectResponse("/training/login", status_code=302)
    dataset = await load_active_dataset()
    progress = user["training_progress"]
    attempt = progress.get("active_attempt")
    if not attempt or attempt.get("module_id") != module_id:
        return RedirectResponse("/training", status_code=302)
    question, _, _ = await get_current_question(user, dataset)
    lang = progress.get("preferred_lang", "en")
    lang_data = localized_question(question, lang)
    return render_question_page(user, dataset, module_id, question, lang_data, None)


@router.post("/training/module/answer", response_class=HTMLResponse)
async def module_answer(request: Request, module_id: str = Form(...), choice: str = Form(...)):
    try:
        user = await require_login(request)
    except HTTPException:
        return RedirectResponse("/training/login", status_code=302)
    progress = user["training_progress"]
    attempt = progress.get("active_attempt")
    if not attempt or attempt.get("module_id") != module_id:
        return RedirectResponse("/training", status_code=303)
    selected = choice.strip().upper()
    if selected not in {"A", "B", "C", "D"}:
        return RedirectResponse(f"/training/module/{module_id}", status_code=303)
    return await handle_question_answer(user, selected)


@router.post("/training/module/next", response_class=HTMLResponse)
async def module_next(request: Request, module_id: str = Form(...)):
    try:
        user = await require_login(request)
    except HTTPException:
        return RedirectResponse("/training/login", status_code=302)
    progress = user["training_progress"]
    attempt = progress.get("active_attempt")
    if not attempt or attempt.get("module_id") != module_id:
        return RedirectResponse("/training", status_code=303)
    dataset = await load_active_dataset()
    question, _, _ = await get_current_question(user, dataset)
    lang = progress.get("preferred_lang", "en")
    lang_data = localized_question(question, lang)
    return render_question_page(user, dataset, module_id, question, lang_data, None)


@router.get("/admin/kpi", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    user = await get_session_user(request)
    if not user:
        return RedirectResponse("/training/login", status_code=302)
    return await render_admin_dashboard(user, request)


async def ensure_training_indexes() -> None:
    await training_datasets_collection.create_index("active")
    await training_datasets_collection.create_index("dataset_id", unique=True)
    await users_collection.create_index("user_id", unique=True)
    await users_collection.create_index("email", unique=True, sparse=True)
    await kpi_events_collection.create_index("timestamp_dt")
    await kpi_events_collection.create_index("event_type")


async def init_training() -> None:
    if not Config.training_enabled:
        return
    try:
        await ensure_training_indexes()
        await load_active_dataset(force=True)
    except Exception as exc:
        # Do not block app startup if Mongo is unavailable; training routes will still attempt to load when used.
        print("Training init skipped due to database error:", exc)
