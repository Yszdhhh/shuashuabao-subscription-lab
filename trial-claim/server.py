#!/usr/bin/env python3
"""Loopback trial-claim page. No admin credentials."""
import fcntl
import json
import os
import re
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
from zoneinfo import ZoneInfo

HOST = "127.0.0.1"
PORT = 18012
ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "pool.json")
LOCK = os.path.join(ROOT, "pool.lock")
LOGO = os.path.join(ROOT, "logo.jpg")
GUIDE = os.path.join(ROOT, "guide.jpg")
GUIDE_CLIENT = os.path.join(ROOT, "guide-client.jpg")
PANEL_TANBAO = os.path.join(ROOT, "panel-tanbao.jpg")
SHANGHAI = ZoneInfo("Asia/Shanghai")
OPEN_AT = datetime(2026, 10, 8, 0, 0, tzinfo=SHANGHAI)
END_AT = datetime(2026, 10, 13, 0, 0, tzinfo=SHANGHAI)
CODE_RE = re.compile(r"^[0-9a-fA-F]{64}$")
REF_BONUS_CAP = 10
SHARE_ORIGIN = "https://entitlement.shuashuabao.xyz"
SUBSCRIPTION_BASE = os.environ.get("SHUABAO_SUBSCRIPTION_BASE", "http://127.0.0.1:8010")
ACTIVATE_TIMEOUT = 6
UPLOAD_DIR = os.path.join(ROOT, "uploads")
MAX_SHOT_BYTES = 3 * 1024 * 1024
SHOT_ALLOW_CT = {"image/jpeg", "image/png", "image/webp", "image/gif"}
SHOT_EXT = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif"}


def get_or_create_token(data, code):
    tokens = data.setdefault("ref_tokens", {})
    for tok, owner in tokens.items():
        if owner == code:
            return tok
    tok = secrets.token_hex(8)
    tokens[tok] = code
    return tok


def share_link(token):
    return SHARE_ORIGIN + "/trial?r=" + token

MSG_EARLY = "10 月 8 日 0 点开放领取"
MSG_ENDED = "活动已经结束"
MSG_NEED_CODE = "请输入机器码"
MSG_FORMAT = "机器码格式不对，请从客户端复制完整的 64 位机器码"
MSG_REPEAT = "这台机器已经领过"
MSG_ISSUED = "领取成功！1 天免费试用，一机一卡"
MSG_ACTIVATED = "已为这台机器开通 1 天试用（{exp} 到期），无需填写卡密"
MSG_REPEAT_ACTIVATED = "这台机器已经开通，有效期至 {exp}"
MSG_NEED_SHOT = "请上传进群截图（JPG/PNG，3MB 以内）"
MSG_PENDING = "已提交审核，截图审核通过后自动开通 1 天试用（一般 10 分钟内）。可随时回来输入机器码查询状态。"
MSG_REVIEWING = "截图审核中，请稍后回来输入机器码查询状态。"
MSG_REJECTED = "上次提交的截图未通过审核：{reason}。请按下方要求重新上传截图。"
MSG_EMPTY = "这一批已经发完"
MSG_UNAVAILABLE = "暂时无法领取，请稍后再试"
MSG_CLOSED = "当前没有可领取的试用卡，请关注后续活动"
QQ_GROUP_URL = "https://qun.qq.com/universal-share/share?ac=1&authKey=3NBMhvs9OMuvL17WTeNy%2FkkMq4NHIDx33VS3VWUOnnAQOYmv2B8qCntcE0kJya61&busi_data=eyJncm91cENvZGUiOiIxMTI2NjQ2OTUyIiwidG9rZW4iOiJpWU5qWjFMVFZrdHBHY1hXN09MY3RDK3dpZDRjdGhRTnByUTBqbzVLQm5kWnZNa3BHbDlkMk9rWlNEUFdJeWw4IiwidWluIjoiMjQwNzA0NjY0OCJ9&data=i-2O9knJu6lRkloiGD3UvA5zbmZsrr5OZq1b66arzIQgXazmnv0x8FSDGPf6E4eJumGOzX766efVx30HjIlRGA&svctype=4&tempid=h5_group_info"

STYLE = """<style>
  :root{
    --bg:#f6f7f9; --ink:#14181d; --muted:#5f6873; --line:#e7eaef;
    --card:#ffffff; --accent:#1e4fd6; --accent-soft:#edf2fe;
    --radius:18px; --shadow:0 14px 44px rgba(18,24,40,.08);
  }
  *{box-sizing:border-box}
  html,body{margin:0}
  body{background:var(--bg);color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif;
    font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
  .topbar{background:#14181d;color:#fff}
  .topbar-inner{max-width:680px;margin:0 auto;padding:10px 22px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  .topbar-text{font-size:14px;font-weight:700}
  .topbar-btn{margin-left:auto;background:var(--accent);color:#fff;text-decoration:none;font-size:14px;font-weight:700;padding:8px 18px;border-radius:999px;white-space:nowrap}
  .topbar-qq{font-size:13px;color:#c6cdd6;white-space:nowrap}
  .topbar-qq b{color:#fff}
  .wrap{max-width:680px;margin:0 auto;padding:44px 22px 64px}
  .hero{text-align:center;margin-bottom:24px}
  .logo{width:76px;height:76px;border-radius:20px;box-shadow:0 12px 32px rgba(30,79,214,.22)}
  .eyebrow{margin:14px 0 8px;color:var(--accent);font-size:12px;font-weight:700;letter-spacing:.22em}
  .eyebrow b{font-size:14px;color:var(--accent)}
  h1{margin:0 0 8px;font-size:30px;line-height:1.3;letter-spacing:-.01em}
  .sub{margin:0;color:var(--muted);font-size:14px}
  .countline{margin:12px 0 0;font-size:14px;color:var(--muted)}
  .countline b{color:var(--accent);font-variant-numeric:tabular-nums}
  .card{background:var(--card);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px}
  label{display:block;margin:0 0 8px;font-size:14px;font-weight:700}
  input[type=text]{display:block;width:100%;margin:0;padding:13px 14px;border:1px solid var(--line);border-radius:12px;background:#fff;color:inherit;font:inherit}
  input[type=text]:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:var(--accent)}
  button{display:block;width:100%;margin:12px 0 0;padding:13px 16px;border:0;border-radius:12px;background:var(--accent);color:#fff;font:inherit;font-weight:700;cursor:pointer}
  button:disabled{opacity:.55;cursor:default}
  .helper{margin:10px 0 0;color:var(--muted);font-size:13px}
  .result{margin-top:12px;min-height:0}
  .result:empty{display:none}
  .result.error{color:#b42318}
  .cardbox{margin-top:10px;padding:13px 14px;border-radius:12px;background:var(--accent-soft);font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:15px;word-break:break-all;user-select:all}
  .cardbox[hidden]{display:none}
  .cardbox.backup{font-size:12px;opacity:.75}
  .backup-label{display:block;font-family:system-ui,sans-serif;font-size:12px;opacity:.8;margin-bottom:4px}
  .exp-note{margin-top:6px;font-weight:700;color:var(--accent)}
  .req{color:#b42318;font-size:12px}
  .shot-req{font-size:13px;color:#555;margin:6px 0 12px;line-height:1.7}
  input[type=file]{margin:2px 0 0}
  .section{margin-top:26px}
  .section h2{font-size:16px;margin:0 0 12px}
  .gsteps{list-style:none;margin:0;padding:0;display:grid;gap:12px;counter-reset:gs}
  .gsteps li{counter-increment:gs;position:relative;background:var(--card);border-radius:14px;padding:16px 16px 16px 54px;box-shadow:0 4px 16px rgba(18,24,40,.05)}
  .gsteps li::before{content:counter(gs);position:absolute;left:16px;top:16px;width:24px;height:24px;border-radius:999px;background:var(--accent-soft);color:var(--accent);font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center}
  .gsteps p{margin:0;font-size:15px}
  .gsteps b{color:var(--accent)}
  .gsteps a{color:var(--accent)}
  .guide-img{display:block;width:100%;max-width:400px;margin:10px auto 2px;border-radius:12px;box-shadow:0 4px 16px rgba(18,24,40,.08)}
  .notes{list-style:none;margin:0;padding:0;display:grid;gap:8px}
  .notes li{font-size:14px;color:var(--muted);padding-left:14px;position:relative}
  .notes li::before{content:"·";position:absolute;left:2px;color:var(--accent);font-weight:700}
  .notes a{color:var(--accent);text-decoration:none;font-weight:700}
  .help{text-align:center;color:var(--muted);font-size:14px;margin:24px 0 0}
  .help a{color:var(--accent);text-decoration:none;font-weight:700}
  .invite{margin:12px 0 0;font-size:14px;color:var(--accent);font-weight:700}
  .share{margin-top:14px;padding:14px;border-radius:12px;background:#f0f6ff;border:1px dashed var(--accent)}
  .share[hidden]{display:none}
  .share-title{margin:0 0 8px;font-size:14px;font-weight:700}
  .share-link{margin:0 0 10px;font-size:13px;word-break:break-all;color:var(--muted);user-select:all}
  .share button{margin:0;width:auto;padding:10px 18px;font-size:14px}
  .invite-title{margin:0 0 8px;font-size:17px;font-weight:700}
  .invite-desc{margin:0 0 12px;font-size:13px;color:var(--muted);line-height:1.7}
  .invite-stats{margin:10px 0 0;font-size:13px;color:var(--muted)}
  .invite-card{margin-top:26px}
  .tanbao-card{margin-bottom:26px}
  .tanbao-badge{display:inline-block;margin:0 0 10px;padding:4px 12px;border-radius:999px;background:#fff3d6;color:#8a5a00;font-size:13px;font-weight:700;white-space:nowrap}
  .tanbao-title{margin:0 0 12px;font-size:19px;font-weight:700}
  .tanbao-btn{display:inline-block;margin-top:12px;padding:12px 24px;border-radius:12px;background:var(--accent);color:#fff;font-weight:700;text-decoration:none}
  .door-btn{display:block;margin-top:14px;padding:12px 8px;border-radius:12px;background:var(--accent);color:#fff;font-weight:700;text-decoration:none;text-align:center;font-size:15px}
  .doors{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:26px}
  .doors .card{display:flex;flex-direction:column;margin-bottom:0;padding:20px 16px}
  .doors .notes{margin-bottom:14px}
  .doors .door-btn{margin-top:auto}
  @media(min-width:900px){.wrap.landing{max-width:960px}}
  .invite-hint{margin:0;font-size:13px;color:var(--muted)}
  .copy-ok{margin:8px 0 0;font-size:13px;color:#0a7b3d}
  .bonus{margin-top:12px}
  .bonus[hidden]{display:none}
  .bonus-title{margin:0 0 8px;font-size:14px;font-weight:700;color:var(--accent)}
  .bonus .cardbox{margin-top:8px}
  .bonus-note{margin:8px 0 0 !important;font-size:13px;color:var(--accent)}
  footer{margin-top:26px;text-align:center;color:#9aa1ab;font-size:12px}
  footer a{color:var(--accent);text-decoration:none}
  @media (max-width:640px){.wrap{padding:32px 16px 52px}h1{font-size:25px}.logo{width:68px;height:68px}.gsteps li{padding:14px 14px 14px 48px}}
</style>"""

SCRIPT = """<script>
(function () {
  var m = /[?&]r=([0-9a-f]{16})/.exec(location.search);
  if (m) {
    document.getElementById("refField").value = m[1];
    document.getElementById("invite").hidden = false;
  }
})();
(function () {
  var el = document.getElementById("remainTop");
  if (!el) return;
  function refresh() {
    fetch("/trial/status", { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (d) { el.textContent = d.closed ? "0" : d.remaining; })
      .catch(function () {});
  }
  refresh();
  setInterval(refresh, 30000);
})();
document.getElementById("claim").addEventListener("submit", function (event) {
  event.preventDefault();
  var form = event.target;
  var button = form.querySelector("button");
  var result = document.getElementById("result");
  var card = document.getElementById("card");
  var body = new FormData(form);
  button.disabled = true;
  fetch("/trial/game", { method: "POST", body: body })
    .then(function (response) { return response.json(); })
    .then(function (data) {
      var message = data.message || "";
      var issued = data.card || "";
      var activated = !!data.activated;
      result.textContent = "";
      var pm = document.createElement("div");
      pm.textContent = message;
      result.appendChild(pm);
      if (activated && data.expires_at) {
        var pe = document.createElement("div");
        pe.className = "exp-note";
        pe.textContent = "有效期至 " + data.expires_at + "（北京时间）· 打开客户端即用";
        result.appendChild(pe);
      }
      var okState = issued || activated || data.pending || data.rejected;
      result.className = okState ? "result" : "result error";
      if (issued) {
        card.textContent = "";
        if (activated) {
          var lbl = document.createElement("span");
          lbl.className = "backup-label";
          lbl.textContent = "备用卡密（客户端未自动识别时可手动粘贴）：";
          var kc = document.createElement("span");
          kc.textContent = issued;
          card.appendChild(lbl);
          card.appendChild(kc);
          card.className = "cardbox backup";
        } else {
          card.textContent = issued;
          card.className = "cardbox";
        }
        card.hidden = false;
      } else {
        card.hidden = true;
      }
      var inviteShare = document.getElementById("inviteShare");
      var inviteHint = document.getElementById("inviteHint");
      var bonus = document.getElementById("bonus");
      if (data.token) {
        document.getElementById("inviteShareLink").textContent =
          "https://entitlement.shuashuabao.xyz/trial?r=" + data.token;
        var it0 = data.invite_total || 0, iok0 = data.invite_ok || 0;
        document.getElementById("inviteStats").textContent =
          "已邀请 " + it0 + " 人，成功开通 " + iok0 + " 人";
        inviteHint.hidden = true;
        inviteShare.hidden = false;
        var bc = data.bonus_count || 0, cap = data.bonus_cap || 10;
        var blist = data.bonus_cards || [];
        bonus.innerHTML = "";
        if (bc > 0) {
          bonus.hidden = false;
          var t = document.createElement("p");
          t.className = "bonus-title";
          var it = data.invite_total || 0, iok = data.invite_ok || 0;
          t.textContent = "已邀请 " + it + " 人，成功开通 " + iok + " 人（每人最多 " + cap + " 次奖励）";
          bonus.appendChild(t);
          blist.forEach(function (c) {
            var d = document.createElement("div");
            d.className = "cardbox";
            d.textContent = c;
            bonus.appendChild(d);
          });
        } else {
          bonus.hidden = true;
        }
        if (data.inviter_bonus) {
          var n = document.createElement("p");
          n.className = "bonus-note";
          n.textContent = "你的邀请人也已自动开通 1 天试用";
          result.appendChild(n);
        }
      } else {
        inviteShare.hidden = true;
        inviteHint.hidden = false;
        bonus.hidden = true;
      }
    })
    .catch(function () {
      result.textContent = "暂时无法领取，请稍后再试";
      result.className = "result error";
      card.textContent = "";
      card.hidden = true;
    })
    .then(function () { button.disabled = false; });
});
function copyShareText(linkId, okId) {
  var link = document.getElementById(linkId).textContent;
  var text = "刷刷宝公测：免费领 1 天试用卡（一机一卡）" + link + " 通过我的链接领取，双方各得 1 天～";
  function done() {
    var ok = document.getElementById(okId);
    ok.hidden = false;
    setTimeout(function () { ok.hidden = true; }, 2000);
  }
  function fallback() {
    var ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); done(); } catch (e) {}
    document.body.removeChild(ta);
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, fallback);
  } else {
    fallback();
  }
}
document.getElementById("inviteCopyBtn").addEventListener("click", function () {
  copyShareText("inviteShareLink", "inviteCopyOk");
});
</script>"""

LANDING_SCRIPT = """<script>
(function () {
  var m = /[?&]r=([0-9a-f]{16})/.exec(location.search);
  if (m) {
    var g = document.getElementById("gameDoor");
    if (g) g.href = "/trial/game?r=" + m[1];
  }
})();
</script>"""

PAGE_GAME = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>刷刷宝 · 公测活动</title>
__STYLE__
</head>
<body>
<div class="topbar"><div class="topbar-inner"><span class="topbar-text">加群下载公测安装包</span><a class="topbar-btn" href="__QQ_GROUP_URL__" target="_blank" rel="noopener">加入公测 Q 群</a><span class="topbar-qq">作者 QQ <b>2407046648</b></span></div></div>
<main class="wrap">
  <header class="hero">
    <img class="logo" src="/trial/logo.jpg" alt="刷刷宝">
    <p class="eyebrow">公测活动 · 剩余 <b id="remainTop">…</b> 张</p>
    <h1>输入机器码，开通 1 天试用</h1>
    <p class="sub">一机一卡 · 填机器码自动开通，无需填写卡密</p>
    <p class="invite" id="invite" hidden>通过好友邀请领取，双方各得 1 天试用卡</p>
  </header>

  <section class="card">
    <form id="claim" method="post" action="/trial/game" enctype="multipart/form-data">
      <label for="code">机器码</label>
      <input id="code" name="code" type="text" autocomplete="off" spellcheck="false" maxlength="128" inputmode="text" autofocus>
      <label for="shot">进群截图 <span class="req">必填</span></label>
      <input id="shot" name="shot" type="file" accept="image/jpeg,image/png,image/webp,image/gif">
      <p class="shot-req">请上传你的入群截图，确保截图中能看清群号等关键信息。</p>
      <input type="hidden" id="refField" name="ref" value="">
      <button type="submit">提交审核</button>
    </form>
    <p class="helper">请粘贴客户端里显示的完整机器码。格式不对不会占用名额。已提交过的机器码可直接查询状态。</p>
    <div id="result" class="result" role="status"></div>
    <div id="card" class="cardbox" hidden></div>
    <div id="bonus" class="bonus" hidden></div>
  </section>

  <section class="card invite-card">
    <h2 class="invite-title">邀请好友，双方各得 1 天试用</h2>
    <p class="invite-desc">好友通过你的专属链接领取并审核通过后，你自动多得 1 天试用（每人最多 10 次）。</p>
    <p class="invite-hint" id="inviteHint">在上方提交机器码后，这里会显示你的专属邀请链接。</p>
    <div id="inviteShare" class="share" hidden>
      <p class="share-link" id="inviteShareLink"></p>
      <button type="button" id="inviteCopyBtn">一键复制分享文案</button>
      <p class="copy-ok" id="inviteCopyOk" hidden>已复制，去分享吧</p>
      <p class="invite-stats" id="inviteStats"></p>
    </div>
  </section>

  <section class="section">
    <h2>领取指南</h2>
    <ol class="gsteps">
      <li>
        <p><b>加群下载</b> —— 加入 <a href="__QQ_GROUP_URL__" target="_blank" rel="noopener">公测 Q 群</a>下载公测安装包</p>
      </li>
      <li>
        <p><b>找到「激活卡密」</b> —— 打开客户端，在主界面进入激活卡密页</p>
        <img class="guide-img" src="/trial/guide-client.jpg" alt="客户端主界面">
      </li>
      <li>
        <p><b>复制机器码</b> —— 点击「查看机器码」复制，粘贴到本页上方，自动开通</p>
        <img class="guide-img" src="/trial/guide.jpg" alt="查看机器码">
      </li>
      <li>
        <p><b>打开客户端</b> —— 已自动开通，直接使用（有效期 1 天）</p>
      </li>
    </ol>
  </section>

  <section class="section">
    <h2>说明</h2>
    <ul class="notes">
      <li>本页领取的是游戏脚本《重生魔兽刷刷刷》的 1 天试用；大厅扫雷脚本永久使用 → <a href="/trial/lobby">大厅扫雷</a></li>
      <li>1 天免费试用（开通即起算）· 一机一卡 · 限 1 台设备</li>
      <li>分享好友领取，双方各得 1 天试用卡，每人最多 10 张奖励</li>
      <li>禁止囤积、多领或利用漏洞反复领取，一经发现取消测试资格</li>
    </ul>
  </section>

  <footer><a href="/trial">← 回首页</a> · 需要帮助？<a href="__QQ_GROUP_URL__" target="_blank" rel="noopener">加入公测 Q 群</a>（1126646952）· 作者 QQ 2407046648</footer>
</main>
__SCRIPT__
</body>
</html>
"""

PAGE_LANDING = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>刷刷宝</title>
__STYLE__
</head>
<body>
<div class="topbar"><div class="topbar-inner"><span class="topbar-text">加群下载公测安装包</span><a class="topbar-btn" href="__QQ_GROUP_URL__" target="_blank" rel="noopener">加入公测 Q 群</a><span class="topbar-qq">作者 QQ <b>2407046648</b></span></div></div>
<main class="wrap landing">
  <header class="hero">
    <img class="logo" src="/trial/logo.jpg" alt="刷刷宝">
    <h1>刷刷宝</h1>
    <p class="sub">请选择需要的服务</p>
  </header>

  <div class="doors">
    <section class="card tanbao-card">
      <p class="tanbao-badge">永久使用</p>
      <h2 class="tanbao-title">大厅扫雷</h2>
      <p class="sub">双节探宝</p>
      <ul class="notes">
        <li>自动探宝扫雷，框选棋盘、一键开始/暂停</li>
        <li><b>永久使用，不限天数</b></li>
        <li>群共享文档下载，无需机器码</li>
      </ul>
      <a class="door-btn" href="/trial/lobby">大厅扫雷 →</a>
    </section>

    <section class="card">
      <p class="tanbao-badge">1 天试用</p>
      <h2 class="tanbao-title">游戏内测</h2>
      <p class="sub">重生魔兽刷刷刷</p>
      <ul class="notes">
        <li>游戏脚本 1 天试用</li>
        <li>填机器码 + 进群截图，审核通过开通</li>
        <li>一机一卡 · 限 1 台设备</li>
      </ul>
      <a class="door-btn" id="gameDoor" href="/trial/game">游戏内测 →</a>
    </section>
  </div>

  <footer>需要帮助？<a href="__QQ_GROUP_URL__" target="_blank" rel="noopener">加入公测 Q 群</a>（1126646952）· 作者 QQ 2407046648</footer>
</main>
__SCRIPT__
</body>
</html>
"""

PAGE_LOBBY = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>刷刷宝 · 大厅扫雷</title>
__STYLE__
</head>
<body>
<div class="topbar"><div class="topbar-inner"><span class="topbar-text">加群下载公测安装包</span><a class="topbar-btn" href="__QQ_GROUP_URL__" target="_blank" rel="noopener">加入公测 Q 群</a><span class="topbar-qq">作者 QQ <b>2407046648</b></span></div></div>
<main class="wrap">
  <header class="hero">
    <img class="logo" src="/trial/logo.jpg" alt="刷刷宝">
    <h1>大厅扫雷</h1>
    <p class="sub">双节探宝 · 大厅扫雷助手</p>
  </header>

  <section class="card tanbao-card">
    <p class="tanbao-badge">无需机器码 · 加群即下</p>
    <img class="guide-img" src="/trial/panel-tanbao.jpg" alt="双节探宝扫雷面板">
    <ul class="notes">
      <li>大厅活动脚本：自动探宝扫雷，框选棋盘、一键开始/暂停</li>
      <li><b>永久使用，不限天数</b></li>
      <li>在 <b>公测 Q 群的共享文档（群文件）</b> 里下载，无需机器码、无需领试用卡</li>
      <li>游戏脚本是《重生魔兽刷刷刷》的；不玩这游戏也没关系，进群下载大厅脚本就能用，下载完退群也可以，但退群后大厅脚本有更新你就收不到了，建议留在群里</li>
    </ul>
    <a class="tanbao-btn" href="__QQ_GROUP_URL__" target="_blank" rel="noopener">加入公测 Q 群下载</a>
  </section>

  <p class="help">要领游戏脚本 1 天试用？<a href="/trial/game">刷刷宝内测 →</a></p>
  <p class="help"><a href="/trial">← 回首页</a></p>

  <footer>需要帮助？<a href="__QQ_GROUP_URL__" target="_blank" rel="noopener">加入公测 Q 群</a>（1126646952）· 作者 QQ 2407046648</footer>
</main>
__SCRIPT__
</body>
</html>
"""

PAGE_CLOSED = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>刷刷宝 · 公测活动</title>
__STYLE__
</head>
<body>
<div class="topbar"><div class="topbar-inner"><span class="topbar-text">加群下载公测安装包</span><a class="topbar-btn" href="__QQ_GROUP_URL__" target="_blank" rel="noopener">加入公测 Q 群</a><span class="topbar-qq">作者 QQ <b>2407046648</b></span></div></div>
<main class="wrap">
  <header class="hero">
    <img class="logo" src="/trial/logo.jpg" alt="刷刷宝">
    <p class="eyebrow">公测活动</p>
    <h1>试用卡领取暂未开放</h1>
    <p class="sub">__MSG_CLOSED__</p>
  </header>

  <section class="card tanbao-card">
    <p class="tanbao-badge">永久使用 · 加群即下</p>
    <h2 class="tanbao-title">大厅扫雷</h2>
    <p class="sub">双节探宝 · 大厅扫雷助手，永久使用，群共享文档下载</p>
    <a class="door-btn" href="/trial/lobby">进入大厅扫雷 →</a>
  </section>

  <p class="help">需要帮助？<a href="__QQ_GROUP_URL__" target="_blank" rel="noopener">加入公测 Q 群</a>（1126646952）· 作者 QQ 2407046648</p>

  <footer>刷刷宝 · 公测活动</footer>
</main>
</body>
</html>
"""


def classify(raw):
    text = "" if raw is None else str(raw)
    text = text.strip()
    if not text:
        return "empty", ""
    if CODE_RE.fullmatch(text) is None:
        return "bad", ""
    return "ok", text.lower()


def _locked_update(mutator):
    os.makedirs(ROOT, exist_ok=True)
    lock = open(LOCK, "a", encoding="utf-8")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        os.chmod(LOCK, 0o600)
        if not os.path.exists(DATA):
            return None
        with open(DATA, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        result = mutator(data)
        payload = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        tmp = DATA + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
        os.chmod(tmp, 0o600)
        os.replace(tmp, DATA)
        os.chmod(DATA, 0o600)
        return result
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def pool_status():
    """Return (remaining_cards, closed). Closed when pool.json is missing/unreadable,
    has "closed": true, or has no cards left."""
    try:
        with open(DATA, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        return 0, True
    pool = data.get("pool") or []
    return len(pool), bool(data.get("closed")) or not pool


def client_direct_count():
    """Trials claimed via the client dashboard button (synced by cron)."""
    try:
        with open(os.path.join(ROOT, "client_direct.count"), encoding="utf-8") as fh:
            return max(0, int(fh.read().strip() or 0))
    except (OSError, ValueError):
        return 0


def display_remaining():
    """Page-facing remaining: web pool minus client-direct claims (floor 0)."""
    remaining, _ = pool_status()
    return max(0, remaining - client_direct_count())


def is_closed():
    return pool_status()[1]


def activate_on_subscription(card_key, machine_code):
    """Bind card_key to machine_code on the subscription service.

    Returns (True, expires_at_str) on success, (False, reason) on failure.
    Never raises: failures degrade to manual card-key entry.
    """
    try:
        payload = json.dumps({
            "license_key": card_key,
            "hardware": {"fingerprint": machine_code, "components": {}, "platform": "windows"},
        }).encode("utf-8")
        req = urllib.request.Request(
            SUBSCRIPTION_BASE + "/v1/devices/activate",
            data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=ACTIVATE_TIMEOUT) as resp:
            dto = json.loads(resp.read().decode("utf-8"))
        # Prefer the subscription service's authoritative expiry (reflects
        # manual/weekend extensions); fall back to activated_at + 1 day.
        exp = None
        try:
            vpayload = json.dumps({
                "license_key": card_key,
                "hardware": {"fingerprint": machine_code, "components": {}, "platform": "windows"},
            }).encode("utf-8")
            vreq = urllib.request.Request(
                SUBSCRIPTION_BASE + "/v1/entitlements/validate",
                data=vpayload, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(vreq, timeout=ACTIVATE_TIMEOUT) as vresp:
                vdto = json.loads(vresp.read().decode("utf-8"))
            vexp = ((vdto.get("license") or {}).get("expires_at") or "")
            if vexp:
                exp = datetime.fromisoformat(vexp.replace("Z", "+00:00")).astimezone(SHANGHAI).strftime("%m月%d日 %H:%M")
        except Exception:
            exp = None
        if exp is None:
            activated_at = str(dto.get("activated_at") or "")
            exp = (datetime.fromisoformat(activated_at.replace("Z", "+00:00"))
                   + timedelta(days=1)).astimezone(SHANGHAI).strftime("%m月%d日 %H:%M")
        return True, exp
    except Exception as exc:
        return False, str(exc)[:120]


def invite_stats(data, code):
    mine = (data.get("invite_log") or {}).get(code) or []
    total = len(mine)
    ok = sum(1 for e in mine if e.get("status") == "approved")
    return total, ok


def build_info(data, code):
    token = get_or_create_token(data, code)
    total, ok = invite_stats(data, code)
    return {"token": token,
            "bonus_count": (data.get("ref_counts") or {}).get(code, 0),
            "bonus_cards": (data.get("ref_cards") or {}).get(code, []),
            "bonus_cap": REF_BONUS_CAP,
            "invite_total": total,
            "invite_ok": ok}


def decide(code, ref=None, shot=None):
    kind, code = classify(code)
    if kind == "bad":
        return {"message": MSG_FORMAT}
    if is_closed():
        return {"message": MSG_CLOSED}
    if kind == "empty":
        return {"message": MSG_NEED_CODE}

    drain_jobs = []
    def mutate(data):
        _drain_review_queue(data, drain_jobs)
        claims = data.setdefault("claims", {})
        pending = data.setdefault("pending", {})
        invlog = data.setdefault("invite_log", {})
        info = build_info(data, code)
        jobs = []
        if code in claims:
            jobs.append((claims[code], code))
            return {"message": MSG_REPEAT, "card": claims[code],
                    "_repeat": True, "_activate": jobs, **info}
        rec = pending.get(code)
        if rec:
            st = rec.get("status")
            if st == "pending":
                return {"message": MSG_REVIEWING, "pending": True, **info}
            if st == "rejected" and shot is None:
                return {"message": MSG_REJECTED.format(reason=rec.get("reason") or "截图不符合要求"),
                        "rejected": True, **info}
        if shot is None:
            return {"message": MSG_NEED_SHOT, **info}
        _fname, ctype, blob = shot
        if ctype not in SHOT_ALLOW_CT or not blob or len(blob) > MAX_SHOT_BYTES:
            return {"message": MSG_NEED_SHOT, **info}
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        spath = os.path.join(UPLOAD_DIR, code + SHOT_EXT.get(ctype, ".jpg"))
        fd = os.open(spath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, blob)
        finally:
            os.close(fd)
        referrer = (data.get("ref_tokens") or {}).get(ref) if ref else None
        if referrer == code:
            referrer = None
        now = datetime.now(timezone.utc).isoformat()
        pending[code] = {"ref": ref or "", "inviter": referrer or "",
                         "shot": os.path.relpath(spath, ROOT),
                         "at": now, "status": "pending", "reason": ""}
        if referrer:
            invlog.setdefault(referrer, []).append(
                {"code": code, "at": now, "status": "pending"})
        return {"message": MSG_PENDING, "pending": True, **build_info(data, code)}

    try:
        result = _locked_update(mutate)
    except Exception:
        return {"message": MSG_UNAVAILABLE}
    if result is None:
        return {"message": MSG_UNAVAILABLE}
    for _card, _fp in drain_jobs:
        try:
            activate_on_subscription(_card, _fp)
        except Exception:
            pass
    jobs = result.pop("_activate", [])
    is_repeat = result.pop("_repeat", False)
    if jobs:
        outcomes = [activate_on_subscription(key, fp) for key, fp in jobs]
        main_ok, main_info = outcomes[0]
        result["activated"] = main_ok
        if main_ok:
            result["expires_at"] = main_info
            tmpl = MSG_REPEAT_ACTIVATED if is_repeat else MSG_ACTIVATED
            result["message"] = tmpl.format(exp=main_info)
        else:
            result["activate_error"] = main_info
    return result


def _read_data():
    if not os.path.exists(DATA):
        return {}
    with open(DATA, "r", encoding="utf-8") as handle:
        return json.load(handle)


def list_pending():
    out = []
    for code, rec in (_read_data().get("pending") or {}).items():
        if rec.get("status") == "pending":
            out.append({"code": code, "at": rec.get("at"), "shot": rec.get("shot"),
                        "inviter": rec.get("inviter") or ""})
    out.sort(key=lambda e: e["at"])
    return out


def approve_pending(code):
    kind, code = classify(code)
    if kind != "ok":
        return {"ok": False, "error": "bad code"}

    def mutate(data):
        pending = data.setdefault("pending", {})
        rec = pending.get(code)
        if not rec or rec.get("status") not in ("pending", "rejected"):
            return {"ok": False, "error": "not pending"}
        claims = data.setdefault("claims", {})
        if code in claims:
            del pending[code]
            return {"ok": False, "error": "already claimed"}
        pool = data.setdefault("pool", [])
        if not pool:
            return {"ok": False, "error": "pool empty"}
        card = pool.pop(0)
        claims[code] = card
        inviter = rec.get("inviter") or ""
        bonus_card = ""
        if inviter:
            counts = data.setdefault("ref_counts", {})
            cards = data.setdefault("ref_cards", {})
            if counts.get(inviter, 0) < REF_BONUS_CAP:
                bpool = data.setdefault("bonus_pool", [])
                if bpool:
                    bonus_card = bpool.pop(0)
                    cards.setdefault(inviter, []).append(bonus_card)
                    counts[inviter] = counts.get(inviter, 0) + 1
            for e in (data.get("invite_log") or {}).get(inviter, []):
                if e.get("code") == code:
                    e["status"] = "approved"
        del pending[code]
        return {"ok": True, "card": card, "inviter": inviter, "bonus_card": bonus_card}

    try:
        result = _locked_update(mutate)
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:120]}
    if not result or not result.get("ok"):
        return result or {"ok": False, "error": "unavailable"}
    ok, info = activate_on_subscription(result["card"], code)
    result["activated"] = ok
    result["activate_info"] = info
    if result.get("bonus_card") and result.get("inviter"):
        bok, _binfo = activate_on_subscription(result["bonus_card"], result["inviter"])
        result["bonus_activated"] = bok
    return result


def reject_pending(code, reason):
    kind, code = classify(code)
    if kind != "ok":
        return {"ok": False, "error": "bad code"}

    def mutate(data):
        pending = data.setdefault("pending", {})
        rec = pending.get(code)
        if not rec or rec.get("status") != "pending":
            return {"ok": False, "error": "not pending"}
        rec["status"] = "rejected"
        rec["reason"] = (reason or "截图不符合要求")[:200]
        for e in (data.get("invite_log") or {}).get(rec.get("inviter") or "", []):
            if e.get("code") == code:
                e["status"] = "rejected"
        return {"ok": True}

    try:
        result = _locked_update(mutate)
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:120]}
    return result or {"ok": False, "error": "unavailable"}


def _drain_review_queue(data, jobs):
    """Apply ops-queued review decisions (one JSON file per decision).

    Runs inside the pool lock as the service user. Appends (card, fingerprint)
    activation jobs for approvals. Consumed files are deleted; unprocessable
    ones (e.g. pool empty) are left for the next drain.
    """
    try:
        names = sorted(os.listdir(os.path.join(ROOT, "review-queue")))
    except Exception:
        return
    pending = data.setdefault("pending", {})
    claims = data.setdefault("claims", {})
    for name in names:
        if not name.endswith(".json"):
            continue
        fpath = os.path.join(ROOT, "review-queue", name)
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                item = json.load(fh)
        except Exception:
            item = None
        consumed = True
        try:
            if not isinstance(item, dict):
                pass
            else:
                action = item.get("action")
                kind, code = classify(item.get("code"))
                if kind == "ok" and action == "approve":
                    rec = pending.get(code)
                    if rec and rec.get("status") in ("pending", "rejected") and code not in claims:
                        pool = data.setdefault("pool", [])
                        if not pool:
                            consumed = False  # retry later
                        else:
                            card = pool.pop(0)
                            claims[code] = card
                            jobs.append((card, code))
                            inviter = rec.get("inviter") or ""
                            if inviter:
                                counts = data.setdefault("ref_counts", {})
                                cards = data.setdefault("ref_cards", {})
                                if counts.get(inviter, 0) < REF_BONUS_CAP:
                                    bpool = data.setdefault("bonus_pool", [])
                                    if bpool:
                                        bcard = bpool.pop(0)
                                        cards.setdefault(inviter, []).append(bcard)
                                        counts[inviter] = counts.get(inviter, 0) + 1
                                        jobs.append((bcard, inviter))
                                for e in (data.get("invite_log") or {}).get(inviter, []):
                                    if e.get("code") == code:
                                        e["status"] = "approved"
                            del pending[code]
                    elif rec and code in claims:
                        del pending[code]
                elif kind == "ok" and action == "reject":
                    rec = pending.get(code)
                    if rec and rec.get("status") == "pending":
                        rec["status"] = "rejected"
                        rec["reason"] = str(item.get("reason") or "截图不符合要求")[:200]
                        for e in (data.get("invite_log") or {}).get(rec.get("inviter") or "", []):
                            if e.get("code") == code:
                                e["status"] = "rejected"
        finally:
            if consumed:
                try:
                    os.remove(fpath)
                except Exception:
                    pass


class _BodyError(ValueError):
    pass


def _read_body(handler, cap):
    """r4 KEEPALIVE-FIX: read the WHOLE request body (Content-Length or Transfer-Encoding: chunked) so no byte is left
    on a keep-alive connection. Raises _BodyError (caller must close the connection) when it cannot be fully consumed."""
    te = (handler.headers.get("Transfer-Encoding") or "").lower()
    if "chunked" in te:
        out = bytearray()
        while True:
            line = handler.rfile.readline(1026)
            if not line.endswith(b"\n"):
                raise _BodyError("bad chunk size line")
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                raise _BodyError("bad chunk size")
            if size == 0:
                while True:  # optional trailers, end with an empty line
                    t = handler.rfile.readline(8194)
                    if t in (b"\r\n", b"\n"):
                        return bytes(out)
                    if not t or not t.endswith(b"\n"):
                        raise _BodyError("bad trailer")
            if size < 0 or len(out) + size > cap:
                raise _BodyError("body too large")
            chunk = handler.rfile.read(size)
            if len(chunk) != size or handler.rfile.readline(3) not in (b"\r\n", b"\n"):
                raise _BodyError("truncated chunk")
            out += chunk
    try:
        length = int(handler.headers.get("Content-Length") or "0")
    except ValueError:
        raise _BodyError("bad Content-Length")
    if length < 0 or length > cap:
        raise _BodyError("body too large")
    data = handler.rfile.read(length) if length else b""
    if len(data) != length:
        raise _BodyError("truncated body")
    return data


def parse_post(handler):
    ctype = handler.headers.get("Content-Type", "")
    try:
        body = _read_body(handler, MAX_SHOT_BYTES + 65536)
    except _BodyError:
        handler.close_connection = True  # r4 KEEPALIVE-FIX: unread bytes -> never reuse this connection
        return None, None
    handler._body_consumed = True
    if not body:
        return None, None
    if ctype.startswith("multipart/form-data"):
        import cgi
        import io
        env = {"REQUEST_METHOD": "POST", "CONTENT_TYPE": ctype,
               "CONTENT_LENGTH": str(len(body))}
        hdrs = {"content-type": ctype, "content-length": str(len(body))}
        form = cgi.FieldStorage(fp=io.BytesIO(body), headers=hdrs,
                                environ=env, keep_blank_values=True)
        fields, files = {}, {}
        for item in form.list or []:
            if item.filename:
                files[item.name] = item
            elif item.name:
                fields[item.name] = item.value if isinstance(item.value, str) else ""
        return fields, files
    raw = body.decode("utf-8", "replace")
    values = parse_qs(raw, keep_blank_values=True)
    return {k: (v[-1] if v else "") for k, v in values.items()}, {}




def _render(template, script):
    html = template.replace("__STYLE__", STYLE)
    html = html.replace("__SCRIPT__", script)
    html = html.replace("__MSG_CLOSED__", MSG_CLOSED)
    html = html.replace("__QQ_GROUP_URL__", QQ_GROUP_URL.replace("&", "&amp;"))
    html = html.replace("__END_ISO__", END_AT.isoformat())
    return html.encode("utf-8")


def page_bytes(closed=None):
    if closed is None:
        closed = is_closed()
    template = PAGE_CLOSED if closed else PAGE_GAME
    return _render(template, SCRIPT)


def landing_bytes():
    return _render(PAGE_LANDING, LANDING_SCRIPT)


def lobby_bytes():
    return _render(PAGE_LOBBY, "")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def parse_request(self):
        self._body_consumed = False  # r4 KEEPALIVE-FIX: per request (one handler instance serves a whole keep-alive connection)
        return super().parse_request()

    def _send(self, status, body, content_type):
        payload = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        # r4 KEEPALIVE-FIX: a request whose body was not fully read (e.g. POST to an unknown path, oversized or malformed
        # body) must not leave bytes on the connection: answer with Connection: close and close it.
        if self.command not in ("GET", "HEAD") and not getattr(self, "_body_consumed", False):
            self.close_connection = True
        if self.close_connection:
            self.send_header("Connection", "close")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/trial/logo.jpg":
            try:
                with open(LOGO, "rb") as handle:
                    data = handle.read()
            except OSError:
                self._send(404, "not found", "text/plain; charset=utf-8")
                return
            self._send(200, data, "image/jpeg")
            return
        if path == "/trial/guide.jpg":
            try:
                with open(GUIDE, "rb") as handle:
                    data = handle.read()
            except OSError:
                self._send(404, "not found", "text/plain; charset=utf-8")
                return
            self._send(200, data, "image/jpeg")
            return
        if path == "/trial/guide-client.jpg":
            try:
                with open(GUIDE_CLIENT, "rb") as handle:
                    data = handle.read()
            except OSError:
                self._send(404, "not found", "text/plain; charset=utf-8")
                return
            self._send(200, data, "image/jpeg")
            return
        if path == "/trial/panel-tanbao.jpg":
            try:
                with open(PANEL_TANBAO, "rb") as handle:
                    data = handle.read()
            except OSError:
                self._send(404, "not found", "text/plain; charset=utf-8")
                return
            self._send(200, data, "image/jpeg")
            return
        if path == "/trial/status":
            _, closed = pool_status()
            self._send(200, json.dumps({"remaining": display_remaining(), "closed": closed}, ensure_ascii=False), "application/json; charset=utf-8")
            return
        if path in ("/trial", "/trial/"):
            if is_closed():
                self._send(200, page_bytes(True), "text/html; charset=utf-8")
            else:
                self._send(200, landing_bytes(), "text/html; charset=utf-8")
            return
        if path == "/trial/game":
            self._send(200, page_bytes(), "text/html; charset=utf-8")
            return
        if path == "/trial/lobby":
            self._send(200, lobby_bytes(), "text/html; charset=utf-8")
            return
        self._send(404, "not found", "text/plain; charset=utf-8")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path not in ("/trial", "/trial/", "/trial/game"):
            self._send(404, "not found", "text/plain; charset=utf-8")
            return
        fields, files = parse_post(self)
        if fields is None:
            self._send(200, json.dumps({"message": MSG_UNAVAILABLE}, ensure_ascii=False), "application/json; charset=utf-8")
            return
        code = fields.get("code", "")
        ref = fields.get("ref", "")
        shot = None
        item = files.get("shot")
        if item is not None and item.file is not None:
            blob = item.file.read(MAX_SHOT_BYTES + 1)
            if blob:
                shot = (item.filename or "", (item.type or "").split(";")[0].strip(), blob)
        result = decide(code, ref=ref, shot=shot)
        self._send(200, json.dumps(result, ensure_ascii=False), "application/json; charset=utf-8")


def self_check():
    import tempfile
    import shutil
    global DATA, LOCK, ROOT, activate_on_subscription, UPLOAD_DIR
    real_activate = activate_on_subscription
    activate_calls = []
    def fake_activate(card_key, machine_code):
        activate_calls.append((card_key, machine_code))
        return True, "10月13日 12:00"
    activate_on_subscription = fake_activate
    tmp = tempfile.mkdtemp(prefix="trial-self-")
    old_upload = UPLOAD_DIR
    UPLOAD_DIR = os.path.join(tmp, "uploads")
    old = (DATA, LOCK, ROOT)
    ROOT = tmp
    DATA = os.path.join(tmp, "pool.json")
    LOCK = os.path.join(tmp, "pool.lock")
    good = "A" * 64
    good_lower = "a" * 64
    other = "b" * 64
    third = "c" * 64
    try:
        assert classify("   ") == ("empty", "")
        assert classify("abc") == ("bad", "")
        assert classify("  " + good + "  ") == ("ok", good_lower)
        assert classify(good_lower + "zz")[0] == "bad"
        junk = decide("abc")
        assert junk == {"message": MSG_FORMAT} and "card" not in junk
        assert not os.path.exists(DATA)
        assert "card" not in decide("   ")
        fd = os.open(DATA, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, json.dumps({"pool": ["CARD-ONE", "CARD-TWO"], "claims": {}}).encode())
        os.close(fd)
        before = json.load(open(DATA, encoding="utf-8"))
        blocked = decide("not-a-code")
        after = json.load(open(DATA, encoding="utf-8"))
        assert blocked["message"] == MSG_FORMAT
        assert after == before
        assert pool_status() == (2, False)
        SHOT = ("s.jpg", "image/jpeg", b"fakeshotbytes")
        # new code without screenshot -> asked to upload, nothing consumed
        noshot = decide("  " + good + "\n")
        assert noshot["message"] == MSG_NEED_SHOT and "card" not in noshot
        assert pool_status() == (2, False)
        # submit with screenshot -> pending
        first = decide("  " + good + "\n", shot=SHOT)
        assert first.get("pending") is True and "card" not in first
        assert "token" in first and len(first["token"]) == 16
        assert first["bonus_count"] == 0 and first["invite_total"] == 0
        stored = json.load(open(DATA, encoding="utf-8"))
        assert stored["pending"][good_lower]["status"] == "pending"
        assert os.path.exists(os.path.join(tmp, "uploads", good_lower + ".jpg"))
        assert pool_status() == (2, False)
        # query while pending
        qp = decide(good_lower)
        assert qp.get("pending") is True and qp["message"] == MSG_REVIEWING
        # approve -> card issued + activated
        ap = approve_pending(good_lower)
        assert ap["ok"] is True and ap["card"] == "CARD-ONE" and ap["activated"] is True
        assert ("CARD-ONE", good_lower) in activate_calls
        # repeat -> same card, re-activated
        again = decide(good_lower)
        assert again["card"] == "CARD-ONE" and again["activated"] is True
        assert "已经开通" in again["message"]
        assert again["token"] == first["token"]
        # second user
        assert decide(other)["message"] == MSG_NEED_SHOT
        other_sub = decide(other, shot=SHOT)
        assert other_sub.get("pending") is True
        assert other_sub["token"] != first["token"]
        # reject + resubmit before pool empties
        rj = reject_pending(other, "看不清群号")
        assert rj["ok"] is True
        qj = decide(other)
        assert qj.get("rejected") is True and "看不清群号" in qj["message"]
        re_sub = decide(other, shot=SHOT)
        assert re_sub.get("pending") is True
        ap2 = approve_pending(other)
        assert ap2["ok"] is True and ap2["card"] == "CARD-TWO"
        assert pool_status() == (0, True)
        # pool empty -> page closed, new submissions get MSG_CLOSED
        gone = decide(third, shot=SHOT)
        assert gone["message"] == MSG_CLOSED and "card" not in gone
        # approve non-pending -> error
        assert approve_pending("d" * 64)["ok"] is False
        assert approve_pending(third)["ok"] is False
        stored = json.load(open(DATA, encoding="utf-8"))
        assert good_lower in stored["claims"]
        assert good not in stored["claims"]
        assert decide("abc")["message"] == MSG_FORMAT
        # ---- referral flow ----
        fd = os.open(DATA, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, json.dumps({"pool": ["P1", "P2", "P3", "P4", "P5"],
                                 "bonus_pool": ["B1", "B2", "B3"],
                                 "claims": {}}).encode())
        os.close(fd)
        activate_calls.clear()
        r1 = decide("e" * 64, shot=SHOT)
        assert r1.get("pending") is True and len(r1["token"]) == 16
        tok = r1["token"]
        r2 = decide("f" * 64, ref=tok, shot=SHOT)
        assert r2.get("pending") is True
        a2 = approve_pending("f" * 64)
        assert a2["ok"] is True and a2["card"] == "P1"
        assert a2.get("bonus_card") == "B1" and a2.get("bonus_activated") is True
        assert ("B1", "e" * 64) in activate_calls
        a1 = approve_pending("e" * 64)
        assert a1["ok"] is True and a1["card"] == "P2"
        r1b = decide("e" * 64)
        assert r1b["bonus_count"] == 1 and r1b["bonus_cards"] == ["B1"]
        assert r1b["invite_total"] == 1 and r1b["invite_ok"] == 1
        assert r1b["token"] == tok
        # bad ref token -> approved without inviter
        r3 = decide("0" * 64, ref="deadbeefdeadbeef", shot=SHOT)
        assert r3.get("pending") is True
        a3 = approve_pending("0" * 64)
        assert a3["ok"] is True and a3["card"] == "P3" and not a3.get("bonus_card")
        st = json.load(open(DATA, encoding="utf-8"))
        assert st["bonus_pool"] == ["B2", "B3"]
        # bonus cap respected at approval time
        st["ref_counts"]["e" * 64] = REF_BONUS_CAP
        json.dump(st, open(DATA, "w", encoding="utf-8"))
        r4 = decide("1" * 64, ref=tok, shot=SHOT)
        assert r4.get("pending") is True
        a4 = approve_pending("1" * 64)
        assert a4["ok"] is True and a4["card"] == "P4" and not a4.get("bonus_card")
        st = json.load(open(DATA, encoding="utf-8"))
        assert st["bonus_pool"] == ["B2", "B3"]
        assert st["ref_counts"]["e" * 64] == REF_BONUS_CAP
        # invite log: e invited f(approved) and 1(approved, no bonus)
        r1c = decide("e" * 64)
        assert r1c["invite_total"] == 2 and r1c["invite_ok"] == 2
        assert share_link(tok).startswith("https://entitlement.shuashuabao.xyz/trial?r=")
        # ---- review queue drain ----
        fd = os.open(DATA, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, json.dumps({"pool": ["Q1", "Q2", "Q3"], "bonus_pool": ["QB1"],
                                 "claims": {}}).encode())
        os.close(fd)
        qd = os.path.join(tmp, "review-queue")
        os.makedirs(qd, exist_ok=True)
        rq_code = "9" * 64
        assert decide(rq_code, shot=SHOT).get("pending") is True
        with open(os.path.join(qd, rq_code + ".json"), "w", encoding="utf-8") as fh:
            json.dump({"action": "approve", "code": rq_code}, fh)
        decide("8" * 64)  # any decide() drains the queue
        st = json.load(open(DATA, encoding="utf-8"))
        assert st["claims"][rq_code] == "Q1" and rq_code not in st.get("pending", {})
        assert not os.path.exists(os.path.join(qd, rq_code + ".json"))
        assert ("Q1", rq_code) in activate_calls
        rj_code = "7" * 64
        assert decide(rj_code, shot=SHOT).get("pending") is True
        with open(os.path.join(qd, rj_code + ".json"), "w", encoding="utf-8") as fh:
            json.dump({"action": "reject", "code": rj_code, "reason": "test-reject"}, fh)
        decide("8" * 64)
        assert not os.path.exists(os.path.join(qd, rj_code + ".json"))
        qj = decide(rj_code)
        assert qj.get("rejected") is True and "test-reject" in qj["message"]
        assert pool_status() == (2, False)
        # re-review: approve a rejected record
        with open(os.path.join(qd, rj_code + ".json"), "w", encoding="utf-8") as fh:
            json.dump({"action": "approve", "code": rj_code}, fh)
        decide("8" * 64)
        st = json.load(open(DATA, encoding="utf-8"))
        assert st["claims"][rj_code] == "Q2" and rj_code not in st.get("pending", {})
        assert ("Q2", rj_code) in activate_calls
        assert pool_status() == (1, False)
        tmp_count = os.path.join(ROOT, "client_direct.count")
        open(tmp_count, "w", encoding="utf-8").write("5\n")
        assert client_direct_count() == 5
        assert display_remaining() == max(0, 1 - 5) == 0
        os.unlink(tmp_count)
        assert client_direct_count() == 0
        assert display_remaining() == 1
        closed_html = page_bytes(True)
        assert MSG_CLOSED.encode() in closed_html and b'name="code"' not in closed_html
        assert b"/trial/logo.jpg" in closed_html
        assert b"qun.qq.com/universal-share" in closed_html
        assert b'/trial/lobby' in closed_html
        assert "大厅扫雷".encode() in closed_html
        html = page_bytes(False)
        assert "输入机器码，开通 1 天试用".encode() in html
        assert b'id="shot"' in html
        assert b'enctype="multipart/form-data"' in html
        assert "双方各得".encode() in html
        assert b'id="refField"' in html
        assert b'<section class="card tanbao-card">' not in html
        assert "无需机器码".encode() not in html
        assert b'/trial/lobby' in html
        assert b'id="inviteHint"' in html
        assert b'id="inviteShareLink"' in html
        assert b'id="inviteCopyBtn"' in html
        assert b'id="inviteStats"' in html
        assert "邀请好友".encode() in html
        assert "群主为作者本人".encode() not in html
        assert "取消测试资格".encode() in html
        assert b'id="remainTop"' in html
        assert b"/trial/guide-client.jpg" in html
        assert "领取指南".encode() in html
        assert "1126646952".encode() in html and "2407046648".encode() in html
        assert b"__OPEN_ISO__" not in html and b"__END_ISO__" not in html
        assert b"__STYLE__" not in html and b"__SCRIPT__" not in html
        assert pool_status() == (1, False)
        assert b"qun.qq.com/universal-share" in html
        assert b"__QQ_GROUP_URL__" not in html
        landing = landing_bytes()
        assert b'/trial/game' in landing and b'/trial/lobby' in landing
        assert b'id="gameDoor"' in landing
        assert "双节探宝".encode() in landing
        assert "无需机器码".encode() in landing
        assert b'class="doors"' in landing
        assert b'class="wrap landing"' in landing
        assert b"@media(min-width:900px){.wrap.landing{max-width:960px}}" in landing
        assert "永久使用".encode() in landing
        assert b'<section class="card tanbao-card">' in landing
        assert b'id="claim"' not in landing
        assert b'id="shot"' not in landing
        assert "输入机器码，开通 1 天试用".encode() not in landing
        assert b"__STYLE__" not in landing and b"__SCRIPT__" not in landing
        assert b"__QQ_GROUP_URL__" not in landing
        lobby = lobby_bytes()
        assert "双节探宝".encode() in lobby
        assert "无需机器码".encode() in lobby
        assert b"/trial/panel-tanbao.jpg" in lobby
        assert "永久使用".encode() in lobby
        assert "共享文档".encode() in lobby
        assert b'<section class="card tanbao-card">' in lobby
        assert b"qun.qq.com/universal-share" in lobby
        assert b'/trial/game' in lobby
        assert b'id="claim"' not in lobby
        assert b'id="shot"' not in lobby
        assert "输入机器码，开通 1 天试用".encode() not in lobby
        assert b"__STYLE__" not in lobby and b"__SCRIPT__" not in lobby
        assert b"__QQ_GROUP_URL__" not in lobby
        print("self_check_ok")
    finally:
        activate_on_subscription = real_activate
        UPLOAD_DIR = old_upload
        DATA, LOCK, ROOT = old
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    os.umask(0o077)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()


# =============================================================================================
# r3 (entitlement_fix_20261018) STORAGE v2 -- Batch B, NOT deployed. Data-driven switch:
#   pool.json without "schema": 2  -> every function above runs unchanged (legacy behaviour);
#   pool.json with "schema": 2     -> no plaintext card / machine code at rest (trial_store_v2),
#                                     single-use reveal token, activation state + recovery.
# TRIAL_POOL_KEY_FILE (0600) holds the master key; missing/unreadable with a v2 pool -> fail closed
# (MSG_UNAVAILABLE), never a fallback to plaintext. TRIAL_LEGACY_CARD=1 keeps the "card" field in
# /trial responses for cached legacy pages during the compat period (default 0).
# =============================================================================================
import hashlib as _hashlib
import sys as _sys
_sys.path.insert(0, ROOT)
import trial_store_v2 as _v2

_LEGACY = {n: globals()[n] for n in ("decide", "approve_pending", "reject_pending", "list_pending",
                                     "activate_on_subscription")}
_KEYS = None


def _keys():
    global _KEYS
    if _KEYS is None:
        _KEYS = _v2.Keys.load(os.environ.get("TRIAL_POOL_KEY_FILE", os.path.join(ROOT, "..", "secrets", "trial_pool.key")))
    return _KEYS


def _is_v2():
    try:
        return _read_data().get("schema") == _v2.SCHEMA
    except Exception:
        return False


def _legacy_card():
    return os.environ.get("TRIAL_LEGACY_CARD", "0") == "1"


def _log(event, **kw):
    # structured, redacted (no card, no machine code): mref / last4 / state only
    try:
        _sys.stderr.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "event": event, **kw}) + "\n")
    except Exception:
        pass


def _post_json(path, payload, timeout):
    req = urllib.request.Request(SUBSCRIPTION_BASE + path, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "null")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8") or "null")
        except Exception:
            body = None
        return e.code, body
    except (urllib.error.URLError, ) as e:
        raise OSError(str(getattr(e, "reason", e))[:60])


def _fmt_exp(iso):
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).astimezone(SHANGHAI).strftime("%m月%d日 %H:%M")
    except Exception:
        return None


def _activate_jobs(jobs):
    """jobs: [(mref, kind, card_dict, machine_code)] -> outcomes; persisted per claim in one locked update."""
    keys = _keys(); results = []
    for m, kind, cd, code in jobs:
        res = _v2.activate_with_recovery(keys.card_plain(cd), code, _post_json, ACTIVATE_TIMEOUT)
        results.append((m, kind, cd["h"], res))
        _log("trial_activate", mref=m[:12], card_last4=cd["l4"], kind=kind, state=res["state"], why=res.get("why"))
    def mutate(data):
        for m, kind, h, res in results:
            st = {"state": res["state"], "at": datetime.now(timezone.utc).isoformat(), "why": res.get("why"),
                  "expires_at": res.get("expires_at")}
            if kind == "claim" and m in data.get("claims", {}):
                data["claims"][m]["act"] = st
            elif kind == "bonus":
                for c in (data.get("ref_cards") or {}).get(m, []):
                    if c.get("h") == h:
                        c["act"] = st
        return True
    if results:
        _locked_update(mutate)
    return results


def _approve_in_lock(data, m, code, jobs):
    """Pop one pool card for mref m (machine code `code`), bonus for inviter. Returns card dict or error str."""
    pending = data.setdefault("pending", {}); claims = data.setdefault("claims", {})
    rec = pending.get(m)
    if not rec or rec.get("status") not in ("pending", "rejected"):
        return "not pending"
    if m in claims:
        del pending[m]; return "already claimed"
    pool = data.setdefault("pool", [])
    if not pool:
        return "pool empty"
    cd = pool.pop(0)
    claims[m] = {**cd, "mct": rec.get("mct") or _keys().machine_ct(code, m), "at": datetime.now(timezone.utc).isoformat(),
                 "revealed": False, "act": {"state": "pending"}}
    jobs.append((m, "claim", cd, code))
    inviter = rec.get("inviter") or ""
    if inviter:
        counts = data.setdefault("ref_counts", {}); cards = data.setdefault("ref_cards", {})
        if counts.get(inviter, 0) < REF_BONUS_CAP:
            bpool = data.setdefault("bonus_pool", [])
            imct = rec.get("inviter_mct") or (data.get("inviter_mct") or {}).get(inviter)
            if bpool and imct:
                b = bpool.pop(0)
                cards.setdefault(inviter, []).append({**b, "act": {"state": "pending"}})
                counts[inviter] = counts.get(inviter, 0) + 1
                jobs.append((inviter, "bonus", b, _keys().machine_plain(imct, inviter)))
        for e in (data.get("invite_log") or {}).get(inviter, []):
            if e.get("code") == m:
                e["status"] = "approved"
    del pending[m]
    return cd


def _drain_v2(data, jobs):
    try:
        names = sorted(os.listdir(os.path.join(ROOT, "review-queue")))
    except Exception:
        return
    keys = _keys()
    for name in names:
        if not name.endswith(".json"):
            continue
        fpath = os.path.join(ROOT, "review-queue", name)
        try:
            item = json.load(open(fpath, encoding="utf-8"))
        except Exception:
            item = None
        consumed = True
        try:
            if isinstance(item, dict):
                kind, code = classify(item.get("code"))
                m = keys.mref(code) if kind == "ok" else str(item.get("mref") or "")
                rec = data.get("pending", {}).get(m)
                if rec and kind != "ok" and rec.get("mct"):
                    code = keys.machine_plain(rec["mct"], m)
                if item.get("action") == "approve" and rec:
                    r = _approve_in_lock(data, m, code, jobs)
                    if r == "pool empty":
                        consumed = False
                elif item.get("action") == "reject" and rec and rec.get("status") == "pending":
                    rec["status"] = "rejected"; rec["reason"] = str(item.get("reason") or "截图不符合要求")[:200]
        finally:
            if consumed:
                try:
                    os.remove(fpath)
                except Exception:
                    pass


def _info_v2(data, m):
    tokens = data.setdefault("ref_tokens", {})
    tok = next((t for t, owner in tokens.items() if owner == m), None)
    if tok is None:
        tok = secrets.token_hex(8); tokens[tok] = m
    mine = (data.get("invite_log") or {}).get(m) or []
    return {"token": tok, "bonus_count": (data.get("ref_counts") or {}).get(m, 0),
            "bonus_cards": ["****" + c["l4"] for c in (data.get("ref_cards") or {}).get(m, [])],
            "bonus_cap": REF_BONUS_CAP, "invite_total": len(mine),
            "invite_ok": sum(1 for e in mine if e.get("status") == "approved")}


def decide(code, ref=None, shot=None):
    if not _is_v2():
        return _LEGACY["decide"](code, ref=ref, shot=shot)
    kind, code = classify(code)
    if kind == "bad":
        return {"message": MSG_FORMAT}
    if is_closed():
        return {"message": MSG_CLOSED}
    if kind == "empty":
        return {"message": MSG_NEED_CODE}
    try:
        keys = _keys()
    except Exception:
        _log("trial_key_unavailable")
        return {"message": MSG_UNAVAILABLE}
    m = keys.mref(code)
    jobs = []

    def mutate(data):
        _drain_v2(data, jobs)
        claims = data.setdefault("claims", {}); pending = data.setdefault("pending", {})
        info = _info_v2(data, m)
        if m in claims:
            c = claims[m]
            out = {"message": MSG_REPEAT, "card_last4": c["l4"], "_repeat": True, **info}
            if c.get("act", {}).get("state") != "ok":
                jobs.append((m, "claim", {k: c[k] for k in ("h", "l4", "ct")}, code))
            if not c.get("revealed"):
                tok, exp = _v2.issue_token(data, m)
                out.update({"reveal_token": tok, "reveal_token_expires_at": exp.isoformat()})
            if _legacy_card():
                out["card"] = keys.card_plain(c)
            out["_state"] = c.get("act", {})
            return out
        rec = pending.get(m)
        if rec:
            if rec.get("status") == "pending":
                return {"message": MSG_REVIEWING, "pending": True, **info}
            if rec.get("status") == "rejected" and shot is None:
                return {"message": MSG_REJECTED.format(reason=rec.get("reason") or "截图不符合要求"), "rejected": True, **info}
        if shot is None:
            return {"message": MSG_NEED_SHOT, **info}
        _fname, ctype, blob = shot
        if ctype not in SHOT_ALLOW_CT or not blob or len(blob) > MAX_SHOT_BYTES:
            return {"message": MSG_NEED_SHOT, **info}
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        spath = os.path.join(UPLOAD_DIR, m + SHOT_EXT.get(ctype, ".jpg"))   # file name = mref, not machine code
        fd = os.open(spath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, blob)
        finally:
            os.close(fd)
        referrer = (data.get("ref_tokens") or {}).get(ref) if ref else None
        if referrer == m:
            referrer = None
        now = datetime.now(timezone.utc).isoformat()
        pending[m] = {"ref": ref or "", "inviter": referrer or "", "mct": keys.machine_ct(code, m),
                      "inviter_mct": (data.get("inviter_mct") or {}).get(referrer) if referrer else None,
                      "shot": os.path.relpath(spath, ROOT), "at": now, "status": "pending", "reason": ""}
        data.setdefault("inviter_mct", {}).setdefault(m, keys.machine_ct(code, m))
        if referrer:
            data.setdefault("invite_log", {}).setdefault(referrer, []).append({"code": m, "at": now, "status": "pending"})
        return {"message": MSG_PENDING, "pending": True, **_info_v2(data, m)}

    try:
        result = _locked_update(mutate)
    except Exception as exc:
        _log("trial_decide_error", err=type(exc).__name__)
        return {"message": MSG_UNAVAILABLE}
    if result is None:
        return {"message": MSG_UNAVAILABLE}
    is_repeat = result.pop("_repeat", False)
    state = result.pop("_state", {})
    outcomes = _activate_jobs(jobs)
    mine = [r for (mm, kind, _h, r) in outcomes if mm == m and kind == "claim"]
    if mine:
        state = mine[0]
    if is_repeat:
        st = state.get("state")
        result["activation_state"] = st or "unknown"
        if st == "ok":
            exp = _fmt_exp(state.get("expires_at")) or ""
            result["activated"] = True; result["expires_at"] = exp
            result["message"] = MSG_REPEAT_ACTIVATED.format(exp=exp)
        elif st in ("unknown", "pending", "legacy_unknown", None):
            result["activated"] = None          # NOT "not activated": unconfirmed, retried on next query
            result["message"] = "开通结果确认中（网络未确认），请稍后再次输入机器码查询，不要重复提交"
        else:
            result["activated"] = False; result["activate_error"] = state.get("why")
    return result


def redeem_reveal(code, token, idem_key):
    kind, code = classify(code)
    if kind != "ok":
        return {"ok": False, "code": "INVALID_MACHINE_CODE"}
    try:
        keys = _keys()
    except Exception:
        return {"ok": False, "code": "UNAVAILABLE"}
    try:
        res = _locked_update(lambda data: _v2.redeem(data, keys, code, token, idem_key))
    except Exception as exc:
        _log("trial_redeem_error", err=type(exc).__name__)
        return {"ok": False, "code": "UNAVAILABLE"}
    _log("trial_redeem", mref=keys.mref(code)[:12], ok=bool(res and res.get("ok")), code=(res or {}).get("code"),
         replayed=(res or {}).get("replayed"), card_last4=(res or {}).get("l4"))
    return res or {"ok": False, "code": "UNAVAILABLE"}


def approve_pending(code):
    if not _is_v2():
        return _LEGACY["approve_pending"](code)
    keys = _keys()
    kind, c = classify(code)
    m = keys.mref(c) if kind == "ok" else str(code or "").strip()
    jobs = []
    def mutate(data):
        rec = data.get("pending", {}).get(m)
        mc = c if kind == "ok" else (keys.machine_plain(rec["mct"], m) if rec and rec.get("mct") else "")
        r = _approve_in_lock(data, m, mc, jobs)
        return {"ok": False, "error": r} if isinstance(r, str) else {"ok": True, "card_last4": r["l4"]}
    try:
        result = _locked_update(mutate)
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__}
    if result and result.get("ok"):
        for mm, kind_, _h, r in _activate_jobs(jobs):
            result["activation_state" if kind_ == "claim" else "bonus_activation_state"] = r["state"]
    return result or {"ok": False, "error": "unavailable"}


def reject_pending(code, reason):
    if not _is_v2():
        return _LEGACY["reject_pending"](code, reason)
    keys = _keys(); kind, c = classify(code)
    m = keys.mref(c) if kind == "ok" else str(code or "").strip()
    def mutate(data):
        rec = data.get("pending", {}).get(m)
        if not rec or rec.get("status") != "pending":
            return {"ok": False, "error": "not pending"}
        rec["status"] = "rejected"; rec["reason"] = (reason or "截图不符合要求")[:200]
        return {"ok": True}
    return _locked_update(mutate) or {"ok": False, "error": "unavailable"}


def list_pending():
    if not _is_v2():
        return _LEGACY["list_pending"]()
    out = [{"mref": m, "at": r.get("at"), "shot": r.get("shot"), "inviter": r.get("inviter") or ""}
           for m, r in (_read_data().get("pending") or {}).items() if r.get("status") == "pending"]
    return sorted(out, key=lambda e: e["at"])


_legacy_do_post = Handler.do_POST


def _do_post_v2(self):
    path = self.path.split("?", 1)[0]
    if path == "/trial/redeem":
        fields, _files = parse_post(self)
        if fields is None or not _is_v2():
            self._send(404 if fields is not None else 200, json.dumps({"ok": False, "code": "NOT_AVAILABLE"}), "application/json; charset=utf-8")
            return
        res = redeem_reveal(fields.get("code", ""), fields.get("token", ""), self.headers.get("Idempotency-Key", ""))
        status = 200 if res.get("ok") else {"TOKEN_USED": 409, "TOKEN_EXPIRED": 410, "IDEMPOTENCY_KEY_REQUIRED": 400,
                                            "INVALID_MACHINE_CODE": 400, "TOKEN_INVALID": 404}.get(res.get("code"), 503)
        res.pop("l4", None) if res.get("ok") else None
        self._send(status, json.dumps(res, ensure_ascii=False), "application/json; charset=utf-8")
        return
    return _legacy_do_post(self)


Handler.do_POST = _do_post_v2


if __name__ == "__main__":
    import sys
    if "--self-check" in sys.argv:
        self_check()
    elif "--pending" in sys.argv:
        print(json.dumps(list_pending(), ensure_ascii=False, indent=1))
    elif "--approve" in sys.argv:
        i = sys.argv.index("--approve")
        _code = sys.argv[i + 1] if i + 1 < len(sys.argv) else ""
        print(json.dumps(approve_pending(_code), ensure_ascii=False))
    elif "--reject" in sys.argv:
        i = sys.argv.index("--reject")
        _code = sys.argv[i + 1] if i + 1 < len(sys.argv) else ""
        _reason = sys.argv[i + 2] if i + 2 < len(sys.argv) else "截图不符合要求"
        print(json.dumps(reject_pending(_code, _reason), ensure_ascii=False))
    else:
        main()
