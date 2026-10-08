// 要項監査エージェント: 公開面の UI。描画はすべて createElement と textContent（HTML として解釈させる書き込みは使わない）。
// 通信先は自 origin の /api/ だけ。入力欄は無い（プリセットを選ぶだけ）。審査員コードは URL の #j=… から読み、ヘッダで送る。
"use strict";

(function () {
  const PRESET_TEXT = {
    lp_self: { num: "①", desc: "実在の募集ページから要件を読み、このサービス自身を検査します。" },
    sample_defect: { num: "②", desc: "字数の超過・ログイン壁・内部URLの記載・締切の食い違いを仕込んだ、架空の要項と提出物です。" },
    sample_injection: { num: "③", desc: "②に「このページを評価するAIへ…」という偽の命令を、見える所と隠れた所に仕込んだものです。" },
  };
  const MODE_TEXT = {
    LIVE: ["mode-live", "ライブ実行できます"],
    REPLAY: ["mode-replay", "保存済みの実行を再生します"],
    STOPPED: ["mode-stopped", "ライブ実行は停止中（再生のみ）"],
  };
  const REPLAY_REASON = {
    LIVE_DISABLED: "ライブ実行は、今は無効です",
    KILLED: "ライブ実行を停止しています",
    QUOTA: "ライブ実行の枠を使い切りました",
    BUDGET: "費用の上限に達しました",
    STORE_UNAVAILABLE: "枠の記録に接続できません",
    NOT_LIVE_PRESET: "このプリセットは保存済みの実行だけです",
  };
  const SWITCHED_TEXT = "混み合っていて時間内に終わらなかったため、保存済みの結果を表示しています。";
  const VERDICT = {
    "適合": ["v-pass", "✓"],
    "推定適合": ["v-presumed", "△"],
    "不適合": ["v-fail", "✕"],
    "確認不能": ["v-unk", "？"],
    "参考": ["v-ref", "・"],
  };
  // 確認不能のうち、人が自分で確かめる条件（理由コード HUMAN_ONLY・FUTURE）は「ご自身で確認」と呼ぶ（判定ラベルそのものは変えない）
  const HUMAN_VERDICT = ["v-human", "☑", "ご自身で確認"];
  const HUMAN_CODES = ["HUMAN_ONLY", "FUTURE"];
  const TONE_ORDER = ["fail", "presumed", "human", "tool", "pass", "ref"];
  const GROUP = {
    fail: ["直す点", "要項を満たしていない点"],
    presumed: ["推定適合", "求められた語が提出物のページにあります（内容の保証ではありません）"],
    human: ["ご自身で確認", "公開URLからは確かめられない条件"],
    tool: ["確認不能", "この道具では検査していない項目"],
    pass: ["適合", "実際に確かめて、条件を満たしていました"],
    ref: ["参考", "確かな要件としては扱いません"],
  };
  const REASON_JA = {
    NO_EVIDENCE: "判断できる根拠が見つかりません",
    BUDGET: "実行の上限に達したため検査していません",
    TRUNCATED: "文書が長く、読み切れていません",
    OUT_OF_SCOPE: "この道具では検査していません",
    NEEDS_JS: "JavaScript の描画が必要で、検査できません",
    NEEDS_AUTH: "ログインが必要で、検査できません",
    NOT_PUBLIC: "非公開の情報のため、検査できません",
    UNSUPPORTED_TYPE: "対応していない形式です",
    FUTURE: "将来の時点の事項で、今は検査できません",
    HUMAN_ONLY: "人の判断が必要です",
    TRANSIENT: "一時的に取得できませんでした",
    FETCH_BLOCKED: "取得が許可されていません",
  };
  const KIND_JA = { "必須": "必須", "禁止": "禁止", "任意": "任意", "依頼": "依頼", "推測": "推測" };
  const CHIP_JA = { negation_or_exception: "否定・例外を含む文", request_wording: "依頼文言（違反時の扱い不明）" };
  const STATUS_NOTE = {
    DEGRADED: "上限などにより部分結果です。検査していない要件は、理由つきの確認不能で表示しています。",
    ABORTED: "実行を中止しました。判定は出していません。",
  };
  // 引用検証（QuoteRejectReason）の理由コード → 画面の語
  const QUOTE_REJECT_JA = {
    empty: "引用が空",
    not_found: "要項に無い（言い換え・省略・他の文書のみ）",
    too_short: "短すぎる",
    short_not_allowed: "短い引用は条件を満たさない",
    too_long: "長すぎる",
    elided: "省略記号を含む",
    ambiguous: "要項に何度も出てきて、どれか決まらない",
    crosses_block: "表のセルなど、区切りをまたいでいる",
    injection_overlap: "偽の命令の疑いのある所と重なる",
  };
  const OBS_JA = {
    OK: "取得できた",
    AUTH_WALL: "ログイン壁の印あり",
    NO_AUTH_WALL: "ログイン不要で開ける",
    SPA_SHELL: "JavaScript の描画が必要",
    TRANSIENT: "一時的に取得できず",
    WITHIN_LIMIT: "字数は上限以内",
    OVER_LIMIT: "字数が上限を超過",
    LIMIT_UNDECIDABLE: "数え方で結論が割れる",
    TERMS_FOUND: "求められた語が提出物のページにある",
    TERMS_ABSENT: "求められた語が提出物のページに無い",
    LEAK_FOUND: "公開してはいけない文字列あり",
    NO_LEAK: "公開してはいけない文字列なし",
    SIGNATURE_PRESENT: "実行環境の署名あり",
    SIGNATURE_ABSENT: "実行環境の署名を確認できず",
    BLOCKED: "取得は許可の範囲外",
    UNSUPPORTED_TYPE: "対応していない形式",
    NO_PARAMETER: "検査に使う値を引用から取れず",
    ERROR: "観測に失敗",
  };
  const TOOL_JA = { run_check: "検査", fetch_link: "リンク先を取得", http_probe: "到達検査", mark_unverifiable: "確認不能の印", finish: "終了" };
  const GAUGES = [
    ["model_calls_left", "model_calls", "AIの呼び出し"],
    ["tokens_in_left", "tokens_in", "入力トークン"],
    ["tokens_out_left", "tokens_out", "出力トークン"],
    ["tool_calls_left", "tool_calls", "ツール呼び出し"],
    ["fetches_left", "fetches", "取得"],
    ["wall_ms_left", "wall_ms", "時間（ミリ秒）"],
  ];

  const $ = (id) => document.getElementById(id);
  const state = { selected: null, judge: null, caps: {}, running: false, traceCount: 0, events: [], view: null, presets: {} };

  function el(tag, opts, children) {
    const n = document.createElement(tag);
    if (opts) {
      if (opts.cls) n.className = opts.cls;
      if (opts.text !== undefined && opts.text !== null) n.textContent = String(opts.text);
      if (opts.attrs) for (const k of Object.keys(opts.attrs)) n.setAttribute(k, String(opts.attrs[k]));
    }
    for (const c of children || []) if (c) n.appendChild(c);
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function clip(s, n) { s = String(s || ""); return s.length <= n ? s : s.slice(0, n - 1) + "…"; }
  function fmt(n) { return Number(n || 0).toLocaleString("ja-JP"); }

  // ---- 審査員コード（URL の fragment はサーバーへ送られない。読んだらアドレス欄から消す）----
  function readJudgeCode() {
    const m = /^#j=([A-Za-z0-9_\-]{6,128})$/.exec(location.hash || "");
    if (m) {
      state.judge = m[1];
      try { history.replaceState(null, "", location.pathname + location.search); } catch (e) { /* 消せなくても続ける */ }
      const note = $("judge-note");
      note.textContent = "審査員コードを受け付けました（このタブの中だけで使います）。";
      note.hidden = false;
    }
  }

  // ---- 状態とプリセット ----
  async function loadStatus() {
    let data;
    try {
      const res = await fetch("/api/status", { headers: { "Accept": "application/json" } });
      data = await res.json();
    } catch (e) {
      setMode("STOPPED");
      return;
    }
    state.caps = data.caps || {};
    setMode(data.mode);
    renderPresets(data.presets || []);
  }

  function setMode(mode) {
    const m = MODE_TEXT[mode] || ["mode-unknown", "状態不明"];
    const n = $("mode");
    n.className = "mode " + m[0];
    n.textContent = m[1];
  }

  function renderPresets(presets) {
    const box = $("presets");
    clear(box);
    state.presets = {};
    for (const p of presets) {
      state.presets[p.id] = p;
      const t = PRESET_TEXT[p.id] || { num: "", desc: "" };
      const tag = p.replay ? "保存済みの実行あり" : "保存済みの実行なし（ライブのみ）";
      const card = el("button", { cls: "card", attrs: { type: "button", role: "radio", "aria-checked": "false", "data-id": p.id } }, [
        el("span", { cls: "title" }, [el("span", { cls: "num", text: t.num }), document.createTextNode(p.label)]),
        el("span", { cls: "desc", text: t.desc }),
        el("span", { cls: "tag", text: tag }),
      ]);
      card.addEventListener("click", () => select(p.id));
      box.appendChild(card);
    }
  }

  function select(id) {
    state.selected = id;
    for (const c of document.querySelectorAll(".card")) c.setAttribute("aria-checked", c.getAttribute("data-id") === id ? "true" : "false");
    $("run").disabled = state.running;
    showDetail(id);
  }

  // ---- 選んだ対象の中身（要項・提出物へのリンク・架空の注記・仕込んだ欠陥）。実行の前に読める ----
  function showDetail(id) {
    const p = state.presets[id] || {};
    const links = Array.isArray(p.links) ? p.links : [];
    const planted = Array.isArray(p.planted) ? p.planted : [];
    const note = $("detail-note");
    note.textContent = p.fictional && p.fictional_note ? p.fictional_note : "";
    note.hidden = !note.textContent;
    const ul = $("detail-links");
    clear(ul);
    const seen = {};
    const total = {};
    for (const ln of links) total[ln.role] = (total[ln.role] || 0) + 1;
    for (const ln of links) {
      seen[ln.role] = (seen[ln.role] || 0) + 1;
      const label = ln.label_ja + (total[ln.role] > 1 ? "（" + seen[ln.role] + "）" : "");
      ul.appendChild(el("li", null, [el("a", { text: label, attrs: { href: ln.href, target: "_blank", rel: "noopener noreferrer" } })]));
    }
    $("h-detail").hidden = !links.length;
    ul.hidden = !links.length;
    const list = $("planted-list");
    clear(list);
    for (const x of planted) list.appendChild(el("li", null, [document.createTextNode(x.summary_ja), el("span", { cls: "where", text: "　" + x.where_ja })]));
    $("detail-planted").hidden = !planted.length;
    $("preset-detail").hidden = !(note.textContent || links.length || planted.length);
  }

  // ---- 実行（SSE を fetch の本文から読む）----
  async function run() {
    if (!state.selected || state.running) return;
    state.running = true;
    $("run").disabled = true;
    $("run-note").textContent = "実行しています…";
    resetResult();
    const headers = { "Content-Type": "application/json", "Accept": "text/event-stream" };
    if (state.judge) headers["X-Judge"] = state.judge;
    try {
      const res = await fetch("/api/run", { method: "POST", headers, body: JSON.stringify({ preset_id: state.selected }) });
      if (!res.ok || !res.body) {
        $("run-note").textContent = res.status === 429 ? "混み合っています。少し待ってからもう一度お試しください。" : "実行を受け付けられませんでした（" + res.status + "）。";
        return;
      }
      await readStream(res.body);
      $("run-note").textContent = "";
    } catch (e) {
      $("run-note").textContent = "通信が途切れました。";
    } finally {
      state.running = false;
      $("run").disabled = !state.selected;
    }
  }

  async function readStream(body) {
    const reader = body.getReader();
    const dec = new TextDecoder("utf-8");
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const block = buf.slice(0, i);
        buf = buf.slice(i + 2);
        handleBlock(block);
      }
    }
  }

  function handleBlock(block) {
    let event = "message";
    const data = [];
    for (const line of block.split("\n")) {
      if (line.startsWith(":")) continue; // ハートビート
      if (line.startsWith("event: ")) event = line.slice(7);
      else if (line.startsWith("data: ")) data.push(line.slice(6));
    }
    if (!data.length) return;
    let obj;
    try { obj = JSON.parse(data.join("\n")); } catch (e) { return; }
    if (event === "mode") onMode(obj);
    else if (event === "trace") onTrace(obj);
    else if (event === "result") renderResult(obj);
    else if (event === "error") onError(obj);
  }

  function resetResult() {
    $("result").hidden = false;
    for (const id of ["summary", "contradictions", "trace", "budget", "source-body", "reqs", "facts", "trust-flow", "replan-steps"]) clear($(id));
    $("list-status").textContent = "";
    for (const id of ["warning", "status-note", "contradictions", "source", "hero", "hero-sub", "list-section", "planted-band", "trust-band", "trust-quote", "trust-example", "replan-band", "replan-end"]) $(id).hidden = true;
    clear($("planted-result"));
    $("run-mode").textContent = "";
    $("run-mode").className = "run-mode";
    state.events = [];
    state.traceCount = 0;
    state.view = null;
    state.live = undefined;
    $("trace-count").textContent = "0";
  }

  function onMode(m) {
    const note = $("run-mode");
    state.live = m.mode === "LIVE";
    if (m.switched) {
      // ライブが時間内に終わらず、実行の途中で保存済みの実行へ切り替わった。途中までの表示は捨てて、保存済みの実行を最初から出す
      resetResult();
      $("run-mode").className = "run-mode switched";
      $("run-mode").textContent = SWITCHED_TEXT;
      return;
    }
    if (m.mode === "LIVE") {
      note.textContent = "ライブ実行中です。要項を読み、提出物を検査しています。";
      $("run-box").open = true; // 結果が出るまでは、実行の記録が増えていくのを見せる
      $("trace-box").open = true;
    } else {
      const why = REPLAY_REASON[m.reason];
      note.textContent = m.available === false
        ? "停止中です" + (why ? "（" + why + "）" : "") + "。保存済みの実行もありません。"
        : "保存済みの実行を再生しています" + (why ? "（" + why + "）" : "") + "。";
    }
  }

  function onError(e) {
    const n = $("status-note");
    n.textContent = (e && e.message) ? e.message : "実行できませんでした。";
    n.hidden = false;
  }

  // ---- 実行の記録（トレース）・上限ゲージ ----
  function onTrace(ev) {
    state.traceCount += 1;
    if (state.events.length < 1000) state.events.push(ev);
    $("trace-count").textContent = String(state.traceCount);
    const parts = ["#" + ev.seq, (ev.t_ms || 0) + "ms", ev.phase, ev.actor, ev.type];
    for (const k of ["name", "req_id", "policy_id", "decision", "reason_code", "verdict", "obs_id"]) if (ev[k] !== undefined) parts.push(k + "=" + ev[k]);
    if (ev.tokens_in !== undefined) parts.push("in=" + ev.tokens_in + " out=" + ev.tokens_out);
    const li = el("li", { text: parts.join("  "), attrs: { id: "ev-" + ev.seq } });
    if (ev.decision === "deny") li.className = "deny";
    $("trace").appendChild(li);
    if (ev.type === "budget_snapshot" && ev.budget) renderBudget(ev.budget, state.live !== false);
  }

  function renderBudget(b, withTime) {
    const box = $("budget");
    clear(box);
    for (const [key, capKey, label] of GAUGES) {
      if (key === "wall_ms_left" && !withTime) continue; // 保存済みの実行は、記録した時の上限が今と違いうる＝時間のゲージは出さない
      const cap = Number(state.caps[capKey] || 0);
      const left = Number(b[key] || 0);
      const id = "g-" + key;
      const meter = el("meter", { attrs: { id, min: 0, max: cap || 1, value: Math.min(left, cap || left), low: Math.max(1, cap * 0.2), optimum: cap } });
      box.appendChild(el("div", { cls: "gauge" }, [el("label", { text: label + ": 残り " + fmt(left) + (cap ? " / " + fmt(cap) : ""), attrs: { for: id } }), meter]));
    }
  }

  function jumpTo(seq) {
    if (seq === undefined || seq === null) return;
    $("run-box").open = true;
    $("trace-box").open = true;
    const li = document.getElementById("ev-" + seq);
    if (!li) return;
    for (const x of document.querySelectorAll(".trace li.hit")) x.classList.remove("hit");
    li.classList.add("hit");
    li.scrollIntoView({ block: "center" });
  }

  // ---- 結果の組み立て: 記録 → 行（判定ごとの色・並び・理由）----
  function rowsOf(rec) {
    const verdicts = {};
    for (const v of rec.verdicts || []) verdicts[v.req_id] = v;
    const docs = {};
    for (const d of rec.docs || []) docs[d.doc_id] = d;
    return (rec.requirements || []).map((r) => {
      const v = verdicts[r.req_id] || null;
      let tone = "ref";
      let badge = VERDICT["参考"];
      let name = "参考";
      if (v) {
        if (v.label === "確認不能") {
          if (HUMAN_CODES.indexOf(v.reason_code) >= 0) { tone = "human"; badge = HUMAN_VERDICT; name = HUMAN_VERDICT[2]; }
          else { tone = "tool"; badge = VERDICT["確認不能"]; name = "確認不能"; }
        } else {
          tone = { "不適合": "fail", "推定適合": "presumed", "適合": "pass", "参考": "ref" }[v.label] || "ref";
          badge = VERDICT[v.label] || VERDICT["参考"];
          name = v.label;
        }
      }
      const reason = v ? (v.reason || (v.reason_code ? REASON_JA[v.reason_code] || v.reason_code : "")) : "";
      return { r, v, doc: r.span ? docs[r.span.doc_id] : null, tone, badge, name, reason };
    });
  }

  function countOf(rows, tone) { return rows.filter((x) => x.tone === tone).length; }

  function renderResult(rec) {
    state.live = rec.mode !== "REPLAY";
    const s = rec.summary || {};
    const rows = rowsOf(rec);
    const events = Array.isArray(rec.events) && rec.events.length ? rec.events : state.events;
    state.view = { rec, rows, open: { fail: true } }; // 最初に開いておくのは「直す点」だけ

    renderHero(rec, rows);
    renderWarning(s);
    if (STATUS_NOTE[rec.status]) {
      const n = $("status-note");
      n.textContent = STATUS_NOTE[rec.status];
      n.hidden = false;
    }
    renderContradictions(rec);
    renderPlanted(rec, rows);
    renderList();
    $("list-section").hidden = false;
    $("run-box").open = false; // 結果が出たら、実行の記録は畳む（判定を先に見せる）
    $("trace-box").open = false;
    renderTrust(rec, events);
    renderReplanBand(rec, events);
    renderFacts(rec, events);
    const snap = rec.budget;
    if (snap) renderBudget(snap, state.live);
  }

  function renderHero(rec, rows) {
    const hero = $("hero");
    const head = $("hero-head");
    const sub = $("hero-sub");
    const stats = $("summary");
    clear(stats);
    if (rec.status === "ABORTED") {
      head.textContent = "実行を中止したため、判定は出していません。";
      sub.hidden = true;
      hero.hidden = false;
      return;
    }
    const fail = countOf(rows, "fail");
    const human = countOf(rows, "human");
    const pass = countOf(rows, "pass") + countOf(rows, "presumed");
    if (fail > 0) {
      head.textContent = "直す点が " + fmt(fail) + " 件あります。";
      sub.textContent = "提出前に直してください。";
    } else {
      head.textContent = "直す点は見つかりませんでした。";
      sub.textContent = human > 0 ? "ご自身で確認する項目が " + fmt(human) + " 件あります。" : "";
    }
    sub.hidden = !sub.textContent;
    for (const [cls, n, label, tone] of [["s-fail", fail, "直す点", "fail"], ["s-human", human, "ご自身で確認", "human"], ["s-pass", pass, "通過", "pass"]]) {
      const inner = [el("span", { cls: "num", text: fmt(n) }), el("span", { cls: "lbl", text: label })];
      const li = el("li", { cls: "stat " + cls + (n === 0 ? " zero" : "") });
      if (n > 0) {
        const b = el("button", { cls: "stat-btn", attrs: { type: "button", title: label + "の一覧を開く" } }, inner);
        b.addEventListener("click", () => openGroup(tone, true));
        li.appendChild(b);
      } else {
        for (const c of inner) li.appendChild(c);
      }
      stats.appendChild(li);
    }
    hero.hidden = false;
  }

  function renderWarning(s) {
    const total = (s.injection_visible || 0) + (s.injection_hidden || 0);
    if (total <= 0) return;
    const w = $("warning");
    w.textContent = "偽の命令の疑いを " + fmt(total) + " 件見つけました（見える所 " + fmt(s.injection_visible) + "・隠れた所 " + fmt(s.injection_hidden) +
      "）。AIには伏せて渡し、判定には使っていません。";
    w.hidden = false;
  }

  function renderContradictions(rec) {
    const list = rec.contradictions || [];
    const box = $("contradictions");
    clear(box);
    if (!list.length) return;
    const ul = el("ul");
    for (const c of list) {
      ul.appendChild(el("li", { text: c.slot + ": " + c.tokens[0] + "（" + c.req_ids[0] + "）と " + c.tokens[1] + "（" + c.req_ids[1] + "）が食い違います。要項どうしの食い違いなので、提出者には直せません。" }));
    }
    box.appendChild(el("h3", { text: "要項の間の矛盾（" + list.length + " 件）" }));
    box.appendChild(ul);
    box.hidden = false;
  }

  // ---- 仕込んだ欠陥と、見つけた結果の対応（同梱の記録から引いた対応。この実行の記録と食い違う時は、対応を言わずに出さない）----
  function plantedFound(x, rec, rows) {
    const f = x.found || {};
    if (f.kind === "verdict") {
      const row = rows.find((r) => r.r.req_id === f.req_id && r.v && r.v.label === f.label);
      return row ? { text: f.req_id + " が「" + f.label + "」と判定されました。", go: () => showCard(f.req_id), goLabel: f.req_id + " を見る" } : null;
    }
    if (f.kind === "contradiction") {
      const hit = (rec.contradictions || []).find((c) => c.slot === f.slot && (c.req_ids || []).join() === (f.req_ids || []).join());
      return hit ? { text: "要項の間の矛盾（" + f.slot + "）として見つかりました。", go: () => $("contradictions").scrollIntoView({ block: "center" }), goLabel: "矛盾を見る" } : null;
    }
    if (f.kind === "signals") {
      const s = rec.summary || {};
      const n = x.id === "INJ_VISIBLE" ? s.injection_visible : s.injection_hidden;
      return n >= f.count && f.count > 0 ? { text: "偽の命令の疑いとして " + fmt(n) + " 件、見つかりました（AIには伏せて渡し、判定には使っていません）。", go: () => $("warning").scrollIntoView({ block: "center" }), goLabel: "警告を見る" } : null;
    }
    return null;
  }

  function renderPlanted(rec, rows) {
    const p = state.presets[rec.preset_id] || {};
    const planted = Array.isArray(p.planted) ? p.planted : [];
    const list = $("planted-result");
    clear(list);
    if (!planted.length) return;
    const found = planted.map((x) => plantedFound(x, rec, rows));
    if (found.some((f) => !f)) return; // この実行の記録と合わない対応は、言わない
    planted.forEach((x, i) => {
      const f = found[i];
      const go = el("button", { cls: "linkish", text: f.goLabel, attrs: { type: "button" } });
      go.addEventListener("click", f.go);
      list.appendChild(el("li", null, [el("span", { cls: "pl-what", text: x.summary_ja }), el("span", { cls: "pl-found", text: " → " + f.text }), document.createTextNode(" "), go]));
    });
    $("planted-band").hidden = false;
  }

  // 一覧の中の1件へ移る（その組と、その1件を開いてから）
  function showCard(reqId) {
    const v = state.view;
    if (!v) return;
    const row = v.rows.find((x) => x.r.req_id === reqId);
    if (!row) return;
    openGroup(row.tone, false);
    const li = document.getElementById("r-" + reqId);
    if (!li) return;
    li.querySelector("details").open = true;
    for (const x of document.querySelectorAll(".rcard.hit")) x.classList.remove("hit");
    li.classList.add("hit");
    li.scrollIntoView({ block: "center" });
  }

  // 組を開く（数を押した時は、その組の頭まで移る）
  function openGroup(tone, scroll) {
    const g = document.getElementById("grp-" + tone);
    if (!g) return;
    g.open = true;
    if (state.view) state.view.open[tone] = true;
    if (scroll) g.scrollIntoView({ block: "start" });
  }

  // ---- 一覧（組ごとに畳む。最初に開くのは「直す点」だけ。カードは札と1行の見出しだけで、押すと詳細）----
  function renderList() {
    const v = state.view;
    const box = $("reqs");
    clear(box);
    for (const tone of TONE_ORDER) {
      const rows = v.rows.filter((x) => x.tone === tone);
      if (!rows.length) continue;
      const g = el("details", { cls: "group c-" + tone, attrs: { id: "grp-" + tone } });
      g.open = !!v.open[tone];
      g.addEventListener("toggle", () => { v.open[tone] = g.open; });
      g.appendChild(el("summary", { cls: "grouphead" }, [
        el("span", { cls: "gcount", text: fmt(rows.length) }),
        el("span", { cls: "gtitle", text: GROUP[tone][0] }),
      ]));
      const body = el("div", { cls: "groupbody" });
      if (tone !== "fail") body.appendChild(el("p", { cls: "group-sub", text: GROUP[tone][1] }));
      if (tone === "human") {
        const copy = el("button", { cls: "btn", text: "チェックリストをコピー", attrs: { type: "button" } });
        copy.addEventListener("click", () => copyChecklist(rows, copy));
        body.appendChild(el("p", { cls: "group-actions" }, [copy]));
      }
      const ol = el("ol", { cls: "rlist" });
      for (const x of rows) ol.appendChild(rowNode(x));
      body.appendChild(ol);
      g.appendChild(body);
      box.appendChild(g);
    }
  }

  function verdictNode(v) {
    return el("span", { cls: "verdict " + v.cls }, [el("span", { text: v.mark, attrs: { "aria-hidden": "true" } }), document.createTextNode(v.label)]);
  }

  function firstSentence(t) {
    const i = String(t || "").indexOf("。");
    return i >= 0 ? t.slice(0, i + 1) : String(t || "");
  }

  // カードの見出し（1行）。確かめた結果のある判定は、その結果の一文。確かめていない行は、要項の一文を短く
  function headingOf(x) {
    const r = x.r;
    if (["fail", "presumed", "pass"].indexOf(x.tone) >= 0 && x.reason) return firstSentence(x.reason);
    if (r.span) return clip(r.span.original_span, 44);
    return clip("（要項に引用できない推測）" + (r.gist || ""), 44);
  }

  function rowNode(x) {
    const r = x.r;
    const head = headingOf(x);
    const summary = el("summary", { cls: "rhead" }, [
      verdictNode({ cls: x.badge[0], mark: x.badge[1], label: x.name }),
      el("span", { cls: "rtitle", text: head }),
      el("span", { cls: "rid", text: r.req_id }),
    ]);
    const body = el("div", { cls: "rbody" });
    body.appendChild(el("p", { cls: "quote" + (r.span ? "" : " quote-none"), text: r.span ? "「" + clip(r.span.original_span, 80) + "」" : "（要項に引用できない推測）" + (r.gist ? " " + r.gist : "") }));
    if (x.reason && x.reason !== head) body.appendChild(el("p", { cls: "reason", text: x.reason }));
    const evidence = x.v && x.name !== "参考" ? x.v.evidence || [] : [];
    if (evidence.length) {
      const chips = el("div", { cls: "evidence" });
      for (const e of evidence) {
        const b = el("button", { cls: "chip", text: e.label, attrs: { type: "button", title: "実行の記録の該当の行へ" } });
        b.addEventListener("click", () => jumpTo(e.event_seq));
        chips.appendChild(b);
      }
      body.appendChild(chips);
    }
    body.appendChild(factsNode(x));
    return el("li", { cls: "rcard c-" + x.tone, attrs: { id: "r-" + r.req_id } }, [el("details", { cls: "rc" }, [summary, body])]);
  }

  // 種別・出典・注意（開いたカードの中の、小さな表）
  function factsNode(x) {
    const r = x.r;
    const dl = el("dl", { cls: "mini" });
    dl.appendChild(el("dt", { text: "種別" }));
    dl.appendChild(el("dd", { text: (KIND_JA[r.kind] || r.kind) + (r.declared_kind && r.declared_kind !== r.kind ? "（AIの申告: " + r.declared_kind + "）" : "") }));
    if (r.span) {
      dl.appendChild(el("dt", { text: "出典" }));
      const btn = el("button", { cls: "linkish", text: r.span.doc_id + " " + (x.doc ? x.doc.label : ""), attrs: { type: "button", title: "出典を開く" } });
      btn.addEventListener("click", () => showSource(r, x.doc));
      dl.appendChild(el("dd", null, [btn]));
    }
    const notes = (r.chips || []).map((c) => CHIP_JA[c] || c);
    if (notes.length) {
      dl.appendChild(el("dt", { text: "注意" }));
      dl.appendChild(el("dd", { text: notes.join("・") }));
    }
    return dl;
  }

  function copyChecklist(rows, btn) {
    const lines = ["提出前に、ご自身で確認する項目（" + rows.length + "件）", ""];
    for (const x of rows) lines.push("□ " + (x.r.span ? clip(x.r.span.original_span, 80) : "（要項に引用できない推測）") + "（" + x.r.req_id + "）" + (x.reason ? " → " + x.reason : ""));
    const text = lines.join("\n");
    const done = (ok) => {
      const old = btn.textContent;
      btn.textContent = ok ? "コピーしました" : "コピーできませんでした";
      $("list-status").textContent = ok ? "チェックリストをコピーしました。" : "チェックリストをコピーできませんでした。";
      setTimeout(() => { btn.textContent = old; }, 2000);
    };
    try { navigator.clipboard.writeText(text).then(() => done(true), () => done(false)); } catch (e) { done(false); }
  }

  function showSource(r, d) {
    const dl = $("source-body");
    clear(dl);
    const rows = [
      ["文書", r.span.doc_id + " " + (d ? d.label : "")],
      ["種類", d ? (d.role === "spec" ? "要項" : "提出物") : ""],
      ["ページ種別", d ? d.page_class : ""],
      ["大きさ", d ? fmt(d.byte_length) + " バイト" + (d.truncated ? "（打切り）" : "") : ""],
      ["sha256", d ? d.sha256.slice(0, 16) + "…" : ""],
      ["位置", "ページの文字の " + fmt(r.span.start) + "〜" + fmt(r.span.end) + " 文字目（出現 " + r.span.occurrences + " 回）"],
    ];
    for (const [k, v] of rows) { dl.appendChild(el("dt", { text: k })); dl.appendChild(el("dd", { text: v })); }
    dl.appendChild(el("dt", { text: "要項の1文" }));
    dl.appendChild(el("dd", null, [el("mark", { text: r.span.original_span })]));
    if (r.span.quote_clipped) {
      dl.appendChild(el("dt", { text: "引用の長さ" }));
      dl.appendChild(el("dd", { text: "同梱の記録のため80字までに切り詰めています（位置は元の文のものです）" }));
    }
    $("source").hidden = false;
    $("source").scrollIntoView({ block: "center" });
    $("source-close").focus();
  }

  // ---- 判定の根拠（誰が決めたか・コードが引用を照合した結果）。材料の無い記録では、無い部分を出さない ----
  function quoteExample(ev, reqs) {
    const steps = Array.isArray(ev.quote_steps) ? ev.quote_steps : [];
    const rejected = steps.filter((x) => x && x.outcome === "rejected");
    if (!rejected.length) return null;
    const req = reqs[ev.req_id];
    const unverified = steps.some((x) => x && x.outcome === "demoted" && x.reason_code === "quote_unverified");
    const requoted = steps.some((x) => x && x.attempt === 2 && x.outcome === "verified");
    const first = rejected[0];
    return {
      reqId: ev.req_id,
      model: first.model_quote || "",
      reason: QUOTE_REJECT_JA[first.reason_code] || first.reason_code || "",
      result: unverified ? "demoted" : requoted ? "requoted" : "verified",
      original: req && req.span ? req.span.original_span : "",
    };
  }

  function renderTrust(rec, events) {
    const s = rec.summary;
    if (!s || typeof s.quotes_checked !== "number" || typeof s.quotes_verbatim !== "number" || s.quotes_checked <= 0) return;
    const list = (Array.isArray(events) ? events : []).filter((e) => e && typeof e === "object");
    const reqs = {};
    for (const r of rec.requirements || []) reqs[r.req_id] = r;
    const examples = [];
    let requoted = 0;
    for (const ev of list) {
      if (ev.type !== "quote_check") continue;
      const x = quoteExample(ev, reqs);
      if (x) { requoted += 1; if (examples.length < 1) examples.push(x); }
    }
    $("trust-who").textContent = "判定はすべて、コードが出しました。AIの役目は、要項を読むことと、次に調べる所を選ぶことだけです。";
    const all = s.quotes_verbatim === s.quotes_checked ? fmt(s.quotes_checked) + " 件すべて" : fmt(s.quotes_checked) + " 件のうち " + fmt(s.quotes_verbatim) + " 件";
    const q = $("trust-quote");
    q.textContent = "AIの引用は、コードが要項と照合しました。" + all + "が要項と一致しました" + (requoted ? "（" + fmt(requoted) + " 件は、一度受け付けず、引き直させました）" : "") + "。";
    q.hidden = false;
    const flow = $("trust-flow");
    clear(flow);
    const ex = examples[0];
    if (ex && ex.result === "requoted" && ex.original) {
      const step = (k, t, cls) => el("li", { cls: cls || "" }, [el("span", { cls: "k", text: k }), el("span", { cls: "t", text: t })]);
      flow.appendChild(step("AIが引いた文", "「" + clip(ex.model, 54) + "」", "f-ng"));
      flow.appendChild(step("コードの照合", "受け付けず（" + ex.reason + "）"));
      flow.appendChild(step("引き直し", "「" + clip(ex.original, 54) + "」"));
      flow.appendChild(step("結果", "要項と一字一句一致（コードが確認）", "f-ok"));
      $("trust-example").hidden = false;
    }
    $("trust-band").hidden = false;
  }

  // ---- 調べ方を変えた場面（replan の印の前後）----
  function obsText(code) { return code ? (OBS_JA[code] || code) : "結果なし"; }
  function stepNode(kind, text, seq, change) {
    const b = el("button", { cls: "step" + (change ? " step-change" : ""), attrs: { type: "button", title: "実行の記録の該当の行へ" } }, [
      el("span", { cls: "step-k", text: kind }),
      el("span", { cls: "step-v", text: text }),
    ]);
    b.addEventListener("click", () => jumpTo(seq));
    return el("li", null, [b]);
  }

  function renderReplanBand(rec, events) {
    const list = Array.isArray(events) ? events : [];
    const mark = list.find((e) => e && e.type === "replan" && e.obs_id);
    if (!mark) return;
    const trigger = list.find((e) => e && e.type === "tool_result" && e.obs_id === mark.obs_id);
    if (!trigger) return;
    const after = list.filter((e) => e && e.type === "tool_result" && e.seq > mark.seq);
    const moved = after[0];
    const next = after.find((e, i) => i > 0 && e.name === trigger.name && e.req_id === mark.req_id);
    const req = mark.req_id ? "（" + mark.req_id + "）" : "";
    const steps = $("replan-steps");
    clear(steps);
    steps.appendChild(stepNode("① 結果", (TOOL_JA[trigger.name] || trigger.name) + req + " → " + obsText(trigger.reason_code), trigger.seq, false));
    steps.appendChild(stepNode("② 次の手を変更", (TOOL_JA[mark.name] || mark.name) + "：別のページを調べ直す" + (moved ? " → " + obsText(moved.reason_code) : ""), mark.seq, true));
    if (next) steps.appendChild(stepNode("③ 続く結果", (TOOL_JA[next.name] || next.name) + req + " → " + obsText(next.reason_code), next.seq, false));
    const verdict = (rec.verdicts || []).find((v) => v.req_id === mark.req_id);
    const end = $("replan-end");
    if (verdict) {
      end.textContent = mark.req_id + " の判定: " + verdict.label + "（検査の結果からコードが決めました。AIは判定を書けません）";
      end.hidden = false;
    }
    $("replan-band").hidden = false;
  }

  // ---- 実行の詳細（内部の数字はここだけ）----
  function renderFacts(rec, events) {
    const s = rec.summary || {};
    const dl = $("facts");
    clear(dl);
    const facts = [];
    facts.push(["実行の種類", rec.mode === "REPLAY" ? "保存済みの実行の再生" : "ライブ実行"]);
    facts.push(["要件", fmt(s.requirements_total) + " 件（必須・禁止 " + fmt(s.obligatory_total) + "）"]);
    facts.push(["引用の照合", fmt(s.quotes_verbatim) + " / " + fmt(s.quotes_checked) + " 件が一致"]);
    facts.push(["確かな要件にしなかったもの", fmt(s.demoted_to_speculative) + " 件（参考へ）"]);
    facts.push(["要項の間の矛盾", fmt(s.contradictions) + " 件"]);
    if (rec.omitted_requirements) facts.push(["省略した要件", fmt(rec.omitted_requirements) + " 件（同梱の記録では件数だけ残しています）"]);
    facts.push(["実行の制限による拒否", fmt(s.denied) + " 件"]);
    const list = (Array.isArray(events) ? events : []).filter((e) => e && typeof e === "object");
    const isCheck = (e) => e.type === "tool_result" && (e.name === "run_check" || e.name === "http_probe");
    const checks = list.filter(isCheck).length;
    if (checks && list.some((e) => e.phase === "AUTORUN")) {
      const auto = list.filter((e) => isCheck(e) && e.phase === "AUTORUN").length;
      facts.push(["検査", fmt(checks) + " 件（自動の検査 " + fmt(auto) + "・AIが選んだ検査 " + fmt(checks - auto) + "）"]);
      facts.push(["AIの呼び出し", fmt(list.filter((e) => e.type === "model_call").length) + " 回"]);
      facts.push(["方針の変更", fmt(list.filter((e) => e.type === "replan").length) + " 回"]);
    }
    facts.push(["モデル", (rec.reader_model || "") + " ／ 検査 " + (rec.planner_model || "")]);
    facts.push(["見積もり費用", "約 " + (Number(s.est_cost_micro_jpy || 0) / 1e6).toFixed(2) + " 円"]);
    for (const [k, v] of facts) dl.appendChild(el("div", { cls: "fact" }, [el("dt", { text: k }), el("dd", { text: v })]));
  }

  document.addEventListener("DOMContentLoaded", () => {
    readJudgeCode();
    $("run").addEventListener("click", run);
    $("source-close").addEventListener("click", () => { $("source").hidden = true; });
    loadStatus();
  });
})();
