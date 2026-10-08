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
    LIVE_DISABLED: "ライブ実行は無効にしてあります",
    KILLED: "ライブ実行を停止しています",
    QUOTA: "ライブ実行の枠を使い切りました",
    BUDGET: "費用の上限に達しました",
    STORE_UNAVAILABLE: "枠の記録に接続できません",
    NOT_LIVE_PRESET: "このプリセットは保存済みの実行だけです",
    LIVE_TIMEOUT: "ライブ実行が時間内に終わりませんでした",
  };
  const VERDICT = {
    "適合": ["v-pass", "✓"],
    "推定適合": ["v-presumed", "△"],
    "不適合": ["v-fail", "✕"],
    "確認不能": ["v-unk", "？"],
    "参考": ["v-ref", "・"],
  };
  const KIND_CLASS = { "必須": "k-required", "禁止": "k-prohibited", "任意": "k-optional", "依頼": "k-request", "推測": "k-speculative" };
  const REASON_JA = {
    NO_EVIDENCE: "判断できる根拠が見つかりません",
    BUDGET: "実行の上限に達したため検査していません",
    TRUNCATED: "文書が長く、読み切れていません",
    OUT_OF_SCOPE: "検査できる範囲の外です",
    NEEDS_JS: "JavaScript の描画が必要で、検査できません",
    NEEDS_AUTH: "ログインが必要で、検査できません",
    NOT_PUBLIC: "非公開の情報のため、検査できません",
    UNSUPPORTED_TYPE: "対応していない形式です",
    FUTURE: "将来の時点の事項で、今は検査できません",
    HUMAN_ONLY: "人の判断が必要です",
    TRANSIENT: "一時的に取得できませんでした",
    FETCH_BLOCKED: "取得が許可されていません",
  };
  const CHIP_JA = { negation_or_exception: "否定・例外を含む文", request_wording: "依頼文言（違反時の扱い不明）" };
  const STATUS_NOTE = {
    DEGRADED: "上限などにより部分結果です。未検査の要件は理由つきの確認不能で表示しています。",
    ABORTED: "実行を中止しました。判定は出していません。",
  };
  // 引用検証（QuoteRejectReason）の理由コード → 画面の語
  const QUOTE_REJECT_JA = {
    empty: "引用が空",
    not_found: "原文に無い（言い換え・省略・他の文書のみ）",
    too_short: "短すぎる",
    short_not_allowed: "短い引用は条件を満たさない",
    too_long: "長すぎる",
    elided: "省略記号を含む",
    ambiguous: "原文に何度も出てきて、どれか決まらない",
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
    TERMS_FOUND: "求められた語が本文にある",
    TERMS_ABSENT: "求められた語が本文に無い",
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
    ["model_calls_left", "model_calls", "モデル呼び出し"],
    ["tokens_in_left", "tokens_in", "入力トークン"],
    ["tokens_out_left", "tokens_out", "出力トークン"],
    ["tool_calls_left", "tool_calls", "ツール呼び出し"],
    ["fetches_left", "fetches", "取得"],
    ["wall_ms_left", "wall_ms", "時間（ミリ秒）"],
  ];

  const $ = (id) => document.getElementById(id);
  const state = { selected: null, judge: null, caps: {}, running: false, traceCount: 0, events: [] };

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
    for (const p of presets) {
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
    for (const id of ["summary", "contradictions", "trace", "budget", "source-body"]) clear($(id));
    clear($("reqs").tBodies[0]);
    for (const id of ["warning", "status-note", "contradictions", "source"]) $(id).hidden = true;
    for (const id of ["who-band", "quote-band", "replan-band"]) $(id).hidden = true;
    for (const id of ["who-sum", "quote-band-sum", "quote-examples", "replan-steps", "replan-end"]) clear($(id));
    $("run-mode").textContent = "";
    state.events = [];
    state.traceCount = 0;
    $("trace-count").textContent = "0";
  }

  function onMode(m) {
    if (m.switched) {
      // ライブが時間内に終わらず、実行の途中で保存済みの実行へ切り替わった。途中までの表示は捨てて、保存済みの実行を最初から出す
      resetResult();
      $("run-mode").textContent = "ライブ実行が時間内に終わらなかったため、保存済みの実行を表示しています。";
      return;
    }
    if (m.mode === "LIVE") {
      $("run-mode").textContent = "ライブ実行（この場で要項を読み、提出物を検査しています）";
    } else {
      const why = REPLAY_REASON[m.reason] || "保存済みの実行を再生します";
      $("run-mode").textContent = m.available === false ? "停止中: " + why + "（保存済みの実行もありません）" : "再生（REPLAY）: " + why + "。以下は保存済みの実行です。";
    }
  }

  function onError(e) {
    const n = $("status-note");
    n.textContent = (e && e.message) ? e.message : "実行できませんでした。";
    n.hidden = false;
  }

  // ---- トレース・予算ゲージ ----
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
    if (ev.type === "budget_snapshot" && ev.budget) renderBudget(ev.budget);
  }

  function renderBudget(b) {
    const box = $("budget");
    clear(box);
    for (const [key, capKey, label] of GAUGES) {
      const cap = Number(state.caps[capKey] || 0);
      const left = Number(b[key] || 0);
      const id = "g-" + key;
      const meter = el("meter", { attrs: { id, min: 0, max: cap || 1, value: Math.min(left, cap || left), low: Math.max(1, cap * 0.2), optimum: cap } });
      box.appendChild(el("div", { cls: "gauge" }, [el("label", { text: label + ": 残り " + fmt(left) + (cap ? " / " + fmt(cap) : ""), attrs: { for: id } }), meter]));
    }
  }

  function jumpTo(seq) {
    if (seq === undefined || seq === null) return;
    $("trace-box").open = true;
    const li = document.getElementById("ev-" + seq);
    if (!li) return;
    for (const x of document.querySelectorAll(".trace li.hit")) x.classList.remove("hit");
    li.classList.add("hit");
    li.scrollIntoView({ block: "center" });
  }

  // ---- 結果 ----
  function stat(k, v) { return el("div", { cls: "stat" }, [el("span", { cls: "k", text: k }), el("span", { cls: "v", text: v })]); }

  function renderResult(rec) {
    const s = rec.summary || {};
    const counts = s.verdict_counts || {};
    const sum = $("summary");
    clear(sum);
    sum.appendChild(stat("要件", fmt(s.requirements_total) + " 件（必須・禁止 " + fmt(s.obligatory_total) + "）"));
    sum.appendChild(stat("引用検証", fmt(s.quotes_verbatim) + " / " + fmt(s.quotes_checked) + " 件が逐語一致"));
    sum.appendChild(stat("推測へ降格", fmt(s.demoted_to_speculative) + " 件"));
    sum.appendChild(stat("判定", ["不適合", "適合", "推定適合", "確認不能", "参考"].map((k) => k + " " + fmt(counts[k] || 0)).join("・")));
    if (rec.mode === "REPLAY") {
      sum.appendChild(stat("引用の検証", "保存時に検証済み（再生では原文を持たないため再検証しません）"));
      if (rec.omitted_requirements) sum.appendChild(stat("省略した要件", fmt(rec.omitted_requirements) + " 件（同梱では件数だけ残しています）"));
    }
    sum.appendChild(stat("矛盾", fmt(s.contradictions) + " 件"));
    sum.appendChild(stat("Governor の拒否", fmt(s.denied) + " 件"));
    sum.appendChild(stat("見積もり費用", "約 " + (Number(s.est_cost_micro_jpy || 0) / 1e6).toFixed(2) + " 円"));
    sum.appendChild(stat("モデル", (rec.reader_model || "") + " ／ 検査 " + (rec.planner_model || "")));

    if ((s.injection_visible || 0) + (s.injection_hidden || 0) > 0) {
      const w = $("warning");
      w.textContent = "偽の命令の疑い: 見える所に " + fmt(s.injection_visible) + " 件・隠れた所に " + fmt(s.injection_hidden) +
        " 件。読み取るモデルには伏せて渡し、判定には使っていません（判定は観測からコードが決めます）。";
      w.hidden = false;
    }
    if (STATUS_NOTE[rec.status]) {
      const n = $("status-note");
      n.textContent = STATUS_NOTE[rec.status] + (rec.degraded_reason ? "（" + rec.degraded_reason + "）" : rec.aborted_reason ? "（" + rec.aborted_reason + "）" : "");
      n.hidden = false;
    }
    renderContradictions(rec);
    const events = Array.isArray(rec.events) && rec.events.length ? rec.events : state.events;
    renderWhoBand(rec, events);
    renderQuoteBand(rec, events);
    renderReplanBand(rec, events);
    renderTable(rec);
  }

  // ---- 誰が決めたか（実行の内訳）。数字は記録の events・summary から数える。材料の無い記録では帯を出さない ----
  function renderWhoBand(rec, events) {
    const s = rec.summary;
    if (!s || typeof s.est_cost_micro_jpy !== "number" || !Array.isArray(events)) return;
    const list = events.filter((e) => e && typeof e === "object");
    if (!list.some((e) => e.phase === "AUTORUN")) return; // AUTORUN の無い古い記録では内訳を言えない
    const isCheck = (e) => e.type === "tool_result" && (e.name === "run_check" || e.name === "http_probe");
    const checks = list.filter(isCheck).length;
    if (!checks) return;
    const auto = list.filter((e) => isCheck(e) && e.phase === "AUTORUN").length;
    const modelCalls = list.filter((e) => e.type === "model_call").length;
    const plannerCalls = list.filter((e) => e.type === "model_call" && e.purpose === "planner").length;
    const replans = list.filter((e) => e.type === "replan").length;
    const skipped = list.some((e) => e.type === "autorun" && e.name === "planner_skipped");
    const cost = "約 " + (s.est_cost_micro_jpy / 1e6).toFixed(2) + " 円";
    let mid;
    if (plannerCalls > 0) mid = "Planner（モデル）が" + fmt(plannerCalls) + "手を判断（方針変更 " + fmt(replans) + "回）";
    else if (skipped) mid = "AUTORUN で全部決まったため、Planner（モデル）は呼ばれていません";
    else mid = "Planner（モデル）は使っていません";
    $("who-sum").textContent = "検査 " + fmt(checks) + "件: AUTORUN（コード）が" + fmt(auto) + "件を実行／" + mid +
      "／モデル呼び出し " + fmt(modelCalls) + "回・見積もり " + cost;
    $("who-band").hidden = false;
  }

  // ---- コードが検証した引用（要約と、モデルの引用をコードが弾いた例）----
  // 必要なフィールドが無い記録（古い記録・省略された記録）では帯を出さない。
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
      seq: ev.seq,
      model: first.model_quote || "",
      reason: QUOTE_REJECT_JA[first.reason_code] || first.reason_code || "",
      result: unverified ? "demoted" : requoted ? "requoted" : "verified",
      original: req && req.span ? req.span.original_span : "",
    };
  }

  function renderQuoteBand(rec, events) {
    const s = rec.summary;
    if (!s || typeof s.quotes_checked !== "number" || typeof s.quotes_verbatim !== "number" || s.quotes_checked <= 0) return;
    const sum = "引用検証 " + fmt(s.quotes_checked) + "件中" + fmt(s.quotes_verbatim) + "件が逐語一致・" +
      fmt(s.demoted_to_speculative || 0) + "件を推測へ降格";
    $("quote-band-sum").textContent = sum;
    const reqs = {};
    for (const r of rec.requirements || []) reqs[r.req_id] = r;
    const ex = [];
    for (const ev of events || []) {
      if (!ev || ev.type !== "quote_check") continue;
      const x = quoteExample(ev, reqs);
      if (x) ex.push(x);
      if (ex.length >= 3) break;
    }
    const ul = $("quote-examples");
    clear(ul);
    for (const x of ex) {
      const li = el("li");
      li.appendChild(el("span", { cls: "ex-head", text: x.reqId + "：モデルの引用をコードが原文と照合" }));
      li.appendChild(el("span", { cls: "ex-model", text: "✕ 「" + clip(x.model, 80) + "」を棄却（" + x.reason + "）" }));
      if (x.result === "requoted" && x.original) {
        li.appendChild(el("span", { cls: "ex-code ex-ok", text: "→ 再引用 「" + clip(x.original, 80) + "」" }));
        li.appendChild(el("span", { cls: "ex-result ex-ok", text: "✓ 原文と逐語で一致（コードが確認）" }));
      } else if (x.result === "demoted") {
        li.appendChild(el("span", { cls: "ex-result ex-demoted", text: "→ 再引用も一致せず、推測に降格（判定の根拠にしません）" }));
      } else if (x.original) {
        li.appendChild(el("span", { cls: "ex-code ex-ok", text: "→ 「" + clip(x.original, 80) + "」" }));
        li.appendChild(el("span", { cls: "ex-result ex-ok", text: "✓ 原文と逐語で一致（コードが確認）" }));
      }
      ul.appendChild(li);
    }
    ul.hidden = ex.length === 0;
    $("quote-band").hidden = false;
  }

  // ---- 判断が変わった場面（replan の印の前後）----
  function obsText(code) { return code ? (OBS_JA[code] || code) : "結果なし"; }
  function stepNode(kind, text, seq, change) {
    const b = el("button", { cls: "step" + (change ? " step-change" : ""), attrs: { type: "button", title: "トレースの該当イベントへ" } }, [
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
    steps.appendChild(stepNode("① 観測", (TOOL_JA[trigger.name] || trigger.name) + req + " → " + obsText(trigger.reason_code), trigger.seq, false));
    steps.appendChild(stepNode("② 次の手（方針変更）", (TOOL_JA[mark.name] || mark.name) + "：別のページを調べ直す" + (moved ? " → " + obsText(moved.reason_code) : ""), mark.seq, true));
    if (next) steps.appendChild(stepNode("③ 続く観測", (TOOL_JA[next.name] || next.name) + req + " → " + obsText(next.reason_code), next.seq, false));
    const verdict = (rec.verdicts || []).find((v) => v.req_id === mark.req_id);
    const end = $("replan-end");
    if (verdict) {
      end.textContent = mark.req_id + " の判定: " + verdict.label + "（観測からコードが決めました。モデルは書けません）";
      end.hidden = false;
    }
    $("replan-band").hidden = false;
  }

  function renderContradictions(rec) {
    const list = rec.contradictions || [];
    const box = $("contradictions");
    clear(box);
    if (!list.length) return;
    const ul = el("ul");
    for (const c of list) {
      ul.appendChild(el("li", { text: c.slot + ": " + c.tokens[0] + "（" + c.req_ids[0] + "）と " + c.tokens[1] + "（" + c.req_ids[1] + "）が食い違います" }));
    }
    box.appendChild(el("h3", { text: "要項の間の矛盾（" + list.length + " 件）" }));
    box.appendChild(ul);
    box.hidden = false;
  }

  function verdictNode(v) {
    const m = VERDICT[v.label] || ["v-ref", "・"];
    return el("span", { cls: "verdict " + m[0] }, [el("span", { text: m[1], attrs: { "aria-hidden": "true" } }), document.createTextNode(v.label)]);
  }

  function renderTable(rec) {
    const docs = {};
    for (const d of rec.docs || []) docs[d.doc_id] = d;
    const verdicts = {};
    for (const v of rec.verdicts || []) verdicts[v.req_id] = v;
    const tbody = $("reqs").tBodies[0];
    clear(tbody);
    for (const r of rec.requirements || []) {
      const v = verdicts[r.req_id];
      const kindCell = el("td", { attrs: { "data-label": "種別" } }, [el("span", { cls: "badge " + (KIND_CLASS[r.kind] || ""), text: r.kind })]);
      if (r.declared_kind !== r.kind) kindCell.appendChild(el("span", { cls: "chip-note", text: "申告: " + r.declared_kind }));
      for (const c of r.chips || []) kindCell.appendChild(el("span", { cls: "chip-note", text: CHIP_JA[c] || c }));

      const quoteCell = el("td", { attrs: { "data-label": "要件（原文の引用）" } });
      let srcCell;
      if (r.span) {
        quoteCell.appendChild(el("p", { cls: "quote", text: "「" + clip(r.span.original_span, 80) + "」" }));
        const d = docs[r.span.doc_id];
        const btn = el("button", { cls: "linkish", text: r.span.doc_id + " " + (d ? d.label : ""), attrs: { type: "button" } });
        btn.addEventListener("click", () => showSource(r, d));
        srcCell = el("td", { attrs: { "data-label": "出典" } }, [btn]);
      } else {
        quoteCell.appendChild(el("p", { cls: "quote quote-none", text: "（原文に引用できない推測）" + (r.gist ? " " + r.gist : "") }));
        srcCell = el("td", { text: "—", attrs: { "data-label": "出典" } });
      }

      const vCell = el("td", { attrs: { "data-label": "判定" } }, [v ? verdictNode(v) : document.createTextNode("—")]);
      const why = el("td", { attrs: { "data-label": "理由・証拠" } });
      if (v) {
        const label = v.reason_code ? (REASON_JA[v.reason_code] || v.reason_code) : "";
        const body = v.reason || "";
        const reasonText = label && !body.startsWith(label) ? label + "。" + body : body; // 理由文が既に同じ語で始まるなら重ねない
        if (reasonText) why.appendChild(el("p", { cls: "reason", text: reasonText }));
        if (v.label !== "参考" && (v.evidence || []).length) {
          const chips = el("div", { cls: "evidence" });
          for (const e of v.evidence) {
            const b = el("button", { cls: "chip", text: e.label, attrs: { type: "button", title: "トレースの該当イベントへ" } });
            b.addEventListener("click", () => jumpTo(e.event_seq));
            chips.appendChild(b);
          }
          why.appendChild(chips);
        }
      }
      tbody.appendChild(el("tr", null, [el("td", { text: r.req_id, attrs: { "data-label": "ID" } }), kindCell, quoteCell, srcCell, vCell, why]));
    }
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
      ["位置", "可視テキストの " + fmt(r.span.start) + "〜" + fmt(r.span.end) + " 文字目（出現 " + r.span.occurrences + " 回）"],
    ];
    for (const [k, v] of rows) { dl.appendChild(el("dt", { text: k })); dl.appendChild(el("dd", { text: v })); }
    dl.appendChild(el("dt", { text: "原文の1文" }));
    dl.appendChild(el("dd", null, [el("mark", { text: r.span.original_span })]));
    if (r.span.quote_clipped) {
      dl.appendChild(el("dt", { text: "引用の長さ" }));
      dl.appendChild(el("dd", { text: "同梱の記録のため80字までに切り詰めています（位置は元の文のものです）" }));
    }
    $("source").hidden = false;
    $("source-close").focus();
  }

  document.addEventListener("DOMContentLoaded", () => {
    readJudgeCode();
    $("run").addEventListener("click", run);
    $("source-close").addEventListener("click", () => { $("source").hidden = true; });
    loadStatus();
  });
})();
