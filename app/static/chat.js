// Athena chat widget.
// NOTE (deliberately insecure): the assistant's reply is rendered as raw HTML via marked,
// without sanitization. Think about what a prompt-injected model could output here...
(function () {
  const panel = document.getElementById('chat');
  const toggle = document.getElementById('chat-toggle');
  const log = document.getElementById('chat-log');
  const form = document.getElementById('chat-form');
  const input = document.getElementById('chat-input');
  let loaded = false;

  function scroll() { log.scrollTop = log.scrollHeight; }

  function add(role, text) {
    const div = document.createElement('div');
    div.className = 'msg ' + role;
    if (role === 'assistant') div.innerHTML = marked.parse(text || '');
    else div.textContent = text;
    log.appendChild(div);
    scroll();
    return div;
  }

  // Live activity panel for one turn: LLM calls, tool calls with args/results, errors.
  function addActivity() {
    const d = document.createElement('details');
    d.className = 'tools';
    d.open = true;
    const summary = document.createElement('summary');
    d.appendChild(summary);
    log.appendChild(d);
    const t0 = Date.now();
    let tools = 0, done = false;
    const label = () => {
      const secs = ((Date.now() - t0) / 1000).toFixed(0);
      summary.textContent = (done ? '🛠 ' : '⏳ ') + (done ? 'Done' : 'Working') + ' · ' + secs + 's · ' +
        tools + ' tool call' + (tools === 1 ? '' : 's');
    };
    label();
    const timer = setInterval(label, 1000);
    return {
      line(text, cls) {
        const div = document.createElement('div');
        div.className = 'log-line' + (cls ? ' ' + cls : '');
        div.textContent = text;
        d.appendChild(div);
        scroll();
      },
      tool(ev) {
        tools++;
        const pre = document.createElement('pre');
        pre.textContent = ev.name + '(' + JSON.stringify(ev.args) + ')\n→ ' +
          JSON.stringify(ev.result, null, 1).slice(0, 3000);
        d.appendChild(pre);
        label();
        scroll();
      },
      finish() {
        done = true;
        clearInterval(timer);
        label();
        d.open = false;
        if (d.children.length === 1) d.remove();  // nothing logged (SHOW_TOOL_CALLS=false)
      },
    };
  }

  async function open() {
    panel.hidden = false;
    toggle.hidden = true;
    localStorage.setItem('chatOpen', '1');
    input.focus();
    if (loaded) return;
    loaded = true;
    const r = await fetch('/api/chat/history');
    if (r.ok) (await r.json()).messages.forEach(m => add(m.role, m.text));
  }

  function close() {
    panel.hidden = true;
    toggle.hidden = false;
    localStorage.removeItem('chatOpen');
  }

  toggle.onclick = open;
  document.getElementById('chat-close').onclick = close;
  document.getElementById('chat-reset').onclick = async () => {
    await fetch('/api/chat/reset', { method: 'POST' });
    log.innerHTML = '';
    add('assistant', 'Conversation cleared.');
  };

  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); }
  });

  form.onsubmit = async e => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    input.value = '';
    add('user', text);
    const activity = addActivity();
    let gotReply = false;
    try {
      const r = await fetch('/api/chat/stream', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: text })
      });
      if (!r.ok || !r.body) throw new Error('HTTP ' + r.status);
      const reader = r.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (!line) continue;
          const ev = JSON.parse(line);
          if (ev.type === 'log') activity.line(ev.text);
          else if (ev.type === 'tool') activity.tool(ev);
          else if (ev.type === 'error') { activity.line('Error: ' + ev.text, 'err'); add('error', ev.text); gotReply = true; }
          else if (ev.type === 'reply') { add('assistant', ev.text); gotReply = true; }
        }
      }
      if (!gotReply) add('error', 'The connection closed without an answer.');
    } catch (err) {
      add('error', String(err));
    } finally {
      activity.finish();
    }
  };

  try { if (localStorage.getItem('chatOpen')) open(); } catch (e) {}
})();
