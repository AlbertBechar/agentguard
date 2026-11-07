// Athena chat widget.
// SECURITY (AgentGuard, P4): the assistant's reply may be controlled by a prompt-injected model.
// We turn markdown into HTML with marked, then clean it with an ALLOWLIST before it touches the page:
// no images (they leak data via the URL with zero clicks), no scripts/iframes/styles/forms,
// no attributes except a safe href on links.
(function () {
  const panel = document.getElementById('chat');
  const toggle = document.getElementById('chat-toggle');
  const log = document.getElementById('chat-log');
  const form = document.getElementById('chat-form');
  const input = document.getElementById('chat-input');
  let loaded = false;

  // Only these tags survive (normal markdown formatting). Everything else is removed or unwrapped.
  const ALLOWED_TAGS = new Set(['P', 'BR', 'HR', 'STRONG', 'B', 'EM', 'I', 'DEL', 'S', 'CODE', 'PRE', 'BLOCKQUOTE',
    'UL', 'OL', 'LI', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'A', 'TABLE', 'THEAD', 'TBODY', 'TR', 'TH', 'TD', 'SPAN']);
  // These are dropped together with their content (unwrapping a <script> would leave its code as text).
  const DROP_TAGS = new Set(['SCRIPT', 'STYLE', 'IFRAME', 'FRAME', 'FRAMESET', 'OBJECT', 'EMBED', 'LINK', 'META',
    'BASE', 'FORM', 'INPUT', 'BUTTON', 'TEXTAREA', 'SELECT', 'SVG', 'MATH', 'VIDEO', 'AUDIO', 'SOURCE', 'PICTURE',
    'NOSCRIPT', 'TEMPLATE']);

  // Links: only http(s) or relative (which resolve to our own http(s) origin). Blocks javascript:, data:, ...
  function safeHref(href) {
    try {
      const u = new URL(href, location.href);
      return (u.protocol === 'http:' || u.protocol === 'https:') ? u.href : null;
    } catch (e) { return null; }
  }

  function cleanNode(node) {
    for (const child of Array.from(node.childNodes)) {
      if (child.nodeType === Node.TEXT_NODE) continue;
      if (child.nodeType !== Node.ELEMENT_NODE) { child.remove(); continue; }  // e.g. HTML comments
      const tag = child.tagName.toUpperCase();
      if (tag === 'IMG') { child.replaceWith(document.createTextNode('[image blocked]')); continue; }
      if (DROP_TAGS.has(tag)) { child.remove(); continue; }
      cleanNode(child);                                    // clean the inside first
      if (!ALLOWED_TAGS.has(tag)) { child.replaceWith(...child.childNodes); continue; }  // unknown tag: keep text
      for (const attr of Array.from(child.attributes)) {  // removes on*, style, src, class, ... everything
        if (!(tag === 'A' && attr.name === 'href')) child.removeAttribute(attr.name);
      }
      if (tag === 'A') {
        const href = safeHref(child.getAttribute('href') || '');
        if (href) {
          child.setAttribute('href', href);
          child.setAttribute('rel', 'noopener noreferrer');
          child.setAttribute('target', '_blank');
        } else {
          child.removeAttribute('href');
        }
      }
    }
  }

  // markdown -> safe DocumentFragment. A <template> is inert: nothing inside it loads or runs,
  // so we can inspect and clean the HTML before it is inserted into the real page.
  function renderAssistant(text) {
    const tpl = document.createElement('template');
    tpl.innerHTML = marked.parse(text || '');
    cleanNode(tpl.content);
    return tpl.content;
  }
  // For checking from the DevTools console: renderAssistantHTML('![x](http://evil.example/p.png)')
  window.renderAssistantHTML = function (text) {
    const div = document.createElement('div');
    div.appendChild(renderAssistant(text));
    return div.innerHTML;
  };

  function scroll() { log.scrollTop = log.scrollHeight; }

  function add(role, text) {
    const div = document.createElement('div');
    div.className = 'msg ' + role;
    if (role === 'assistant') div.appendChild(renderAssistant(text));
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
