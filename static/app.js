/* ══════════════════════════════════════════════════
   Crypto Channel Lab — v2  ·  Frontend logic
   ══════════════════════════════════════════════════ */

// ── DOM cache ──────────────────────────────────────
const el = {
  // KPIs
  kpiMessages:  document.getElementById('kpiMessages'),
  kpiCaesar:    document.getElementById('kpiCaesar'),
  kpiXor:       document.getElementById('kpiXor'),
  kpiDec:       document.getElementById('kpiDec'),
  // Dashboard mini-tables
  dashMsgBody:    document.getElementById('dashMsgBody'),
  dashAuditBody:  document.getElementById('dashAuditBody'),
  dashMsgEmpty:   document.getElementById('dashMsgEmpty'),
  dashAuditEmpty: document.getElementById('dashAuditEmpty'),
  // Keys
  keyName:      document.getElementById('keyName'),
  keyCipher:    document.getElementById('keyCipher'),
  keyShift:     document.getElementById('keyShift'),
  keySecret:    document.getElementById('keySecret'),
  shiftLabel:   document.getElementById('shiftLabel'),
  secretLabel:  document.getElementById('secretLabel'),
  createKeyBtn: document.getElementById('createKeyBtn'),
  keysBody:     document.getElementById('keysBody'),
  keysEmpty:    document.getElementById('keysEmpty'),
  // Send
  sender:     document.getElementById('sender'),
  receiver:   document.getElementById('receiver'),
  keySelect:  document.getElementById('keySelect'),
  message:    document.getElementById('message'),
  charCount:  document.getElementById('charCount'),
  sendBtn:    document.getElementById('sendBtn'),
  // Messages
  msgBody:    document.getElementById('msgBody'),
  msgSearch:  document.getElementById('msgSearch'),
  msgEmpty:   document.getElementById('msgEmpty'),
  // Audit
  auditBody:  document.getElementById('auditBody'),
  auditEmpty: document.getElementById('auditEmpty'),
  // Controls
  darkToggle:     document.getElementById('darkToggle'),
  statusDot:      document.getElementById('statusDot'),
  exportBtn:      document.getElementById('exportBtn'),
  importFile:     document.getElementById('importFile'),
  seedBtn:        document.getElementById('seedBtn'),
  tabBar:         document.getElementById('tabBar'),
  toastBox:       document.getElementById('toastBox'),
  confirmOverlay: document.getElementById('confirmOverlay'),
  confirmMsg:     document.getElementById('confirmMsg'),
  confirmYes:     document.getElementById('confirmYes'),
  confirmNo:      document.getElementById('confirmNo'),
};

// Cached data for search filtering
let cachedMessages = [];
let cachedAudits   = [];

/* ═══════════════════════════════════════════════════
   Mejora 2 · Dark mode + localStorage
   ═══════════════════════════════════════════════════ */
function applyTheme(dark) {
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  el.darkToggle.textContent = dark ? '☀️' : '🌙';
  localStorage.setItem('crypto_dark', dark ? '1' : '0');
}

(function initTheme() {
  const stored = localStorage.getItem('crypto_dark');
  const prefersDark = stored === '1' || (stored === null && matchMedia('(prefers-color-scheme:dark)').matches);
  applyTheme(prefersDark);
})();

el.darkToggle.addEventListener('click', () => {
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  applyTheme(!isDark);
});

/* ═══════════════════════════════════════════════════
   Mejora 3 · Tabs
   ═══════════════════════════════════════════════════ */
el.tabBar.addEventListener('click', (e) => {
  const btn = e.target.closest('.tab');
  if (!btn) return;
  const target = btn.dataset.tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t === btn));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `tab-${target}`));
});

/* ═══════════════════════════════════════════════════
   Mejora 6 · Toast notifications
   ═══════════════════════════════════════════════════ */
function toast(msg, tone = 'ok') {
  const d = document.createElement('div');
  d.className = `toast toast-${tone}`;
  d.textContent = msg;
  el.toastBox.appendChild(d);
  setTimeout(() => { d.classList.add('fade-out'); setTimeout(() => d.remove(), 360); }, 3200);
}

/* ═══════════════════════════════════════════════════
   Mejora 7 · nousConfirm (Promise-based)
   ═══════════════════════════════════════════════════ */
function nousConfirm(msg) {
  return new Promise((resolve) => {
    el.confirmMsg.textContent = msg;
    el.confirmOverlay.classList.remove('hidden');
    function cleanup(val) {
      el.confirmOverlay.classList.add('hidden');
      el.confirmYes.removeEventListener('click', onYes);
      el.confirmNo.removeEventListener('click', onNo);
      resolve(val);
    }
    function onYes() { cleanup(true); }
    function onNo()  { cleanup(false); }
    el.confirmYes.addEventListener('click', onYes);
    el.confirmNo.addEventListener('click', onNo);
  });
}

/* ═══════════════════════════════════════════════════
   Status dot
   ═══════════════════════════════════════════════════ */
async function checkStatus() {
  try {
    const r = await fetch('/api/stats');
    el.statusDot.className = r.ok ? 'status-dot online' : 'status-dot offline';
  } catch {
    el.statusDot.className = 'status-dot offline';
  }
}

/* ═══════════════════════════════════════════════════
   Key form
   ═══════════════════════════════════════════════════ */
function refreshKeyForm() {
  const isCaesar = el.keyCipher.value === 'caesar';
  el.shiftLabel.classList.toggle('hidden', !isCaesar);
  el.secretLabel.classList.toggle('hidden', isCaesar);
}
el.keyCipher.addEventListener('change', refreshKeyForm);
refreshKeyForm();

/* ═══════════════════════════════════════════════════
   Mejora 12 · Character counter
   ═══════════════════════════════════════════════════ */
function updateCharCount() {
  el.charCount.textContent = el.message.value.length;
}
el.message.addEventListener('input', updateCharCount);
updateCharCount();

/* ═══════════════════════════════════════════════════
   Mejora 11 · Badge helpers
   ═══════════════════════════════════════════════════ */
function channelBadge(ch) {
  const c = ch.toLowerCase();
  return `<span class="badge badge-${c}">${c.toUpperCase()}</span>`;
}
function cipherBadge(ci) {
  const c = ci.toLowerCase();
  return `<span class="badge badge-${c}">${c.toUpperCase()}</span>`;
}

/* ═══════════════════════════════════════════════════
   API helpers
   ═══════════════════════════════════════════════════ */
async function loadKeys() {
  try {
    const res = await fetch('/api/keys');
    if (!res.ok) return;
    const data = await res.json();
    const items = data.items || [];
    // Key select dropdown
    el.keySelect.innerHTML = items.map(k => `<option value="${k.name}">${k.name} (${k.cipher})</option>`).join('');
    // Keys table
    if (items.length === 0) {
      el.keysBody.innerHTML = '';
      el.keysEmpty.classList.remove('hidden');
    } else {
      el.keysEmpty.classList.add('hidden');
      el.keysBody.innerHTML = items.map(k => `
        <tr>
          <td>${k.id}</td>
          <td>${k.name}</td>
          <td>${cipherBadge(k.cipher)}</td>
          <td>${k.cipher === 'caesar' ? k.shift : '—'}</td>
          <td>${k.created_at}</td>
        </tr>`).join('');
    }
  } catch { /* silent */ }
}

async function createKey() {
  const cipher  = el.keyCipher.value;
  const payload = {
    name:   el.keyName.value.trim(),
    cipher,
    shift:  Number(el.keyShift.value),
    secret: el.keySecret.value,
  };
  try {
    const res = await fetch('/api/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      toast('Clave creada correctamente', 'ok');
      await loadKeys();
    } else {
      const d = await res.json();
      toast(d.error || 'Error al crear clave', 'error');
    }
  } catch { toast('Error de red', 'error'); }
}

async function sendMessage() {
  const payload = {
    sender:   el.sender.value.trim() || 'nodo-a',
    receiver: el.receiver.value.trim() || 'nodo-b',
    key_name: el.keySelect.value,
    message:  el.message.value,
  };
  try {
    const res = await fetch('/api/messages/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      toast('Mensaje cifrado y enviado', 'ok');
      el.message.value = 'Mensaje de prueba protegido.';
      updateCharCount();
    } else {
      toast('Error al enviar mensaje', 'error');
    }
  } catch { toast('Error de red', 'error'); }
}

async function decryptMessage(messageId) {
  const ok = await nousConfirm(`¿Descifrar el mensaje #${messageId}?`);
  if (!ok) return;
  try {
    const res = await fetch('/api/messages/decrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message_id: messageId, actor: 'panel-web' }),
    });
    if (res.ok) {
      const d = await res.json();
      toast(`Descifrado: ${d.plain.slice(0, 60)}…`, 'info');
    } else {
      toast('Error al descifrar', 'error');
    }
  } catch { toast('Error de red', 'error'); }
  await loadMessages();
  await loadStats();
}
window.__decrypt = decryptMessage;

/* ═══════════════════════════════════════════════════
   Load messages + audits
   ═══════════════════════════════════════════════════ */
async function loadMessages() {
  try {
    const res = await fetch('/api/messages?limit=200');
    if (!res.ok) return;
    const data = await res.json();
    cachedMessages = data.items || [];
    cachedAudits   = data.audits || [];
    renderMessages(cachedMessages);
    renderAudits(cachedAudits);
    renderDashboard(cachedMessages, cachedAudits);
  } catch { /* silent */ }
}

/* ═══════════════════════════════════════════════════
   Mejora 10 · Render with search filter
   ═══════════════════════════════════════════════════ */
function renderMessages(items) {
  const q = (el.msgSearch.value || '').trim().toLowerCase();
  let filtered = items;
  if (q) {
    filtered = items.filter(m =>
      (m.sender + m.receiver + m.key_name + m.cipher + m.channel + m.encrypted_payload)
        .toLowerCase().includes(q)
    );
  }

  if (filtered.length === 0) {
    el.msgBody.innerHTML = '';
    el.msgEmpty.classList.remove('hidden');
  } else {
    el.msgEmpty.classList.add('hidden');
    el.msgBody.innerHTML = filtered.map(m => `
      <tr>
        <td>${m.id}</td>
        <td>${m.created_at}</td>
        <td>${channelBadge(m.channel)}</td>
        <td>${m.key_name}</td>
        <td>${cipherBadge(m.cipher)}</td>
        <td>${m.encrypted_payload.slice(0, 36)}…</td>
        <td><button onclick="window.__decrypt(${m.id})">Descifrar</button></td>
      </tr>`).join('');
  }
}

function renderAudits(items) {
  if (!items || items.length === 0) {
    el.auditBody.innerHTML = '';
    el.auditEmpty.classList.remove('hidden');
  } else {
    el.auditEmpty.classList.add('hidden');
    el.auditBody.innerHTML = items.map(a => `
      <tr>
        <td>${a.id}</td>
        <td>${a.message_id}</td>
        <td>${a.created_at}</td>
        <td>${a.actor}</td>
        <td>${a.result_preview}</td>
      </tr>`).join('');
  }
}

/* ═══════════════════════════════════════════════════
   Mejora 4 · Dashboard mini-tables
   ═══════════════════════════════════════════════════ */
function renderDashboard(msgs, audits) {
  const last5Msgs   = msgs.slice(0, 5);
  const last5Audits = audits.slice(0, 5);

  if (last5Msgs.length === 0) {
    el.dashMsgBody.innerHTML = '';
    el.dashMsgEmpty.classList.remove('hidden');
  } else {
    el.dashMsgEmpty.classList.add('hidden');
    el.dashMsgBody.innerHTML = last5Msgs.map(m => `
      <tr>
        <td>${m.id}</td>
        <td>${channelBadge(m.channel)}</td>
        <td>${cipherBadge(m.cipher)}</td>
        <td>${m.sender}</td>
        <td>${m.created_at}</td>
      </tr>`).join('');
  }

  if (last5Audits.length === 0) {
    el.dashAuditBody.innerHTML = '';
    el.dashAuditEmpty.classList.remove('hidden');
  } else {
    el.dashAuditEmpty.classList.add('hidden');
    el.dashAuditBody.innerHTML = last5Audits.map(a => `
      <tr>
        <td>${a.id}</td>
        <td>${a.message_id}</td>
        <td>${a.actor}</td>
        <td>${a.created_at}</td>
      </tr>`).join('');
  }
}

/* ═══════════════════════════════════════════════════
   Stats / KPIs
   ═══════════════════════════════════════════════════ */
async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const d = await res.json();
    el.kpiMessages.textContent = d.total_messages;
    el.kpiCaesar.textContent   = d.by_cipher.caesar;
    el.kpiXor.textContent      = d.by_cipher.xor;
    el.kpiDec.textContent      = d.runtime.decrypt_ops;
  } catch { /* silent */ }
}

/* ═══════════════════════════════════════════════════
   Mejora 8 · Export / Import JSON
   ═══════════════════════════════════════════════════ */
el.exportBtn.addEventListener('click', () => {
  const payload = { messages: cachedMessages, audits: cachedAudits, exported_at: new Date().toISOString() };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `crypto-channel-export-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast('Datos exportados', 'ok');
});

el.importFile.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    const msgs = data.messages || [];
    if (msgs.length === 0) { toast('El archivo no contiene mensajes', 'warning'); return; }
    const ok = await nousConfirm(`¿Importar ${msgs.length} mensajes desde el archivo?`);
    if (!ok) return;
    let imported = 0;
    for (const m of msgs) {
      const res = await fetch('/api/messages/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sender:   m.sender   || 'import',
          receiver: m.receiver || 'import',
          key_name: m.key_name || 'default_caesar',
          message:  m.plain_preview || 'imported',
        }),
      });
      if (res.ok) imported++;
    }
    toast(`${imported} mensajes importados`, 'ok');
    await loadMessages();
    await loadStats();
  } catch { toast('Error al leer archivo', 'error'); }
  e.target.value = '';
});

/* ═══════════════════════════════════════════════════
   Mejora 9 · Seed data
   ═══════════════════════════════════════════════════ */
const SEED_MESSAGES = [
  { sender: 'alice',   receiver: 'bob',    key_name: 'default_caesar', message: 'Hola Bob, esta prueba usa cifrado César con shift 5.' },
  { sender: 'bob',     receiver: 'alice',  key_name: 'default_xor',   message: 'Respuesta cifrada con XOR y secreto DAM2-PSP.' },
  { sender: 'server',  receiver: 'nodo-c', key_name: 'default_caesar', message: 'Confirmación de handshake cifrado correcto.' },
  { sender: 'nodo-a',  receiver: 'nodo-b', key_name: 'default_xor',   message: 'Transferencia de token de sesión protegida.' },
  { sender: 'admin',   receiver: 'server', key_name: 'default_caesar', message: 'Reinicio planificado del canal seguro a las 03:00.' },
];

el.seedBtn.addEventListener('click', async () => {
  const ok = await nousConfirm('¿Insertar 5 mensajes de ejemplo?');
  if (!ok) return;
  let count = 0;
  for (const s of SEED_MESSAGES) {
    const res = await fetch('/api/messages/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(s),
    });
    if (res.ok) count++;
  }
  toast(`${count} mensajes seed insertados`, 'ok');
  await loadMessages();
  await loadStats();
});

/* ═══════════════════════════════════════════════════
   Mejora 10 · Live search
   ═══════════════════════════════════════════════════ */
el.msgSearch.addEventListener('input', () => renderMessages(cachedMessages));

/* ═══════════════════════════════════════════════════
   Event bindings
   ═══════════════════════════════════════════════════ */
el.createKeyBtn.addEventListener('click', async () => {
  await createKey();
  await loadMessages();
  await loadStats();
});

el.sendBtn.addEventListener('click', async () => {
  await sendMessage();
  await loadMessages();
  await loadStats();
});

/* ═══════════════════════════════════════════════════
   Init
   ═══════════════════════════════════════════════════ */
checkStatus();
loadKeys();
loadMessages();
loadStats();

setInterval(async () => {
  await loadMessages();
  await loadStats();
  checkStatus();
}, 4000);
