const el = {
  kpiMessages: document.getElementById('kpiMessages'),
  kpiCaesar: document.getElementById('kpiCaesar'),
  kpiXor: document.getElementById('kpiXor'),
  kpiDec: document.getElementById('kpiDec'),
  keyName: document.getElementById('keyName'),
  keyCipher: document.getElementById('keyCipher'),
  keyShift: document.getElementById('keyShift'),
  keySecret: document.getElementById('keySecret'),
  shiftLabel: document.getElementById('shiftLabel'),
  secretLabel: document.getElementById('secretLabel'),
  createKeyBtn: document.getElementById('createKeyBtn'),
  sender: document.getElementById('sender'),
  receiver: document.getElementById('receiver'),
  keySelect: document.getElementById('keySelect'),
  message: document.getElementById('message'),
  sendBtn: document.getElementById('sendBtn'),
  msgBody: document.getElementById('msgBody'),
  auditBody: document.getElementById('auditBody'),
};

function refreshKeyForm() {
  const isCaesar = el.keyCipher.value === 'caesar';
  el.shiftLabel.classList.toggle('hidden', !isCaesar);
  el.secretLabel.classList.toggle('hidden', isCaesar);
}

async function loadKeys() {
  const res = await fetch('/api/keys');
  if (!res.ok) return;
  const data = await res.json();
  const items = data.items || [];
  el.keySelect.innerHTML = items.map((k) => `<option value="${k.name}">${k.name} (${k.cipher})</option>`).join('');
}

async function createKey() {
  const cipher = el.keyCipher.value;
  const payload = {
    name: el.keyName.value.trim(),
    cipher,
    shift: Number(el.keyShift.value),
    secret: el.keySecret.value,
  };

  const res = await fetch('/api/keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (res.ok) {
    await loadKeys();
  }
}

async function sendMessage() {
  const payload = {
    sender: el.sender.value.trim() || 'nodo-a',
    receiver: el.receiver.value.trim() || 'nodo-b',
    key_name: el.keySelect.value,
    message: el.message.value,
  };

  await fetch('/api/messages/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

async function decryptMessage(messageId) {
  await fetch('/api/messages/decrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message_id: messageId, actor: 'panel-web' }),
  });
  await loadMessages();
  await loadStats();
}

function renderMessages(items) {
  el.msgBody.innerHTML = items.map((m) => `
    <tr>
      <td>${m.id}</td>
      <td>${m.created_at}</td>
      <td>${m.channel}</td>
      <td>${m.key_name}</td>
      <td>${m.cipher}</td>
      <td>${m.encrypted_payload.slice(0, 36)}...</td>
      <td><button onclick="window.__decrypt(${m.id})">Descifrar</button></td>
    </tr>
  `).join('');
}

function renderAudits(items) {
  el.auditBody.innerHTML = (items || []).map((a) => `
    <tr>
      <td>${a.id}</td>
      <td>${a.message_id}</td>
      <td>${a.created_at}</td>
      <td>${a.actor}</td>
      <td>${a.result_preview}</td>
    </tr>
  `).join('');
}

async function loadMessages() {
  const res = await fetch('/api/messages?limit=100');
  if (!res.ok) return;
  const data = await res.json();
  renderMessages(data.items || []);
  renderAudits(data.audits || []);
}

async function loadStats() {
  const res = await fetch('/api/stats');
  if (!res.ok) return;
  const data = await res.json();

  el.kpiMessages.textContent = data.total_messages;
  el.kpiCaesar.textContent = data.by_cipher.caesar;
  el.kpiXor.textContent = data.by_cipher.xor;
  el.kpiDec.textContent = data.runtime.decrypt_ops;
}

window.__decrypt = decryptMessage;

el.keyCipher.addEventListener('change', refreshKeyForm);
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

refreshKeyForm();
loadKeys();
loadMessages();
loadStats();
setInterval(async () => {
  await loadMessages();
  await loadStats();
}, 4000);
