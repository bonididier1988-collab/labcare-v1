// Labcare V1 — frontend (sans étape de build, JavaScript simple).
// Écrans : connexion (avec 2FA simulée), tableau des dossiers, fiche dossier,
// Utilisateurs (Admin), profil. Données fictives de test uniquement.
const $ = (s) => document.querySelector(s);
const app = $('#app');
const who = $('#who');

// Comptes de test : ils ne vivent plus dans le frontend. La page de
// connexion les demande au serveur (/api/test-accounts), qui ne les
// expose qu'en développement — en production, la liste reste vide.
let testAccounts = null;

let me = null;
let meta = null;
let notifUnread = 0;
// Pagination du tableau : page courante gardée en mémoire, 10 dossiers par page.
let boardPage = 1;
let boardQuery = '';
const BOARD_LIMIT = 10;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || 'Erreur du serveur.');
    err.status = res.status;
    if (res.status === 503 && data.maintenance) {
      err.maintenance = true;
      // Un non-admin déjà connecté voit la page de maintenance, pas une erreur brute.
      if (me && !me.roles.includes('admin')) viewMaintenance();
    }
    throw err;
  }
  return data;
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' });
}
function fmtDateTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('fr-FR', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
}
function roleLabel(r) { return (meta && meta.roles[r]) || r; }
function stepLabel(n) { const s = meta && meta.steps.find((x) => x.n === n); return s ? s.label : 'Étape ' + n; }
function excLabel(k) { return (meta && meta.exceptions[k] && meta.exceptions[k].label) || k; }

// ---------- Squelettes de chargement (UI/UX) ----------
// Formes grises animées qui imitent le contenu à venir : elles s'affichent
// pendant que les données chargent, pour que l'écran ne reste jamais vide.
function skeletonBoard() {
  const group = (label, n) => `<div class="group"><h3>${label}</h3>${'<div class="sk-card"><div class="sk sk-title"></div><div class="sk sk-line" style="width:80%"></div><div class="sk sk-line" style="width:60%"></div></div>'.repeat(n)}</div>`;
  app.innerHTML = `
  <nav class="tabs"><button class="active">Tableau des dossiers</button></nav>
  <div class="sk sk-line" style="height:38px"></div>
  ${group('Dossiers bloqués', 2)}
  ${group('RDV pris', 2)}${group('RDV confirmé', 2)}${group('Accueilli', 1)}`;
}
function skeletonDossier() {
  app.innerHTML = `
  <nav class="tabs"><button>← Retour au tableau</button></nav>
  <div class="card"><div class="sk sk-title"></div><div class="sk sk-line" style="width:70%"></div><div class="sk sk-line" style="width:50%"></div><div class="sk sk-line" style="width:65%"></div></div>
  <div class="card"><div class="sk sk-title" style="width:35%"></div>${'<div class="sk sk-line" style="width:90%"></div>'.repeat(4)}<div class="sk sk-btn"></div></div>
  <div class="card"><div class="sk sk-title" style="width:40%"></div><div class="sk sk-line" style="width:85%"></div><div class="sk sk-line" style="width:75%"></div></div>`;
}
function skeletonList() {
  app.innerHTML = `<nav class="tabs"><button>← Retour au tableau</button></nav>
  <div class="card"><div class="sk sk-title"></div>${'<div class="sk sk-line" style="width:92%"></div>'.repeat(5)}</div>`;
}

function renderWho() {
  if (!me) { who.innerHTML = ''; return; }
  who.innerHTML = `<span>${esc(me.name)} · ${me.roles.map(roleLabel).join(', ')}</span>
    <button id="btn-notif">Notifications${notifUnread ? ` (${notifUnread})` : ''}</button>
    <button id="btn-logout">Se déconnecter</button>`;
  $('#btn-logout').onclick = async () => { await api('/api/auth/logout', { method: 'POST' }); me = null; location.hash = ''; render(); };
  $('#btn-notif').onclick = () => { location.hash = '#/notifications'; };
}

async function loadMe() {
  try {
    const d = await api('/api/auth/me');
    me = d.user;
    const m = await api('/api/meta');
    meta = m;
    try {
      const n = await api('/api/notifications');
      notifUnread = n.unread;
    } catch (e) {
      // En maintenance, les notifications répondent 503 pour un non-admin :
      // on laisse passer l'erreur pour afficher la page de maintenance.
      if (e && e.maintenance) throw e;
      notifUnread = 0;
    }
  } catch (e) {
    if (e && e.maintenance) throw e;
    me = null;
  }
}

// ---------- Maintenance / page introuvable ----------
// Bandeau affiché aux Administrateurs quand la maintenance est active.
function maintenanceBanner() {
  return (meta && meta.maintenance)
    ? '<div class="alert">Maintenance active — seuls les Administrateurs voient l’application.</div>'
    : '';
}

// Page « Application en maintenance » pour les non-admins : aucune action
// sur les dossiers n'est possible depuis cette page.
function viewMaintenance() {
  who.innerHTML = '';
  app.innerHTML = `
  <div class="login-wrap"><div class="card">
    <h3>Application en maintenance</h3>
    <p>L'application est en maintenance, revenez plus tard.</p>
    <button class="btn" id="btn-maint-logout">Se déconnecter</button>
  </div></div>`;
  $('#btn-maint-logout').onclick = async () => {
    try { await api('/api/auth/logout', { method: 'POST' }); } catch (e) { /* déjà déconnecté */ }
    me = null;
    meta = null;
    location.hash = '';
    render();
  };
}

// Page « Page introuvable » : hash inconnu ou dossier qui n'existe pas.
function viewNotFound() {
  app.innerHTML = `
  <div class="login-wrap"><div class="card">
    <h3>Page introuvable</h3>
    <p>Cette page n'existe pas.</p>
    <button class="btn" id="btn-back-board">Retour au tableau</button>
  </div></div>`;
  $('#btn-back-board').onclick = () => { location.hash = '#/board'; };
}

// ---------- Connexion ----------
function viewLogin(msg) {
  who.innerHTML = '';
  app.innerHTML = `
  <div class="login-wrap">
    <div class="card">
      <h3>Connexion — équipe Labcare</h3>
      <span class="badge">Données fictives — version de test, aucun vrai patient</span>
      ${msg ? `<div class="alert">${esc(msg)}</div>` : ''}
      <form id="login-form">
        <label>E-mail</label>
        <input type="email" name="email" required autocomplete="username" placeholder="prenom.nom@labcare-test.ci">
        <label>Mot de passe</label>
        <input type="password" name="password" required autocomplete="current-password" placeholder="10 caractères minimum">
        <button class="btn" type="submit">Se connecter</button>
      </form>
      <p><a href="#/forgot">Mot de passe oublié ?</a></p>
      <p class="muted">Après 5 échecs consécutifs, le compte est verrouillé 15 minutes. Un Administrateur peut le déverrouiller avant.</p>
    </div>
    <div class="card" id="test-accounts" style="display:none">
      <h3>Comptes de test (données fictives)</h3>
      <p class="muted">Cliquez sur « Remplir » pour tester un rôle. La double authentification est obligatoire pour l'Administrateur et le Médecin : dans cette version de test, le code s'affiche dans l'application pour simuler l'envoi.</p>
      <table><thead><tr><th>Personne (fictive)</th><th>Rôle</th><th></th></tr></thead><tbody id="test-accounts-body"></tbody></table>
    </div>
  </div>`;
  // Comptes de test : demandés au serveur, qui ne les expose qu'en
  // développement. En production, la carte reste cachée.
  fetch('/api/test-accounts', { credentials: 'include' })
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      if (!d || !Array.isArray(d.accounts) || !d.accounts.length) return;
      testAccounts = d.accounts;
      const card = $('#test-accounts');
      if (!card) return;
      card.style.display = '';
      $('#test-accounts-body').innerHTML = testAccounts.map((a, i) => `<tr><td>${esc(a.name)}<br><span class="muted">${esc(a.email)}</span></td><td>${esc(a.roles)}</td><td><button class="btn small ghost" data-fill="${i}">Remplir</button></td></tr>`).join('');
      document.querySelectorAll('[data-fill]').forEach((b) => {
        b.onclick = () => {
          const a = testAccounts[Number(b.dataset.fill)];
          document.querySelector('input[name=email]').value = a.email;
          document.querySelector('input[name=password]').value = a.pass;
        };
      });
    })
    .catch(() => { /* pas de comptes de test : la carte reste cachée */ });
  $('#login-form').onsubmit = async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type=submit]');
    btn.disabled = true;
    btn.textContent = 'Connexion…';
    const fd = new FormData(e.target);
    try {
      const d = await api('/api/auth/login', { method: 'POST', body: { email: fd.get('email'), password: fd.get('password') } });
      if (d.needs2fa) return view2fa(d.email, d.demoCode);
      location.hash = '#/board';
      await loadMe();
      render();
    } catch (err) { viewLogin(err.message); }
  };
}

function view2fa(email, demoCode) {
  app.innerHTML = `
  <div class="login-wrap"><div class="card">
    <h3>Double authentification</h3>
    <p>Un code à usage unique est demandé pour ce compte (Administrateur ou Médecin).</p>
    ${demoCode
      ? `<div class="demo"><b>Version de test — simulation d'envoi :</b> en production, ce code partirait par application d'authentification ou par SMS. Ici, il s'affiche : <b style="font-size:20px">${esc(demoCode)}</b></div>`
      : `<p>Le code à 6 chiffres vous a été envoyé par application d'authentification ou par SMS. Il est valable 10 minutes.</p>`}
    <form id="form-2fa">
      <label>Code à 6 chiffres</label>
      <input name="code" inputmode="numeric" maxlength="6" required placeholder="123456">
      <button class="btn" type="submit">Valider le code</button>
    </form>
    <p><a href="#/">Retour à la connexion</a></p>
    <div id="err2fa"></div>
  </div></div>`;
  $('#form-2fa').onsubmit = async (e) => {
    e.preventDefault();
    try {
      await api('/api/auth/verify-2fa', { method: 'POST', body: { email, code: new FormData(e.target).get('code') } });
      location.hash = '#/board';
      await loadMe();
      render();
    } catch (err) { $('#err2fa').innerHTML = `<div class="alert">${esc(err.message)}</div>`; }
  };
}

// ---------- Tableau des dossiers ----------
async function viewBoard() {
  skeletonBoard();
  const params = new URLSearchParams();
  if (boardQuery) params.set('q', boardQuery);
  params.set('page', String(boardPage));
  params.set('limit', String(BOARD_LIMIT));
  let data;
  try {
    data = await api('/api/dossiers?' + params.toString());
  } catch (err) {
    if (err.maintenance) return; // la page de maintenance est déjà affichée par api()
    throw err;
  }
  const dossiers = data.dossiers || [];
  const total = (data.total != null) ? data.total : dossiers.length;
  const totalPages = (data.totalPages != null) ? data.totalPages : 1;
  const page = (data.page != null) ? data.page : boardPage;
  boardPage = page;
  // La recherche ou la page demandée ne donne plus rien : on repart à la page 1.
  if (page > totalPages && totalPages > 0) { boardPage = 1; return viewBoard(); }
  const blocked = dossiers.filter((d) => d.blocked);
  const closed = dossiers.filter((d) => d.status === 'closed');
  const open = dossiers.filter((d) => d.status === 'open' && !d.blocked);
  const myRoles = me.roles;
  const card = (d) => {
    const mine = meta.steps[d.step - 1] && myRoles.includes(meta.steps[d.step - 1].role);
    return `<div class="card dossier ${mine ? 'mine' : ''}" data-id="${d.id}">
      <b>${esc(d.code)}</b>
      ${d.blocked ? `<span class="pill blocked">Bloqué — ${esc(excLabel(d.exception))}</span>` : `<span class="pill">${esc(stepLabel(d.step))}</span>`}
      ${d.status === 'closed' ? '<span class="pill grey">Clôturé</span>' : ''}
      <br>${d.type === 'entreprise' ? 'Entreprise : ' + esc(d.company_name || '') : 'Particulier : ' + esc(d.client_name || '')}
      <br><span class="muted">RDV ${esc(fmtDate(d.rdv_date))}${d.rdv_time ? ' · ' + esc(d.rdv_time) : ''} · Intervenant : ${esc(d.assigned_name || '—')}</span>
      ${mine && d.status === 'open' ? '<br><span class="pill">À vous</span>' : ''}
    </div>`;
  };
  app.innerHTML = `
  <nav class="tabs">
    <button class="active">Tableau des dossiers</button>
    ${me.roles.includes('admin') ? '<button data-nav="#/users">Utilisateurs (Admin)</button>' : ''}
    <button data-nav="#/profile">Mon profil</button>
  </nav>
  ${maintenanceBanner()}
  <p class="muted">${total === 1 ? '1 dossier au total' : total + ' dossiers au total'} — page ${page} sur ${totalPages}</p>
  <div class="row">
    <div><input id="board-search" type="search" placeholder="Rechercher (numéro, nom, entreprise)…" value="${esc(boardQuery)}"></div>
    <div style="flex:0 0 auto">${me.roles.includes('secretariat') ? '<button class="btn" id="btn-new">+ Nouveau dossier</button>' : ''}</div>
  </div>
  <div id="new-form"></div>
  ${boardQuery && total === 0 ? '<p class="muted">Aucun dossier trouvé</p>' : `
  ${blocked.length ? `<div class="group"><h3>⚠️ Dossiers bloqués — visibles tout de suite (${blocked.length})</h3>${blocked.map(card).join('')}</div>` : ''}
  ${meta.steps.map((s) => {
    const list = open.filter((d) => d.step === s.n);
    return `<div class="group"><h3>${esc(s.label)} (${list.length}) — ${esc(roleLabel(s.role))}</h3>${list.length ? list.map(card).join('') : '<p class="muted">Aucun dossier à cette étape</p>'}</div>`;
  }).join('')}
  ${closed.length ? `<div class="group"><h3>Clôturés (${closed.length})</h3>${closed.map(card).join('')}</div>` : ''}`}
  ${total > 0 && totalPages > 1 ? `<div class="row"><div>
    <button class="btn small ghost" id="pg-prev" ${page <= 1 ? 'disabled' : ''}>Précédent</button>
    ${Array.from({ length: totalPages }, (_, i) => i + 1).map((n) => `<button class="btn small ${n === page ? '' : 'ghost'}" data-page="${n}">${n}</button>`).join('')}
    <button class="btn small ghost" id="pg-next" ${page >= totalPages ? 'disabled' : ''}>Suivant</button>
  </div></div>` : ''}`;
  document.querySelectorAll('[data-nav]').forEach((b) => { b.onclick = () => { location.hash = b.dataset.nav; }; });
  document.querySelectorAll('.dossier').forEach((el) => { el.onclick = () => { location.hash = '#/dossier/' + el.dataset.id; }; });
  $('#board-search').onchange = (e) => { boardQuery = e.target.value.trim(); boardPage = 1; viewBoard(); };
  const pgPrev = $('#pg-prev');
  if (pgPrev) pgPrev.onclick = () => { if (boardPage > 1) { boardPage -= 1; viewBoard(); } };
  const pgNext = $('#pg-next');
  if (pgNext) pgNext.onclick = () => { if (boardPage < totalPages) { boardPage += 1; viewBoard(); } };
  document.querySelectorAll('[data-page]').forEach((b) => { b.onclick = () => { boardPage = Number(b.dataset.page); viewBoard(); }; });
  const btnNew = $('#btn-new');
  if (btnNew) btnNew.onclick = () => showNewDossierForm();
}

function showNewDossierForm() {
  $('#new-form').innerHTML = `
  <div class="card"><h3>Nouveau dossier — RDV pris (Secrétariat)</h3>
  <form id="form-new">
    <label>Type de client</label>
    <select name="type"><option value="particulier">Particulier</option><option value="entreprise">Entreprise</option></select>
    <div class="row">
      <div><label>Date du RDV</label><input type="date" name="rdv_date" required></div>
      <div><label>Heure</label><input type="time" name="rdv_time"></div>
    </div>
    <div id="fields-part">
      <label>Nom du client</label><input name="client_name">
      <label>Téléphone / contact</label><input name="phone">
      <label>Adresse du domicile</label><input name="address">
    </div>
    <div id="fields-ent" style="display:none">
      <label>Nom de l'entreprise</label><input name="company_name">
      <label>Contact RH (e-mail ou téléphone)</label><input name="hr_contact">
      <label>Formule Entreprise</label><input name="formula" placeholder="Essentiel, Standard, Premium…">
      <label>Effectif prévu</label><input type="number" name="effectif" min="1">
    </div>
    <button class="btn" type="submit">Créer le dossier</button>
  </form><div id="new-err"></div></div>`;
  const sel = document.querySelector('select[name=type]');
  sel.onchange = () => {
    const ent = sel.value === 'entreprise';
    $('#fields-part').style.display = ent ? 'none' : '';
    $('#fields-ent').style.display = ent ? '' : 'none';
  };
  $('#form-new').onsubmit = async (e) => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(e.target).entries());
    try {
      const d = await api('/api/dossiers', { method: 'POST', body: fd });
      location.hash = '#/dossier/' + d.dossier.id;
      render();
    } catch (err) { $('#new-err').innerHTML = `<div class="alert">${esc(err.message)}</div>`; }
  };
}

// ---------- Fiche dossier ----------
async function viewDossier(id) {
  skeletonDossier();
  let payload;
  try {
    payload = await api('/api/dossiers/' + id);
  } catch (err) {
    if (err.maintenance) return; // la page de maintenance est déjà affichée par api()
    if (err.status === 404) return viewNotFound();
    throw err;
  }
  const { dossier: d, history, permissions: p } = payload;
  const stepsHtml = meta.steps.map((s) => {
    const done = d.status === 'closed' ? true : s.n < d.step;
    const now = d.status === 'open' && s.n === d.step;
    return `<div class="step"><span class="dot ${done ? 'done' : now ? 'now' : 'todo'}">${done ? '✓' : s.n}</span><div><b>${esc(s.label)}</b> — ${esc(roleLabel(s.role))}${now ? ' <b>(étape en cours)</b>' : ''}</div></div>`;
  }).join('');
  app.innerHTML = `
  <nav class="tabs"><button data-nav="#/board">← Retour au tableau</button>
  ${me.roles.includes('admin') ? '<button data-nav="#/users">Utilisateurs (Admin)</button>' : ''}
  <button data-nav="#/profile">Mon profil</button></nav>
  ${maintenanceBanner()}
  <div id="msg"></div>
  <div class="card">
    <h3>Fiche dossier — ${esc(d.code)}</h3>
    ${d.blocked ? `<div class="alert"><b>Dossier bloqué — ${esc(excLabel(d.exception))}</b><br>Il reste visible jusqu'à sa reprise ou sa clôture.</div>` : ''}
    ${d.status === 'closed' ? `<div class="alert"><b>Dossier clôturé</b>${d.close_reason ? ' — ' + esc(d.close_reason) : ''}</div>` : ''}
    <p><b>Étape en cours :</b> ${esc(stepLabel(d.step))} <span class="pill">étape ${d.step} / 8</span><br>
    <b>Date du RDV :</b> ${esc(fmtDate(d.rdv_date))}${d.rdv_time ? ' · ' + esc(d.rdv_time) : ''}<br>
    <b>Intervenant assigné :</b> ${esc(d.assigned_name || '—')}<br>
    <b>Type de client :</b> ${d.type === 'entreprise' ? 'Entreprise' : 'Particulier'}</p>
    <h4>${d.type === 'entreprise' ? 'Client entreprise' : 'Client particulier'}</h4>
    ${d.type === 'entreprise'
      ? `<p>Nom de l'entreprise : <b>${esc(d.company_name || '')}</b><br>Contact RH : ${esc(d.hr_contact || '')}<br>Formule Entreprise : ${esc(d.formula || '')}<br>Effectif prévu : ${esc(d.effectif || '')} personne(s)</p>`
      : `<p>Nom : <b>${esc(d.client_name || '')}</b><br>Numéro / contact : ${esc(d.phone || '')}<br>Adresse du domicile : ${esc(d.address || '')}</p>`}
    <p class="muted">Aucun contenu médical, aucun résultat d'examen affiché dans la fiche. L'application suit le parcours, pas le dossier médical.</p>
  </div>
  <div class="card">
    <h3>Parcours — 8 étapes</h3>
    ${stepsHtml}
    ${p.canAdvance ? `<button class="btn" id="btn-advance">Passer à « ${d.step >= 8 ? 'Clôturer (remis au patient)' : esc(stepLabel(d.step + 1))} »</button>
    <p class="muted">En confirmant : notification envoyée au rôle suivant et historique mis à jour — qui a changé le statut, et quand.</p>` : ''}
    ${p.canSignalException ? `<button class="btn ghost" id="btn-exc">Signaler une exception</button>` : ''}
    ${p.canResume ? `<button class="btn" id="btn-resume">Reprendre le parcours</button>` : ''}
    ${p.canClose ? `<button class="btn danger" id="btn-close">Clôturer le dossier</button>` : ''}
    <div id="action-form"></div>
    ${p.canEdit ? `<button class="btn ghost" id="btn-edit">Modifier les informations / réassigner</button><div id="edit-form"></div>` : ''}
  </div>
  <div class="card">
    <h3>Historique complet — qui et quand</h3>
    ${history.length ? history.map((h) => `<div class="step"><span class="dot done">✓</span><div>${esc(fmtDateTime(h.created_at))} — <b>${esc(h.user_name || '—')}</b> : ${esc(historyText(h))}</div></div>`).join('') : '<p class="muted">Aucun historique.</p>'}
    <p class="muted">L'historique ne peut être modifié par aucun utilisateur.</p>
  </div>`;
  document.querySelectorAll('[data-nav]').forEach((b) => { b.onclick = () => { location.hash = b.dataset.nav; }; });
  const msg = (html) => { const el = $('#msg'); if (el) el.innerHTML = html; };
  const reload = () => render();
  const adv = $('#btn-advance');
  if (adv) adv.onclick = async () => {
    const label = adv.textContent;
    adv.disabled = true;
    adv.textContent = 'Chargement…';
    try { await api(`/api/dossiers/${id}/advance`, { method: 'POST', body: {} }); reload(); }
    catch (err) { adv.disabled = false; adv.textContent = label; msg(`<div class="alert">${esc(err.message)}</div>`); }
  };
  const exc = $('#btn-exc');
  if (exc) exc.onclick = () => {
    $('#action-form').innerHTML = `<div class="card"><h4>Signaler une exception</h4>
      <form id="form-exc">
        <label>Exception</label>
        <select name="type">${Object.entries(meta.exceptions).map(([k, v]) => `<option value="${k}">${esc(v.label)}</option>`).join('')}</select>
        <label>Précision (facultatif)</label>
        <input name="note" placeholder="Ex. : le patient n'était pas là à 9 h">
        <button class="btn danger" type="submit">Signaler</button>
      </form><div id="exc-err"></div></div>`;
    $('#form-exc').onsubmit = async (e) => {
      e.preventDefault();
      const fd = Object.fromEntries(new FormData(e.target).entries());
      try { await api(`/api/dossiers/${id}/exception`, { method: 'POST', body: fd }); reload(); }
      catch (err) { $('#exc-err').innerHTML = `<div class="alert">${esc(err.message)}</div>`; }
    };
  };
  const res = $('#btn-resume');
  if (res) res.onclick = async () => {
    try { await api(`/api/dossiers/${id}/resume`, { method: 'POST', body: {} }); reload(); }
    catch (err) { msg(`<div class="alert">${esc(err.message)}</div>`); }
  };
  const clo = $('#btn-close');
  if (clo) clo.onclick = async () => {
    if (!confirm('Clôturer ce dossier bloqué ?')) return;
    try { await api(`/api/dossiers/${id}/close`, { method: 'POST', body: { reason: 'Clôturé depuis un dossier bloqué.' } }); reload(); }
    catch (err) { msg(`<div class="alert">${esc(err.message)}</div>`); }
  };
  const edt = $('#btn-edit');
  if (edt) edt.onclick = async () => {
    const { users } = await api('/api/users').catch(() => ({ users: [] }));
    const intervenants = users.filter((u) => u.status === 'active');
    $('#edit-form').innerHTML = `<div class="card"><h4>Modifier le dossier</h4>
      <form id="form-edit">
        <div class="row">
          <div><label>Date du RDV</label><input type="date" name="rdv_date" value="${esc(d.rdv_date)}"></div>
          <div><label>Heure</label><input type="time" name="rdv_time" value="${esc(d.rdv_time || '')}"></div>
        </div>
        ${d.type === 'particulier' ? `
          <label>Nom du client</label><input name="client_name" value="${esc(d.client_name || '')}">
          <label>Téléphone / contact</label><input name="phone" value="${esc(d.phone || '')}">
          <label>Adresse du domicile</label><input name="address" value="${esc(d.address || '')}">` : `
          <label>Nom de l'entreprise</label><input name="company_name" value="${esc(d.company_name || '')}">
          <label>Contact RH</label><input name="hr_contact" value="${esc(d.hr_contact || '')}">
          <label>Formule Entreprise</label><input name="formula" value="${esc(d.formula || '')}">
          <label>Effectif prévu</label><input type="number" name="effectif" value="${esc(d.effectif || '')}">`}
        <label>Intervenant assigné</label>
        <select name="assigned_to">${intervenants.map((u) => `<option value="${u.id}" ${u.id === d.assigned_to ? 'selected' : ''}>${esc(u.name)} (${u.roles.map(roleLabel).join(', ')})</option>`).join('')}</select>
        <button class="btn" type="submit">Enregistrer</button>
      </form><div id="edit-err"></div></div>`;
    $('#form-edit').onsubmit = async (e) => {
      e.preventDefault();
      const fd = Object.fromEntries(new FormData(e.target).entries());
      fd.assigned_to = Number(fd.assigned_to);
      if (fd.effectif !== undefined && fd.effectif !== '') fd.effectif = Number(fd.effectif);
      try { await api(`/api/dossiers/${id}`, { method: 'PATCH', body: fd }); reload(); }
      catch (err) { $('#edit-err').innerHTML = `<div class="alert">${esc(err.message)}</div>`; }
    };
  };
}

function historyText(h) {
  if (h.action === 'create') return 'a créé le dossier (RDV pris).';
  if (h.action === 'advance') return `a passé le dossier à « ${stepLabel(h.to_step)} ».`;
  if (h.action === 'exception') return `a signalé une exception : ${excLabel(h.exception)}${h.note ? ' — ' + h.note : ''}.`;
  if (h.action === 'resume') return `a repris le parcours à « ${stepLabel(h.to_step)} ».`;
  if (h.action === 'close') return `a clôturé le dossier${h.note ? ' : ' + h.note : '.'}`;
  if (h.action === 'update') return h.note ? `a modifié les informations du dossier : ${h.note}.` : 'a modifié les informations du dossier.';
  return h.action;
}

// ---------- Utilisateurs (Admin) ----------
async function viewUsers() {
  skeletonList();
  let users;
  let logs;
  try {
    ({ users } = await api('/api/users'));
    ({ logs } = await api('/api/admin/auth-logs'));
  } catch (err) {
    if (err.maintenance) return; // la page de maintenance est déjà affichée par api()
    throw err;
  }
  app.innerHTML = `
  <nav class="tabs">
    <button data-nav="#/board">Tableau des dossiers</button>
    <button class="active">Utilisateurs (Admin)</button>
    <button data-nav="#/profile">Mon profil</button>
  </nav>
  ${maintenanceBanner()}
  <div id="msg"></div>
  <div class="card">
    <h3>Comptes de l'équipe (${users.length})</h3>
    <p class="muted">Seul l'Administrateur crée les comptes, par invitation. Un compte = une personne, pas de compte partagé. Un compte n'est jamais supprimé : il est désactivé. Il doit y avoir un seul Administrateur.</p>
    <table><thead><tr><th>Nom</th><th>E-mail / téléphone</th><th>Rôle(s)</th><th>Statut</th><th>Dernière connexion</th><th></th></tr></thead><tbody>
    ${users.map((u) => `<tr>
      <td><b>${esc(u.name)}</b>${u.locked ? ' <span class="pill warn">Verrouillé</span>' : ''}${!u.hasPassword ? ' <span class="pill">Invitation en attente</span>' : ''}</td>
      <td>${esc(u.email)}<br><span class="muted">${esc(u.phone || '')}</span></td>
      <td>${u.roles.map((r) => `<span class="pill">${esc(roleLabel(r))}</span>`).join('')}</td>
      <td>${u.status === 'active' ? 'Actif' : 'Désactivé'}</td>
      <td>${fmtDateTime(u.last_login)}</td>
      <td>
        <button class="btn small ghost" data-edit="${u.id}">Modifier</button>
        ${u.locked ? `<button class="btn small" data-unlock="${u.id}">Déverrouiller</button>` : ''}
        ${!u.hasPassword ? `<button class="btn small" data-resend="${u.id}">Renvoyer l'invitation</button>` : `<button class="btn small" data-reset-pw="${u.id}">Réinitialiser le mot de passe</button>`}
        ${u.status === 'active' ? `<button class="btn small danger" data-disable="${u.id}">Désactiver</button>` : `<button class="btn small" data-enable="${u.id}">Réactiver</button>`}
      </td></tr>`).join('')}
    </tbody></table>
    <div id="user-form"></div>
  </div>
  <div class="card">
    <h3>Maintenance</h3>
    <p>État actuel : <b>${meta.maintenance ? 'Maintenance active' : 'Application en ligne'}</b></p>
    <p class="muted">La maintenance coupe l'accès aux autres utilisateurs, sans supprimer de données. Seuls les Administrateurs voient encore l'application pendant la maintenance.</p>
    <button class="btn ${meta.maintenance ? 'ghost' : 'danger'}" id="btn-maintenance">${meta.maintenance ? 'Sortir de maintenance' : 'Mettre en maintenance'}</button>
  </div>
  <div class="card">
    <h3>Créer un compte (invitation)</h3>
    <form id="form-user">
      <div class="row">
        <div><label>Nom complet</label><input name="name" required></div>
        <div><label>Adresse e-mail</label><input type="email" name="email" required></div>
        <div><label>Téléphone</label><input name="phone"></div>
      </div>
      <label>Rôle(s) — une personne peut en cumuler plusieurs</label>
      <div>${Object.entries(meta.roles).map(([k, v]) => `<label style="display:inline-block;margin-right:14px"><input type="checkbox" name="roles" value="${k}" style="width:auto"> ${esc(v)}</label>`).join('')}</div>
      <button class="btn" type="submit">Créer et envoyer l'invitation</button>
    </form>
    <div id="user-err"></div><div id="user-ok"></div>
    <p class="muted">À la création, la personne reçoit un lien d'activation valable 48 heures pour choisir son mot de passe. Dans cette version de test, le lien s'affiche ici (simulation d'envoi par e-mail).</p>
  </div>
  <div class="card">
    <h3>Journal des connexions</h3>
    ${logs.map((l) => `<div class="notif"><b>${esc(fmtDateTime(l.created_at))}</b> — ${esc(l.email || '')} — ${esc(l.event)} — ${l.success ? 'réussi' : 'échoué'}${l.detail ? ' — ' + esc(l.detail) : ''}</div>`).join('') || '<p class="muted">Aucun événement.</p>'}
  </div>`;
  document.querySelectorAll('[data-nav]').forEach((b) => { b.onclick = () => { location.hash = b.dataset.nav; }; });
  const msg = (html) => { const el = $('#msg'); if (el) el.innerHTML = html; };
  const btnMaint = $('#btn-maintenance');
  if (btnMaint) btnMaint.onclick = async () => {
    const active = !meta.maintenance;
    if (!confirm(active
      ? "Mettre l'application en maintenance ? Les autres utilisateurs ne pourront plus y accéder, sans suppression de données."
      : "Sortir l'application de maintenance ? Les utilisateurs pourront de nouveau y accéder.")) return;
    try {
      const d = await api('/api/admin/maintenance', { method: 'POST', body: { active } });
      meta.maintenance = d.maintenance;
      render();
    } catch (err) { msg(`<div class="alert">${esc(err.message)}</div>`); }
  };
  $('#form-user').onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const roles = fd.getAll('roles');
    try {
      const d = await api('/api/users', { method: 'POST', body: { name: fd.get('name'), email: fd.get('email'), phone: fd.get('phone'), roles } });
      $('#user-ok').innerHTML = `<div class="ok"><b>Compte créé.</b><br>Lien d'activation (48 h, simulation d'envoi par e-mail) :<br><a href="${esc(d.activationUrl)}">${esc(d.activationUrl)}</a></div>`;
      $('#user-err').innerHTML = '';
      setTimeout(() => viewUsers(), 400);
    } catch (err) { $('#user-err').innerHTML = `<div class="alert">${esc(err.message)}</div>`; }
  };
  document.querySelectorAll('[data-unlock]').forEach((b) => { b.onclick = async () => { await api(`/api/users/${b.dataset.unlock}/unlock`, { method: 'POST', body: {} }); render(); }; });
  document.querySelectorAll('[data-resend]').forEach((b) => {
    b.onclick = async () => {
      try {
        const d = await api(`/api/users/${b.dataset.resend}/resend-invitation`, { method: 'POST', body: {} });
        msg(`<div class="ok">Nouveau lien d'invitation (48 h) : <a href="${esc(d.activationUrl)}">${esc(d.activationUrl)}</a></div>`);
      } catch (err) { msg(`<div class="alert">${esc(err.message)}</div>`); }
    };
  });
  document.querySelectorAll('[data-reset-pw]').forEach((b) => {
    b.onclick = async () => {
      if (!confirm('Déclencher une réinitialisation du mot de passe pour ce compte ? Le lien est valable 1 heure, utilisable une seule fois.')) return;
      try {
        const d = await api(`/api/users/${b.dataset.resetPw}/reset-password`, { method: 'POST', body: {} });
        msg(`<div class="ok">Lien de réinitialisation (1 h, usage unique, simulation d'envoi par e-mail) : <a href="${esc(d.resetUrl)}">${esc(d.resetUrl)}</a></div>`);
      } catch (err) { msg(`<div class="alert">${esc(err.message)}</div>`); }
    };
  });
  const setStatus = async (id, status) => {
    try { await api(`/api/users/${id}`, { method: 'PATCH', body: { status } }); render(); }
    catch (err) {
      if (err.message.includes('Réassignez')) {
        const to = prompt('Ce compte a des dossiers en cours. Entrez l’identifiant (numéro) du compte à qui les réassigner, visible dans le tableau (comptez les lignes) :');
        if (to) {
          try { await api(`/api/users/${id}`, { method: 'PATCH', body: { status, reassign_to: Number(to) } }); render(); }
          catch (e2) { msg(`<div class="alert">${esc(e2.message)}</div>`); }
        }
      } else msg(`<div class="alert">${esc(err.message)}</div>`);
    }
  };
  document.querySelectorAll('[data-disable]').forEach((b) => { b.onclick = () => { if (confirm('Désactiver ce compte ? Il ne pourra plus se connecter, mais son nom restera dans l’historique.')) setStatus(b.dataset.disable, 'disabled'); }; });
  document.querySelectorAll('[data-enable]').forEach((b) => { b.onclick = () => setStatus(b.dataset.enable, 'active'); });
  document.querySelectorAll('[data-edit]').forEach((b) => {
    b.onclick = () => {
      const u = users.find((x) => x.id === Number(b.dataset.edit));
      $('#user-form').innerHTML = `<div class="card"><h4>Modifier — ${esc(u.name)}</h4>
        <form id="form-edit-user">
          <label>Nom complet</label><input name="name" value="${esc(u.name)}" required>
          <label>Téléphone</label><input name="phone" value="${esc(u.phone || '')}">
          <label>Rôle(s)</label>
          <div>${Object.entries(meta.roles).map(([k, v]) => `<label style="display:inline-block;margin-right:14px"><input type="checkbox" name="roles" value="${k}" style="width:auto" ${u.roles.includes(k) ? 'checked' : ''}> ${esc(v)}</label>`).join('')}</div>
          <button class="btn" type="submit">Enregistrer</button>
        </form><div id="edit-user-err"></div></div>`;
      $('#form-edit-user').onsubmit = async (e) => {
        e.preventDefault();
        const fd = new FormData(e.target);
        try { await api(`/api/users/${u.id}`, { method: 'PATCH', body: { name: fd.get('name'), phone: fd.get('phone'), roles: fd.getAll('roles') } }); render(); }
        catch (err) { $('#edit-user-err').innerHTML = `<div class="alert">${esc(err.message)}</div>`; }
      };
    };
  });
}

// ---------- Notifications / profil / mot de passe oublié / activation ----------
async function viewNotifications() {
  skeletonList();
  let notifications;
  let unread;
  try {
    ({ notifications, unread } = await api('/api/notifications'));
  } catch (err) {
    if (err.maintenance) return; // la page de maintenance est déjà affichée par api()
    throw err;
  }
  notifUnread = unread;
  renderWho();
  app.innerHTML = `
  <nav class="tabs"><button data-nav="#/board">← Retour au tableau</button>
  ${me.roles.includes('admin') ? '<button data-nav="#/users">Utilisateurs (Admin)</button>' : ''}
  <button data-nav="#/profile">Mon profil</button></nav>
  ${maintenanceBanner()}
  <div class="card"><h3>Notifications (${unread} non lue(s))</h3>
  <button class="btn ghost" id="btn-readall">Tout marquer comme lu</button>
  ${notifications.length ? notifications.map((n) => `<div class="notif ${n.is_read ? '' : 'unread'}">${esc(fmtDateTime(n.created_at))} — ${esc(n.message)}</div>`).join('') : '<p class="muted">Aucune notification</p>'}
  </div>`;
  document.querySelectorAll('[data-nav]').forEach((b) => { b.onclick = () => { location.hash = b.dataset.nav; }; });
  $('#btn-readall').onclick = async () => { await api('/api/notifications/read-all', { method: 'POST', body: {} }); render(); };
}

function viewProfile() {
  app.innerHTML = `
  <nav class="tabs"><button data-nav="#/board">← Retour au tableau</button>
  ${me.roles.includes('admin') ? '<button data-nav="#/users">Utilisateurs (Admin)</button>' : ''}</nav>
  ${maintenanceBanner()}
  <div class="card"><h3>Mon profil</h3>
    <p><b>${esc(me.name)}</b><br>${esc(me.email)} · ${esc(me.phone || '')}<br>Rôle(s) : ${me.roles.map(roleLabel).join(', ')}</p>
    <h4>Changer mon mot de passe</h4>
    <form id="form-pw">
      <label>Mot de passe actuel</label><input type="password" name="currentPassword" required>
      <label>Nouveau mot de passe (10 caractères minimum, lettres et chiffres)</label><input type="password" name="newPassword" required>
      <button class="btn" type="submit">Changer le mot de passe</button>
    </form><div id="pw-msg"></div>
  </div>`;
  document.querySelectorAll('[data-nav]').forEach((b) => { b.onclick = () => { location.hash = b.dataset.nav; }; });
  $('#form-pw').onsubmit = async (e) => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(e.target).entries());
    try {
      const d = await api('/api/auth/change-password', { method: 'POST', body: fd });
      // Le changement de mot de passe révoque toutes les sessions : il
      // faut se reconnecter avec le nouveau mot de passe.
      $('#pw-msg').innerHTML = `<div class="ok">${esc(d.message)} Reconnectez-vous avec votre nouveau mot de passe.</div>`;
      setTimeout(() => { me = null; meta = null; location.hash = ''; render(); }, 2000);
    }
    catch (err) { $('#pw-msg').innerHTML = `<div class="alert">${esc(err.message)}</div>`; }
  };
}

function viewForgot() {
  app.innerHTML = `<div class="login-wrap"><div class="card"><h3>Mot de passe oublié</h3>
    <form id="form-forgot">
      <label>Votre adresse e-mail</label><input type="email" name="email" required>
      <button class="btn" type="submit">Recevoir le lien de réinitialisation</button>
    </form><div id="forgot-msg"></div>
    <p><a href="#/">Retour à la connexion</a></p></div></div>`;
  $('#form-forgot').onsubmit = async (e) => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(e.target).entries());
    const d = await api('/api/auth/forgot', { method: 'POST', body: fd });
    // La réponse ne contient jamais le lien (PRD §5.2) : elle est
    // identique que l'e-mail existe ou non. En version de test, la
    // réinitialisation passe par l'Administrateur (écran Utilisateurs).
    $('#forgot-msg').innerHTML = `<div class="ok">${esc(d.message)}</div>`;
  };
}

function viewActivate(token) {
  app.innerHTML = `<div class="login-wrap"><div class="card"><h3>Activer mon compte</h3>
    <p>Choisissez votre mot de passe (10 caractères minimum, avec des lettres et des chiffres). Le lien est valable 48 heures.</p>
    <form id="form-activate">
      <label>Nouveau mot de passe</label><input type="password" name="password" required>
      <button class="btn" type="submit">Activer mon compte</button>
    </form><div id="act-msg"></div>
    <p><a href="#/">Retour à la connexion</a></p></div></div>`;
  $('#form-activate').onsubmit = async (e) => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(e.target).entries());
    try { const d = await api('/api/auth/activate', { method: 'POST', body: { token, password: fd.get('password') } }); $('#act-msg').innerHTML = `<div class="ok">${esc(d.message)}</div>`; }
    catch (err) { $('#act-msg').innerHTML = `<div class="alert">${esc(err.message)}</div>`; }
  };
}

function viewReset(token) {
  app.innerHTML = `<div class="login-wrap"><div class="card"><h3>Réinitialiser mon mot de passe</h3>
    <p>Choisissez un nouveau mot de passe (10 caractères minimum, avec des lettres et des chiffres). Le lien est valable 1 heure et utilisable une seule fois.</p>
    <form id="form-reset">
      <label>Nouveau mot de passe</label><input type="password" name="password" required>
      <button class="btn" type="submit">Réinitialiser</button>
    </form><div id="reset-msg"></div>
    <p><a href="#/">Retour à la connexion</a></p></div></div>`;
  $('#form-reset').onsubmit = async (e) => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(e.target).entries());
    try { const d = await api('/api/auth/reset', { method: 'POST', body: { token, password: fd.get('password') } }); $('#reset-msg').innerHTML = `<div class="ok">${esc(d.message)}</div>`; }
    catch (err) { $('#reset-msg').innerHTML = `<div class="alert">${esc(err.message)}</div>`; }
  };
}

// ---------- Routeur ----------
async function render() {
  const hash = location.hash || '#/board';
  const params = new URLSearchParams(hash.split('?')[1] || '');
  if (hash.startsWith('#/activate')) return viewActivate(params.get('token') || '');
  if (hash.startsWith('#/reset')) return viewReset(params.get('token') || '');
  if (hash.startsWith('#/forgot')) return viewForgot();
  try {
    await loadMe();
  } catch (e) {
    if (e && e.maintenance) return viewMaintenance();
    me = null;
  }
  renderWho();
  if (!me) return viewLogin();
  // Maintenance active : un non-admin voit la page de maintenance, jamais l'application.
  if (meta && meta.maintenance && !me.roles.includes('admin')) return viewMaintenance();
  try {
    if (hash.startsWith('#/dossier/')) { await viewDossier(hash.split('/')[2]); return; }
    if (hash.startsWith('#/users')) {
      if (!me.roles.includes('admin')) { await viewBoard(); return; }
      await viewUsers();
      return;
    }
    if (hash.startsWith('#/profile')) return viewProfile();
    if (hash.startsWith('#/notifications')) { await viewNotifications(); return; }
    if (hash === '#/board' || hash === '#/' || hash === '') { await viewBoard(); return; }
    // Toute autre adresse : page introuvable, plus jamais un retour silencieux au tableau.
    viewNotFound();
  } catch (err) {
    if (err && err.maintenance) return viewMaintenance();
    throw err;
  }
}

window.addEventListener('hashchange', render);
render();
