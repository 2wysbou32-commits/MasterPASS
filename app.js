function customConfirm(message) {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,30,35,0.6);backdrop-filter:blur(6px);z-index:9999;display:flex;align-items:center;justify-content:center';
    overlay.innerHTML = `
      <div style="background:white;border-radius:22px;padding:32px;width:420px;max-width:95vw;box-shadow:0 24px 80px rgba(0,0,0,0.22)">
        <div style="font-family:'Plus Jakarta Sans',sans-serif;font-size:18px;font-weight:700;color:#0D2B2E;margin-bottom:24px">${message}</div>
        <div style="display:flex;gap:10px">
          <button id="cc-cancel" style="flex:1;height:44px;border:1.5px solid #e0e0e0;background:white;border-radius:11px;font-size:14px;font-weight:500;color:#3A6A70;cursor:pointer">Annuler</button>
          <button id="cc-confirm" style="flex:1;height:44px;background:linear-gradient(135deg,#00C4D4,#009AAA);border:none;border-radius:11px;font-size:14px;font-weight:700;color:white;cursor:pointer">Confirmer</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    overlay.querySelector('#cc-confirm').onclick = () => { document.body.removeChild(overlay); resolve(true); };
    overlay.querySelector('#cc-cancel').onclick = () => { document.body.removeChild(overlay); resolve(false); };
  });
}

function customPrompt(message, defaultValue = '') {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,30,35,0.6);backdrop-filter:blur(6px);z-index:9999;display:flex;align-items:center;justify-content:center';
    overlay.innerHTML = `
      <div style="background:white;border-radius:22px;padding:32px;width:420px;max-width:95vw;box-shadow:0 24px 80px rgba(0,0,0,0.22)">
        <div style="font-family:'Plus Jakarta Sans',sans-serif;font-size:18px;font-weight:700;color:#0D2B2E;margin-bottom:16px">${message}</div>
        <input id="cp-input" type="text" value="${defaultValue}" style="width:100%;height:46px;border:1px solid rgba(0,196,212,0.3);border-radius:12px;padding:0 16px;font-size:15px;font-family:'Inter',sans-serif;color:#0D2B2E;outline:none;box-sizing:border-box;margin-bottom:20px">
        <div style="display:flex;gap:10px">
          <button id="cp-cancel" style="flex:1;height:44px;border:1.5px solid #e0e0e0;background:white;border-radius:11px;font-size:14px;font-weight:500;color:#3A6A70;cursor:pointer">Annuler</button>
          <button id="cp-confirm" style="flex:1;height:44px;background:linear-gradient(135deg,#00C4D4,#009AAA);border:none;border-radius:11px;font-size:14px;font-weight:700;color:white;cursor:pointer">Confirmer</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    const input = overlay.querySelector('#cp-input');
    input.focus();
    input.select();
    overlay.querySelector('#cp-confirm').onclick = () => { document.body.removeChild(overlay); resolve(input.value || null); };
    overlay.querySelector('#cp-cancel').onclick = () => { document.body.removeChild(overlay); resolve(null); };
    input.onkeydown = e => { if (e.key === 'Enter') overlay.querySelector('#cp-confirm').click(); if (e.key === 'Escape') overlay.querySelector('#cp-cancel').click(); };
  });
}
const $=id=>document.getElementById(id);
let currentUser=null,currentFolder=null;
  
// ── MÉMORISATION DE POSITION ─────────────────────────────────────────────────
function saveNavState(key, value) { try { sessionStorage.setItem(key, JSON.stringify(value)); } catch(e) {} }
function loadNavState(key) { try { const v = sessionStorage.getItem(key); return v ? JSON.parse(v) : null; } catch(e) { return null; } }
function clearNavState(key) { try { sessionStorage.removeItem(key); } catch(e) {} }
function formatSize(b){if(b<1024)return b+' o';if(b<1048576)return (b/1024).toFixed(0)+' Ko';if(b<1073741824)return (b/1048576).toFixed(1)+' Mo';return (b/1073741824).toFixed(2)+' Go';}

function showExpiredScreen() {
  document.body.innerHTML = `
    <div style="position:fixed;inset:0;background:linear-gradient(135deg,#0D2B2E,#003340);display:flex;align-items:center;justify-content:center;z-index:99999">
      <div style="background:rgba(255,255,255,0.05);border:1px solid rgba(0,196,212,0.2);border-radius:24px;padding:48px 40px;max-width:440px;width:90%;text-align:center;backdrop-filter:blur(20px)">
        <div style="font-size:56px;margin-bottom:20px">🔒</div>
        <div style="font-family:'Plus Jakarta Sans',sans-serif;font-size:22px;font-weight:800;color:white;margin-bottom:12px">Accès suspendu</div>
        <p style="color:rgba(255,255,255,0.6);font-size:14px;line-height:1.7;margin-bottom:28px">Ton accès à MasterPASS a été suspendu. Si tu penses que c'est une erreur ou pour renouveler ton accès, contacte l'équipe MasterPASS.</p>
        <a href="mailto:masterpass.lille@gmail.com" style="display:inline-block;background:linear-gradient(135deg,#00C4D4,#009AAA);color:white;text-decoration:none;padding:14px 28px;border-radius:12px;font-size:14px;font-weight:700">Contacter l'équipe</a>
      </div>
    </div>`;
}

async function api(method,path,body){
  const opts={method,headers:{}};
  if(body instanceof FormData){opts.body=body;}
  else if(body){opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body);}
  const r=await fetch('/api'+path,opts);
  const data=await r.json().catch(()=>({error:'Erreur réseau'}));
  // Déconnexion si session remplacée (double connexion détectée)
  if(r.status===401 && currentUser){
    currentUser=null;
    $('app').style.display='none';
    $('auth-page').style.display='flex';
    $('login-input').value='';$('password-input').value='';
    // Afficher une alerte modale percutante
    let modal = document.getElementById('expired-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'expired-modal';
      modal.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,0.65);display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(4px)';
      modal.innerHTML = `<div style="background:white;border-radius:20px;padding:36px;max-width:400px;width:100%;text-align:center;box-shadow:0 24px 60px rgba(0,0,0,0.3)">
        <div style="font-size:52px;margin-bottom:12px">🔐</div>
        <div style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:800;color:#C62828;margin-bottom:10px">Session expirée</div>
        <p style="color:#546E7A;font-size:13.5px;line-height:1.65;margin-bottom:24px">
          Une connexion depuis un autre appareil a été détectée sur ton compte.<br><br>
          <strong style="color:#C62828">Le partage de compte est strictement interdit</strong> selon les conditions d'utilisation de MasterPASS. En cas de récidive, l'accès à la plateforme sera définitivement supprimé.
        </p>
        <button onclick="document.getElementById('expired-modal').remove()" style="width:100%;padding:13px;background:linear-gradient(135deg,#0097A7,#006064);color:white;border:none;border-radius:12px;font-size:14px;font-weight:700;cursor:pointer;font-family:'Inter',sans-serif">
          Compris — me reconnecter
        </button>
      </div>`;
      document.body.appendChild(modal);
    }
    modal.style.display = 'flex';
    throw new Error('Session expirée');
  }
  if(r.status===403 && data.error==='ACCOUNT_EXPIRED'){
    showExpiredScreen();
    throw new Error('ACCOUNT_EXPIRED');
  }
  if(!r.ok){throw new Error(data.error||'Erreur');}
  return data;
}

let toastTimer;
function toast(msg,type='success'){
  const el=$('toast');
  $('toast-text').textContent=msg;
  $('toast-icon').className='toast-icon '+type;
  $('toast-icon').innerHTML=type==='success'
    ?'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>'
    :'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>';
  el.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.classList.remove('show'),3200);
}

function updateRegLogin() {
  var firstEl = document.getElementById('reg-firstname');
  var lastEl = document.getElementById('reg-lastname');
  var loginEl = document.getElementById('reg-login');
  if (!loginEl) return;
  var first = (firstEl ? firstEl.value.trim() : '');
  var last = (lastEl ? lastEl.value.trim() : '');
  if (first && last) {
    var login = (first + '.' + last + '.MP').toLowerCase()
      .normalize('NFD').replace(/[̀-ͯ]/g, '')
      .replace(/[^a-z0-9.]/g, '');
    loginEl.value = login;
  }
}

function showRegisterForm() {
  var reg = document.getElementById('register-form');
  var login = document.querySelector('.auth-card-body:not(#register-form)') || document.querySelector('[id*="login"]');
  document.querySelectorAll('.auth-card-body').forEach(function(el) { el.style.display = 'none'; });
  if (reg) reg.style.display = 'block';
}

function showLoginForm() {
  document.querySelectorAll('.auth-card-body').forEach(function(el) { el.style.display = 'none'; });
  var login = document.querySelector('.auth-card-body:not(#register-form)');
  if (login) login.style.display = 'block';
  else {
    var reg = document.getElementById('register-form');
    if (reg) reg.style.display = 'none';
    // Show the default login card body
    var bodies = document.querySelectorAll('.auth-card-body');
    if (bodies[0]) bodies[0].style.display = 'block';
  }
}

async function doRegister() {
  var firstName = document.getElementById('reg-firstname')?.value?.trim() || '';
  var lastName = document.getElementById('reg-lastname')?.value?.trim() || '';
  const name = (firstName + ' ' + lastName).trim();
  const login = document.getElementById('reg-login')?.value?.trim();
  const email = document.getElementById('reg-email')?.value?.trim();
  const password = document.getElementById('reg-password')?.value?.trim();
  const code = document.getElementById('reg-code')?.value?.trim();
  const mineureEl = document.querySelector('input[name="reg-mineure-radio"]:checked');
  const mineure = mineureEl ? mineureEl.value : '';
  const discord = document.getElementById('reg-discord')?.value?.trim() || '';
  if (!firstName || !lastName || !login || !password || !code) { toast('Tous les champs requis', 'error'); return; }
  try {
    await api('POST', '/register', { firstName, lastName, login, email, password, code, mineure, discord });
    toast('Compte créé ! Connecte-toi. 🎉');
    showLoginForm();
  } catch(e) { toast(e.message, 'error'); }
}

async function doLogin(){
  const login=$('login-input').value.trim(),password=$('password-input').value;
  const btn=$('login-btn');btn.disabled=true;btn.textContent='Connexion…';
  $('auth-error').style.display='none';
  try{
    const user=await api('POST','/login',{login,password});
    currentUser=user;
    $('auth-page').style.display='none';$('app').style.display='block';
    setupApp();
  }catch(e){$('auth-error').style.display='block';$('password-input').value='';}
  finally{btn.disabled=false;btn.textContent='Se connecter';}
}

// Vérifier la session toutes les 30s (détection double connexion)
async function checkSession() {
  if (!currentUser) return;
  try {
    await api('GET', '/me');
  } catch(e) {
    if (e.message && (e.message.includes('SESSION_EXPIRED') || e.message.includes('autre appareil') || e.status === 401)) {
      currentUser = null;
      $('app').style.display = 'none';
      $('auth-page').style.display = 'flex';
      const errEl = $('auth-error') || $('login-error');
      if(errEl) {
        errEl.innerHTML = '⚠️ Ton compte a été connecté depuis un autre appareil. Tu as été déconnecté(e).';
        errEl.style.display = 'block';
      }
    }
  }
}

async function doLogout(){await unsubscribePush();await api('POST','/logout').catch(()=>{});currentUser=null;currentFolder=null;$('app').style.display='none';$('auth-page').style.display='flex';$('login-input').value='';$('password-input').value='';}
document.addEventListener('DOMContentLoaded', function() {
  var pwInput = $('password-input');
  var loginInput = $('login-input');
  if (pwInput) pwInput.addEventListener('keydown', e => { if(e.key==='Enter') doLogin(); });
  var loginBtn = $('login-btn');
if (loginBtn) loginBtn.onclick = function() { doLogin(); };
  if (loginInput) loginInput.addEventListener('keydown', e => { if(e.key==='Enter') { var pw = $('password-input'); if(pw) pw.focus(); } });
});

(async()=>{
  // Détecter token de reset dans l'URL
  const resetToken = new URLSearchParams(window.location.search).get('reset');
  if (resetToken) {
    try {
      const check = await api('GET', '/reset-token/' + resetToken);
      if (check.valid) {
        $('auth-page').style.display='';
        $('app').style.display='none';
        document.querySelector('.auth-card-body').style.display='none';
        $('forgot-form').style.display='none';
        $('register-form').style.display='none';
        $('reset-form').style.display='';
        return;
      }
    } catch(e) {
      $('auth-page').style.display='';
      const errEl = document.getElementById('login-error');
      if(errEl){errEl.textContent='Lien de réinitialisation invalide ou expiré.';errEl.style.display='block';}
    }
    return;
  }
  // Vérifier si déjà connecté
  try{const u=await api('GET','/me');currentUser=u;$('auth-page').style.display='none';$('app').style.display='block';setupApp();}catch(_){}
})();

function setupApp() {
  // Restore sidebar state
  var sidebar = document.getElementById('sidebar');
  if (sidebar && window.innerWidth > 768 && localStorage.getItem('sidebar_collapsed') === '1') {
    sidebar.classList.add('collapsed');
  }
  const isAdmin    = currentUser.role === 'admin';
  const isSubAdmin = currentUser.role === 'subadmin';
  const isAnyAdmin = isAdmin || isSubAdmin;
  const initials=currentUser.name.split(' ').map(w=>w[0]).join('').substring(0,2).toUpperCase();
  document.querySelectorAll('.panel').forEach(p=>{p.classList.remove('active');p.style.display='none';});
  if (isSubAdmin) {
    $('panel-discussions-center').classList.add('active');
    $('panel-discussions-center').style.display='block';
  } else {
    $('panel-files').classList.add('active');$('panel-files').style.display='block';
    $('dashboard-view').style.display='block';
  }
  $('panel-users').style.display=isAdmin?'':'none';
  $('view-folders').style.display='none';$('view-files').style.display='none';
  // Hide discussion panel when navigating back
  const dp = document.getElementById('discussion-panel'); if(dp) dp.style.display='none';
  currentFolder=null;
  $('nav-avatar').textContent=initials;$('nav-username').textContent=currentUser.name;
  $('nav-role-badge').textContent=isAdmin?'Admin':isSubAdmin?'Sous-admin':'Étudiant';
  $('nav-role-text').textContent=isAdmin?'Accès complet':isSubAdmin?'Accès discussions':'Lecture seule';
  $('nav-users').style.display=isAdmin?'flex':'none';
  $('nav-codes').style.display=isAdmin?'flex':'none';
  $('nav-security').style.display=isAdmin?'flex':'none';
  $('nav-settings').style.display='flex';
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  $('nav-revision').style.display=isSubAdmin?'none':'flex';
  $('nav-files').style.display=isSubAdmin?'none':'flex';
  $('nav-dashboard').style.display=isSubAdmin?'none':'flex';
  if (isSubAdmin) {
    $('nav-discussions-center').classList.add('active');
  } else {
    $('nav-dashboard').classList.add('active');
  }
  $('admin-stats').style.display='none';
  $('student-banner').style.display='none';
  $('upload-zone-container').style.display=isAdmin?'block':'none';
  $('storage-indicator').style.display=isAdmin?'block':'none';
  if(!isAnyAdmin)$('student-banner-title').textContent=`Bienvenue, ${currentUser.name.split(' ')[0]} !`;
  $('panel-settings').style.display = 'none';
  $('topbar-title').textContent = isSubAdmin ? 'Discussions' : 'Accueil';
  if (isSubAdmin) {
    _discSort = 'folder';
    loadDiscussionsCenter();
    const dc = document.getElementById('disc-controls-bar'); if(dc) dc.style.display='flex';
    const df = document.getElementById('disc-filters-bar'); if(df) df.style.display='flex';
  } else {
    loadDashboard();
    loadFolders();
  }
  const topbarEl = document.querySelector('.topbar');
  if(topbarEl) topbarEl.style.display = 'flex';
  if($('topbar-search')) $('topbar-search').style.display='block';
  updateTopbar();updateBreadcrumb();
  if(isAnyAdmin)loadStats();
  // Afficher bouton nouvelle annonce pour admin principal seulement
  const annAdminActions = $('ann-admin-actions');
  if(annAdminActions) annAdminActions.style.display = isAnyAdmin ? 'flex' : 'none';
  checkAndShowTutorial();
  updateAnnouncementsBadge();
  // Load discussions center badge
  api('GET', '/threads/all').then(function(threads) {
    _allThreads = threads;
    updateDiscCenterBadge();
  }).catch(function(){});
  updateAvatarPreview();
  updateSidebarAvatar();
  // Vérifier la session toutes les 30 secondes (anti-partage de compte)
  startSessionPolling();
  updateAdminDiscBadge();
  // Activer les notifications push (tous les rôles)
  setTimeout(initPushNotifications, 2000);
  // Fermer le menu @mention si on clique ailleurs
  document.addEventListener('click', function(e) {
    if (_mentionMenu && !_mentionMenu.contains(e.target)) closeMentionMenu();
  });
}

function showDashboard() {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  $('nav-dashboard').classList.add('active');
  document.querySelectorAll('.panel').forEach(p=>{p.classList.remove('active');p.style.display='none';});
  // panel-files doit rester visible car dashboard-view est à l'intérieur
  $('panel-files').style.display = 'block';
$('dashboard-view').style.animation = 'panelFadeIn 0.18s ease forwards';
  $('view-folders').style.display = 'none';
  $('view-files').style.display = 'none';
  const bc = document.getElementById('breadcrumb');
if(bc) bc.style.display = 'none';
const titleWrap = document.getElementById('folder-page-title-wrap');
if(titleWrap) titleWrap.style.display = 'none';
  if($('student-banner')) $('student-banner').style.display = 'none';
  $('dashboard-view').style.display = 'block';
  const dp = document.getElementById('discussion-panel'); if(dp) dp.style.display='none';
  const topbar = document.querySelector('.topbar');
  if(topbar) topbar.style.display = 'flex';
  $('topbar-title').textContent = 'Accueil';
  loadDashboard();
}

async function loadDashboard() {
  const isAdmin = currentUser?.role === 'admin';
  $('dashboard-title').textContent = `Bonjour, ${currentUser.name.split(' ')[0]} 👋`;
  $('dashboard-sub').textContent = isAdmin ? 'Vue d\'ensemble de votre plateforme' : 'Voici ce qui se passe sur MasterPASS';
  if (!isAdmin) {
    const _motivations = [
      { text: "La patience est amère, mais son fruit est doux.", author: "— Aristote" },
      { text: "Ce n'est pas parce que les choses sont difficiles que nous n'osons pas, c'est parce que nous n'osons pas qu'elles sont difficiles.", author: "— Sénèque" },
      { text: "Celui qui déplace une montagne commence par enlever de petites pierres.", author: "— Confucius" },
      { text: "Il n'y a pas de vent favorable pour celui qui ne sait pas où il va.", author: "— Sénèque" },
      { text: "Le commencement de la sagesse, c'est de s'étonner.", author: "— Aristote" },
      { text: "Douter de tout ou tout croire sont deux solutions également commodes, qui l'une et l'autre nous dispensent de réfléchir.", author: "— Henri Poincaré" },
      { text: "Vouloir, c'est pouvoir.", author: "— Hegel" },
      { text: "L'homme est condamné à être libre.", author: "— Sartre" },
      { text: "Ce qui ne me tue pas me rend plus fort.", author: "— Nietzsche" },
      { text: "Le génie, c'est 1% d'inspiration et 99% de transpiration.", author: "— Edison" },
      { text: "Il n'est jamais trop tard pour devenir ce qu'on aurait pu être.", author: "— George Eliot" },
      { text: "La vie, c'est comme une bicyclette : il faut avancer pour ne pas perdre l'équilibre.", author: "— Einstein" },
      { text: "Le moment présent a toujours été et sera toujours.", author: "— Eckhart Tolle" },
      { text: "Les concours, c'est un marathon, pas un sprint. 💪", author: "" },
      { text: "Chaque heure de travail aujourd'hui, c'est un pas de plus vers ton objectif. 🎯", author: "" },
      { text: "Tu n'as pas besoin d'être parfait(e), juste constant(e). 📚", author: "" },
      { text: "La réussite appartient à ceux qui ne lâchent pas. 🔥", author: "" },
      { text: "Un jour à la fois, une leçon à la fois. 🌱", author: "" },
      { text: "Les grands résultats viennent des petits efforts répétés. ⭐", author: "" },
      { text: "Ce que tu apprends aujourd'hui, tu t'en souviendras toute ta vie. 🧠", author: "" },
      { text: "Le PASS est dur, mais toi t'es plus dur(e). 💊", author: "" },
      { text: "Chaque QCM raté est une leçon pour le suivant. 📝", author: "" },
      { text: "Tu étudies pour sauver des vies. Ça vaut le coup. 🫀", author: "" },
      { text: "Même les jours difficiles comptent. Continue. 🌿", author: "" },
      { text: "Le doute fait partie du chemin, pas de la destination. 🧭", author: "" },
      { text: "La fatigue d'aujourd'hui sera la fierté de demain. 💫", author: "" },
      { text: "Ta seule compétition, c'est la version d'hier de toi-même. 🪞", author: "" },
      { text: "La discipline d'aujourd'hui, c'est la liberté de demain. 🕊️", author: "" },
      { text: "Rappelle-toi pourquoi tu as commencé. 💎", author: "" }
    ];
    const today = new Date();
    const dayOfYear = Math.floor((today - new Date(today.getFullYear(), 0, 0)) / 86400000);
    const seed = (currentUser.id * 7 + dayOfYear * 13) % _motivations.length;
    const motiv = document.getElementById('dashboard-motivation');
    const motivText = document.getElementById('dashboard-motivation-text');
    const motivAuthor = document.getElementById('dashboard-motivation-author');
    if (motiv && motivText) {
      motivText.textContent = '\u201C' + _motivations[seed].text + '\u201D';
      motivAuthor.textContent = _motivations[seed].author;
      motiv.style.display = 'block';
    }
  }
  $('dashboard-admin-stats').style.display = 'none';
  $('db-topfiles-card').style.display = 'none';

  // Stats admin
  if (isAdmin) {
    $('dashboard-admin-stats').style.display = 'grid';
    $('db-topfiles-card').style.display = 'block';
    try {
      const stats = await api('GET', '/stats');
      $('db-stat-folders').textContent = stats.folders || 0;
      $('db-stat-files').textContent = stats.files || 0;
      $('db-stat-students').textContent = stats.students || 0;
      const gb = ((stats.totalSize || 0) / 1073741824).toFixed(2);
      $('db-stat-storage').textContent = gb + ' Go';
      document.querySelector('#dashboard-admin-stats .dashboard-stat:last-child .dashboard-stat-label').textContent = 'Stockage R2';
    } catch(e) {}
  }

  // Chargement parallèle
  const [foldersRes, annsRes, threadsRes] = await Promise.allSettled([
    api('GET', '/folders'),
    api('GET', '/announcements'),
    api('GET', '/threads/all')
  ]);

  // Nouveaux fichiers
  if (foldersRes.status === 'fulfilled') {
    const folders = foldersRes.value;
    const allFiles = [];
    folders.forEach(f => {
      (f.files||[]).forEach(file => { if(file.addedAt) allFiles.push({...file, folderName: f.name, folderId: f.id}); });
      (f.subfolders||[]).forEach(sub => {
        (sub.files||[]).forEach(file => { if(file.addedAt) allFiles.push({...file, folderName: f.name + ' / ' + sub.name, folderId: f.id, subId: sub.id}); });
      });
    });
    allFiles.sort((a,b) => new Date(b.addedAt) - new Date(a.addedAt));
    const recent = allFiles.slice(0, 5);
    $('db-new-files').innerHTML = recent.length ? recent.map(f => `
      <div class="dashboard-file-item" onclick="showPanel('files');setTimeout(()=>openFolder(${f.folderId},'${f.folderName}'),300)">
        ${getFileTypeBadge(f.type)}
        <div style="flex:1;min-width:0">
          <div style="font-size:13px;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${f.name}</div>
          <div style="font-size:11px;color:var(--text3)">${f.folderName} · ${new Date(f.addedAt).toLocaleDateString('fr-FR')}</div>
        </div>
        ${(Date.now() - new Date(f.addedAt).getTime()) < 7*24*60*60*1000 ? '<span style="background:linear-gradient(135deg,var(--teal),var(--teal-dark));color:white;border-radius:6px;padding:2px 7px;font-size:9px;font-weight:700">NOUVEAU</span>' : ''}
      </div>`).join('') : '<div class="dashboard-empty">Aucun fichier récent</div>';

    if (isAdmin) {
      const topFiles = [...allFiles].filter(f => f.views > 0).sort((a,b) => (b.views||0) - (a.views||0)).slice(0, 5);
      $('db-top-files').innerHTML = topFiles.length ? topFiles.map(f => `
        <div class="dashboard-file-item">
          ${getFileTypeBadge(f.type)}
          <div style="flex:1;min-width:0">
            <div style="font-size:13px;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${f.name}</div>
            <div style="font-size:11px;color:var(--text3)">${f.folderName}</div>
          </div>
          <span style="font-size:12px;font-weight:700;color:var(--teal-dark)">👁 ${f.views}</span>
        </div>`).join('') : '<div class="dashboard-empty">Aucune consultation</div>';
    }
  }

  // Annonces
  if (annsRes.status === 'fulfilled') {
    const anns = annsRes.value;
    const recent = (anns||[]).slice(0,3);
    $('db-announcements').innerHTML = recent.length ? recent.map(a => `
      <div class="dashboard-ann-item" style="cursor:pointer" onclick="showPanel('announcements');setTimeout(()=>{const el=document.getElementById('ann-${a.id}');if(el){el.scrollIntoView({behavior:'smooth',block:'center'});}},500)">
        <div style="font-size:12px;font-weight:700;color:var(--text);margin-bottom:4px">${a.title||'Annonce'}</div>
        <div style="font-size:12px;color:var(--text2);line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden">${a.message||''}</div>
        <div style="font-size:10px;color:var(--text3);margin-top:4px">${new Date(a.createdAt).toLocaleDateString('fr-FR',{day:'numeric',month:'long'})}</div>
      </div>`).join('') : '<div class="dashboard-empty">Aucune annonce</div>';
  }

  // Discussions récentes
  if (threadsRes.status === 'fulfilled') {
    const threads = threadsRes.value;
    const recent = (threads||[]).slice(0,5);
    $('db-discussions').innerHTML = recent.length ? recent.map(t => `
      <div class="dashboard-disc-item" onclick="showPanel('files');setTimeout(()=>{openFolder(${t.folderId},'${t.folderName||''}');setTimeout(()=>openDiscussion('${t.fileId}','${t.fileName||''}'),600);},300)">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
          <span style="font-size:11px;padding:1px 7px;border-radius:5px;font-weight:700;background:${t.resolved?'rgba(46,125,50,0.1)':'rgba(0,151,167,0.1)'};color:${t.resolved?'#2E7D32':'var(--teal-dark)'}">${t.resolved?'✓ Résolu':'💬 Ouvert'}</span>
          <span style="font-size:12px;font-weight:600;color:var(--text)">${t.title||''}</span>
        </div>
        <div style="font-size:11px;color:var(--text3)">📄 ${t.fileName||''} · ${t.replyCount||0} rép.</div>
      </div>`).join('') : '<div class="dashboard-empty">Aucune discussion</div>';
  }
}
async function updateAdminDiscBadge() {
  if (currentUser?.role !== 'admin' && currentUser?.role !== 'subadmin') return;
  try {
    const { count } = await api('GET', '/comments/admin-unread');
    const badge = document.getElementById('admin-disc-badge');
    if (!badge) return;
    if (count > 0) {
      badge.textContent = count > 9 ? '9+' : count;
      badge.style.display = 'inline-block';
    } else {
      badge.style.display = 'none';
    }
  } catch(e) {}
}

function startSessionPolling() {
  setInterval(async () => {
    if (!currentUser) return;
    try {
      await api('GET', '/me');
    } catch(e) {
      // Si SESSION_EXPIRED, api() gère déjà la déconnexion automatiquement
    }
  }, 30000); // toutes les 30 secondes
}

function showPanel(name){
  if (name === 'home' || name === 'accueil') { showDashboard(); return; }
  document.querySelectorAll('.panel').forEach(p=>{p.classList.remove('active');p.style.display='none';});
  $('dashboard-view').style.display = 'none';
  $('nav-dashboard').classList.remove('active');
  if((name==='users'||name==='codes')&&currentUser?.role!=='admin')return;
  // Always hide discussion when switching panels
  const dp = document.getElementById('discussion-panel');
  if (dp) dp.style.display = 'none';
  const vf = document.getElementById('view-files');
  if (vf && name !== 'files') vf.style.display = 'none';
  
  // Afficher le panel cible
  const target=$('panel-'+name);
  if (!target) { console.error('Panel introuvable: panel-' + name); return; }
  target.classList.add('active');
  target.style.display='block';
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  $('nav-'+name)?.classList.add('active');
  if(name==='files'){$('topbar-title').textContent='Espace documentaire';backToRoot();clearSearch();}
  if(name==='favorites'){$('topbar-title').textContent='Mes favoris';loadFavorites();}
  if(name==='revision'){$('topbar-title').textContent='Révision';loadRevision();}
  if(name==='discussions-center'){$('topbar-title').textContent='Discussions';loadDiscussionsCenter();const dc=document.getElementById('disc-controls-bar');if(dc)dc.style.display='flex';const df=document.getElementById('disc-filters-bar');if(df)df.style.display='flex';}
  if(name==='announcements'){$('topbar-title').textContent='Annonces';loadAnnouncements();}
  if(name==='users'){
  $('topbar-title').textContent='Gestion des comptes';
  loadUsers();
  loadConnectionLogs();
}
if(name==='security'){ $('topbar-title').textContent='Sécurité & Accès'; loadSecurityPanel(); }
  if(name==='codes'){$('topbar-title').textContent="Codes d'invitation";loadCodes();}
  if(name==='settings'){$('topbar-title').textContent='Mes réglages';loadSettingsPanel();}
  // Afficher la barre de recherche uniquement sur le panel fichiers
  const searchBar = $('topbar-search');
  if(searchBar) searchBar.style.display = 'block';
  // Masquer toute la topbar sauf sur le panel fichiers
  const topbar = document.querySelector('.topbar');
  // Topbar visible sur tous les panels sur mobile (pour le bouton hamburger)
  if(topbar) topbar.style.display = 'flex';
  updateTopbar();
  // Sur mobile, fermer la sidebar pour tous les panels
  if(window.innerWidth <= 768) closeSidebar();
}

function updateTopbar(){
  const isAdmin=currentUser?.role==='admin';
  const isSubAdmin=currentUser?.role==='subadmin';
  const isAnyAdmin=isAdmin||isSubAdmin;
  const panel=document.querySelector('.panel.active')?.id;
  const el=$('topbar-actions');el.innerHTML='';
  if(panel==='panel-files'&&isAnyAdmin){
    if(!currentFolder){
      el.innerHTML=`<button class="btn-action primary-action" onclick="openModal('modal-folder')">
        <svg viewBox="0 0 24 24" fill="currentColor" style="width:15px;height:15px"><path d="M20 6h-8l-2-2H4c-1.11 0-2 .89-2 2v12c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V8c0-1.11-.89-2-2-2zm-1 8h-3v3h-2v-3h-3v-2h3v-3h2v3h3v2z"/></svg>
        Nouveau dossier</button>`;
    }else{
      el.innerHTML=`<button class="btn-action" onclick="document.getElementById('file-input').click()">
        <svg viewBox="0 0 24 24" fill="currentColor" style="width:15px;height:15px"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96zM14 13v4h-4v-4H7l5-5 5 5h-3z"/></svg>
        Déposer un fichier</button>`;
    }
  }
  if(panel==='panel-users'&&isAdmin){
    el.innerHTML=`<button class="btn-action primary-action" onclick="openModal('modal-user')">
      <svg viewBox="0 0 24 24" fill="currentColor" style="width:15px;height:15px"><path d="M15 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm-9-2V7H4v3H1v2h3v3h2v-3h3v-2H6zm9 4c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
      Nouveau compte</button>`;
  }
}

async function loadStats(){
  try{
    const s=await api('GET','/stats');
    $('stat-folders').textContent=s.folders;$('stat-files').textContent=s.files;
    $('stat-users').textContent=s.students;$('stat-size').textContent=formatSize(s.totalSize);
    $('storage-mode-badge').textContent=s.storageMode==='Cloudflare R2'?'☁ Cloudflare R2':'⬡ Local';
    const usedGo=(s.totalSize/1073741824).toFixed(2);
    $('storage-used').textContent=formatSize(s.totalSize);
    const pct=Math.min((s.totalSize/(10*1073741824))*100,100);
    $('storage-bar-fill').style.width=pct+'%';
  }catch(_){}
}


// ── SOUS-DOSSIERS ─────────────────────────────────────────────────────────────
function renderSubfolders(subs, parentId, parentName) {
  if (!subs || !subs.length) return '';
  return '<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px">' +
    subs.map(function(sub) {
      return '<div onclick="openSubfolder(' + sub.id + ',\'' + sub.name.replace(/'/g,"\'") + '\',' + parentId + ',\'' + parentName.replace(/'/g,"\'") + '\')" ' +
        'style="display:flex;align-items:center;gap:10px;padding:10px 16px;background:var(--surface,white);border-radius:12px;border:1.5px solid var(--border);cursor:pointer;font-size:13px;font-weight:600;color:var(--text);transition:border-color 0.15s" ' +
        '>' +
        '<svg viewBox="0 0 24 24" fill="currentColor" style="width:18px;height:18px;color:var(--teal-dark)"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>' +
        sub.name + '</div>';
    }).join('') + '</div>';
}

async function openSubfolder(subId, subName, parentId, parentName) {
  currentSubfolder = { id: subId, name: subName, parentId: parentId };
  currentFolder = { id: parentId, name: parentName };
  const vf = $('view-files');
  const vd = $('view-folders');
  if(vd) vd.style.display = 'none';
  if(vf) vf.style.display = 'block';
  const wrap = document.getElementById('folder-page-title-wrap');
if(wrap) wrap.style.display='flex';
const ft = document.getElementById('folder-page-title');
if(ft) ft.textContent = subName;
const backBtn = document.getElementById('btn-back-folder');
if(backBtn) backBtn.style.display='flex'; // bouton retour visible dans un sous-dossier
  if($('student-banner')) $('student-banner').style.display = 'none';
  if($('admin-stats')) $('admin-stats').style.display = 'none';
  const subContainerOld = document.getElementById('subfolders-container');
  if(subContainerOld) subContainerOld.innerHTML = '';
  updateBreadcrumb(); updateTopbar();
  await loadSubfolderFiles(parentId, subId);
}

async function loadSubfolderFiles(folderId, subId) {
  const isAdmin = currentUser?.role === 'admin' || currentUser?.role === 'subadmin';
  const container = $('files-container') || $('files-tbody')?.closest('.files-list');
  try {
    const files = await api('GET', '/folders/' + folderId + '/subfolders/' + subId + '/files');
    const dlBase = '/api/folders/' + folderId + '/subfolders/' + subId + '/files';
    const html = (files||[]).map(function(f) {
      return buildFileRow(f, isAdmin,
        'openPreviewById(this)" data-fileid="' + f.id + '" data-type="' + f.type + '" data-basepath="' + dlBase + '/' + f.id,
        dlBase + '/' + f.id,
        'toggleSubDownload(' + folderId + ',' + subId + ',' + f.id + ')',
        'deleteSubFile(' + folderId + ',' + subId + ',' + f.id + ')',
        folderId, subId
      );
    }).join('');
    const fc = document.getElementById('files-list-body');
    if(fc) fc.innerHTML = html;
    // Also clear files-tbody if exists
    const tb = document.getElementById('files-tbody');
    if(tb) tb.innerHTML = '';
    const validIds = (files||[]).filter(function(f){ return f && f.id; }).map(function(f){ return String(f.id); });
    if(validIds.length) setTimeout(function(){ updateDiscussionBadges(validIds); }, 300);
  } catch(e) {
    const fc = document.getElementById('files-list-body');
    if(fc) fc.innerHTML = '<div style="color:var(--danger);padding:20px">Erreur: ' + e.message + '</div>';
  }
}

// ── TUTORIEL ──────────────────────────────────────────────────────────────────
function checkAndShowTutorial() {
  if (!currentUser) return;
  var key = 'mp_tutorial_done_' + currentUser.id;
  if (!localStorage.getItem(key)) {
    setTimeout(function() { openTutorial(); }, 800);
  }
}

let _tutoStep = 0;
let _tutoTotal = 8;

function showTutoStep(n) {
  _tutoStep = n;
  document.querySelectorAll('.tutorial-step').forEach(function(s,i){
    s.style.display = i === n ? 'block' : 'none';
  });
  document.querySelectorAll('.tutorial-dot').forEach(function(d,i){
    d.style.background = i === n ? 'var(--teal)' : (i < n ? 'var(--teal-dark)' : 'var(--border)');
  });
  var skipBtn = document.getElementById('tuto-skip-btn');
  var nextBtn = document.getElementById('tuto-next-btn');
  if (skipBtn) skipBtn.style.display = n >= _tutoTotal-1 ? 'none' : 'inline-block';
  if (nextBtn) {
    nextBtn.style.display = 'inline-block';
    nextBtn.textContent = n >= _tutoTotal-1 ? 'Terminer ✓' : 'Suivant →';
    nextBtn.onclick = n >= _tutoTotal-1 ? closeTutorial : tutoNext;
  }
  var fn = document.getElementById('tuto-firstname');
  if (fn && currentUser) fn.textContent = currentUser.name.split(' ')[0];
}

function tutoNext() {
  if (_tutoStep < _tutoTotal-1) showTutoStep(_tutoStep+1);
  else closeTutorial();
}

function tutoPrev() {
  if (_tutoStep > 0) showTutoStep(_tutoStep-1);
}

function openTutorial() {
  var overlay = document.getElementById('tutorial-overlay');
  if (overlay) overlay.style.display = 'flex';
  showTutoStep(0);
}

function closeTutorial() {
  var overlay = document.getElementById('tutorial-overlay');
  if (overlay) overlay.style.display = 'none';
  if (currentUser) localStorage.setItem('mp_tutorial_done_' + currentUser.id, '1');
}


// ── RECHERCHE ─────────────────────────────────────────────────────────────────
function clearSearch() {
  var input = document.getElementById('topbar-search-input') || document.getElementById('search-input');
  if (input) input.value = '';
  var clearBtn = document.getElementById('search-clear');
  if (clearBtn) clearBtn.style.display = 'none';
  var panel = document.getElementById('panel-search');
  if (panel) panel.style.display = 'none';
}

function doSearchContextual(query) {
  var panel = document.querySelector('.panel.active')?.id;
  var input = document.getElementById('search-input');

  if (panel === 'panel-discussions-center') {
    // Filtre les cards discussions
    if (input) input.setAttribute('placeholder', 'Rechercher un fil...');
    var q = (query||'').toLowerCase().trim();
    document.querySelectorAll('#disc-center-list .disc-center-card').forEach(function(card) {
      var text = card.textContent.toLowerCase();
      card.style.display = (!q || text.includes(q)) ? '' : 'none';
    });
    return;
  }

  if (panel === 'panel-announcements' || panel === 'panel-announcements-student') {
    // Filtre les cards annonces
    if (input) input.setAttribute('placeholder', 'Rechercher une annonce...');
    var q = (query||'').toLowerCase().trim();
    document.querySelectorAll('#announcements-list .ann-card').forEach(function(card) {
      var text = card.textContent.toLowerCase();
      card.style.display = (!q || text.includes(q)) ? '' : 'none';
    });
    return;
  }

  if (panel === 'panel-users') {
    if (input) input.setAttribute('placeholder', 'Rechercher un compte...');
    var q = (query||'').toLowerCase().trim();
    document.querySelectorAll('#users-grid tr').forEach(function(row) {
      if (row.closest('thead')) return;
      var text = row.textContent.toLowerCase();
      row.style.display = (!q || text.includes(q)) ? '' : 'none';
    });
    return;
  }

  // Par défaut : recherche fichiers
  if (input) input.setAttribute('placeholder', 'Rechercher un fichier...');
  doSearch(query);
}
async function doSearch(query) {
  var panel = document.getElementById('panel-search');
  if (!query || query.length < 2) {
    var rt = document.getElementById('search-results-title');
    var rs = document.getElementById('search-results-sub');
    var rl = document.getElementById('search-results-list');
    if (rt) rt.style.display = 'none';
    if (rs) rs.style.display = 'none';
    if (rl) rl.innerHTML = '';
    if (panel) panel.style.display = 'none';
    return;
  }
  // Afficher le panel de recherche
  if (panel) { panel.style.display = 'block'; panel.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  var clearBtn = document.getElementById('search-clear');
  if (clearBtn) clearBtn.style.display = 'block';
  var rt = document.getElementById('search-results-title');
  var rs = document.getElementById('search-results-sub');
  if (rt) rt.style.display = 'block';
  if (rs) { rs.style.display = 'block'; rs.textContent = 'Recherche en cours...'; }
  try {
    var results = await api('GET', '/search?q=' + encodeURIComponent(query));
    var list = document.getElementById('search-results-list');
    if (!list) return;
    if (!results.length) {
      list.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3)">Aucun résultat pour "' + query + '"</div>';
      return;
    }
    var isAdmin = currentUser?.role === 'admin' || currentUser?.role === 'subadmin';
    if (rs) rs.textContent = results.length + ' résultat(s) pour "' + query + '"';
    list.innerHTML = results.map(function(r) {
      return buildFileRow(r.file, isAdmin,
        'openPreviewById(this)" data-fileid="' + r.file.id + '" data-type="' + r.file.type + '" data-basepath="/api/folders/' + r.folderId + '/files/' + r.file.id,
        '/api/folders/' + r.folderId + '/files/' + r.file.id,
        null, null, r.folderId, r.subId
      );
    }).join('');
  } catch(e) {
    console.error('Search error:', e);
  }
}

// ── SOUS-FICHIERS ─────────────────────────────────────────────────────────────
async function toggleSubDownload(folderId, subId, fileId) {
  try {
    await api('PATCH', '/folders/' + folderId + '/subfolders/' + subId + '/files/' + fileId + '/downloadable');
    await loadSubfolderFiles(folderId, subId);
  } catch(e) { toast(e.message, 'error'); }
}

async function deleteSubFile(folderId, subId, fileId) {
  if (!await customConfirm('Supprimer ce fichier ?')) return;
  try {
    await api('DELETE', '/folders/' + folderId + '/subfolders/' + subId + '/files/' + fileId);
    await loadSubfolderFiles(folderId, subId);
    toast('Fichier supprimé');
  } catch(e) { toast(e.message, 'error'); }
}

// ── WATERMARK (no-op) ─────────────────────────────────────────────────────────
function removeWatermark() {}

// ── SCROLL TO COMMENT ─────────────────────────────────────────────────────────
function scrollToComment(commentId) {
  var el = document.getElementById('msg-' + commentId);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

  var _revisionDossiers = [];
  var _revisionSeances = [];
  var _revisionDossierCourant = null;
  var _revisionSchemas = [];
  var _revisionSeanceCourante = null;
  var _revisionSchemaQueue = [];

// ── RÉVISION ───────────────────────────────────────────────────────────────────
async function loadRevision() {
  var list = document.getElementById('revision-list');
  if (!list) return;
  list.innerHTML = '<div class="dashboard-empty">Chargement...</div>';
  try {
    const dossiers = await api('GET', '/revision/dossiers');
    _revisionDossiers = dossiers;
    var isAdmin = currentUser && currentUser.role === 'admin';
    var html = '';
    if (isAdmin) {
      html += '<button class="btn-action" onclick="creerDossier()" style="margin-bottom:16px">+ Nouveau dossier</button>';
    }
    if (!dossiers.length) {
      html += '<div class="dashboard-empty">Aucun dossier pour le moment</div>';
    } else {
      html += dossiers.map(function(d) {
        return '<div class="dossier-card" data-id="' + d.id + '" style="display:flex;align-items:center;gap:16px;padding:20px 22px;border-radius:20px;border:1.5px solid rgba(139,92,246,0.2);margin-bottom:14px;cursor:pointer;background:linear-gradient(135deg,rgba(139,92,246,0.12),rgba(59,130,246,0.08));backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:0 4px 24px rgba(139,92,246,0.1);transition:all 0.22s" onmouseover="this.style.transform=\'translateY(-2px)\';this.style.boxShadow=\'0 8px 32px rgba(139,92,246,0.2)\'" onmouseout="this.style.transform=\'translateY(0)\';this.style.boxShadow=\'0 4px 24px rgba(139,92,246,0.1)\'">' +
  '<div style="width:48px;height:48px;border-radius:14px;background:linear-gradient(135deg,#8B5CF6,#3B82F6);display:flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 4px 12px rgba(139,92,246,0.35)">' +
    '<svg viewBox="0 0 24 24" fill="white" style="width:22px;height:22px"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>' +
  '</div>' +
  '<div style="flex:1;min-width:0">' +
    '<div style="font-size:15px;font-weight:700;color:var(--text);letter-spacing:-0.2px">' + d.titre + '</div>' +
    '<div style="font-size:12px;color:#8B5CF6;margin-top:4px;font-weight:600">' + d.seanceCount + ' séance(s)</div>' +
  '</div>' +
  (isAdmin ? revActionButtons(d.id) : '') +
'</div>';
      }).join('');
    }
    list.innerHTML = html;
    list.querySelectorAll('.dossier-card').forEach(function(card) {
      card.addEventListener('click', function() { ouvrirDossier(parseInt(card.dataset.id)); });
    });
    if (isAdmin) revWireActions(list, 'dossier');
  } catch(e) {
    list.innerHTML = '<div class="dashboard-empty">Erreur de chargement</div>';
  }
}
async function creerDossier() {
  var titre = await customPrompt('Nom du dossier (ex: Anatomie, Pr Dupont, S1...)');
  if (!titre || !titre.trim()) return;
  try {
    await api('POST', '/revision/dossiers', { titre: titre.trim() });
    loadRevision();
  } catch(e) {
    toast('Erreur lors de la création', 'error');
  }
}
function revActionButtons(id) {
  return '<div class="rev-actions" data-id="' + id + '" style="display:flex;gap:4px;flex-shrink:0">' +
    '<button class="rev-edit-btn" title="Renommer" style="width:28px;height:28px;border-radius:8px;border:1px solid var(--border);background:var(--surface,#fff);display:flex;align-items:center;justify-content:center;cursor:pointer">' +
      '<svg viewBox="0 0 24 24" fill="currentColor" style="width:14px;height:14px;color:var(--text2)"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>' +
    '</button>' +
    '<button class="rev-delete-btn" title="Supprimer" style="width:28px;height:28px;border-radius:8px;border:1px solid var(--border);background:var(--surface,#fff);display:flex;align-items:center;justify-content:center;cursor:pointer">' +
      '<svg viewBox="0 0 24 24" fill="currentColor" style="width:14px;height:14px;color:#C62828"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>' +
    '</button>' +
  '</div>';
}
function revWireActions(container, type) {
  container.querySelectorAll('.rev-edit-btn').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      var id = parseInt(btn.closest('.rev-actions').dataset.id);
      if (type === 'dossier') renommerDossier(id);
      else if (type === 'seance') renommerSeance(id);
      else if (type === 'schema') renommerSchema(id);
    });
  });
  container.querySelectorAll('.rev-delete-btn').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      var id = parseInt(btn.closest('.rev-actions').dataset.id);
      if (type === 'dossier') supprimerDossier(id);
      else if (type === 'seance') supprimerSeance(id);
      else if (type === 'schema') supprimerSchema(id);
    });
  });
}
function revFormatDate(iso) {
  if (!iso) return null;
  return new Date(iso).toLocaleDateString('fr-FR');
}
async function renommerDossier(id) {
  var d = _revisionDossiers.find(function(x) { return x.id === id; });
  var titre = await customPrompt('Nouveau nom du dossier', d ? d.titre : '');
  if (!titre || !titre.trim()) return;
  try {
    await api('PATCH', '/revision/dossiers/' + id, { titre: titre.trim() });
    loadRevision();
  } catch(e) {
    toast('Erreur lors du renommage', 'error');
  }
}
async function supprimerDossier(id) {
  if (!await customConfirm('Supprimer ce dossier et toutes ses séances ? Cette action est irréversible.')) return;
  try {
    await api('DELETE', '/revision/dossiers/' + id);
    loadRevision();
  } catch(e) {
    toast('Erreur lors de la suppression', 'error');
  }
}
async function renommerSeance(id) {
  var s = _revisionSeances.find(function(x) { return x.id === id; });
  var titre = await customPrompt('Nouveau nom de la séance', s ? s.titre : '');
  if (!titre || !titre.trim()) return;
  try {
    await api('PATCH', '/revision/seances/' + id, { titre: titre.trim() });
    ouvrirDossier(_revisionDossierCourant);
  } catch(e) {
    toast('Erreur lors du renommage', 'error');
  }
}
async function supprimerSeance(id) {
  if (!await customConfirm('Supprimer cette séance et tous ses schémas ? Cette action est irréversible.')) return;
  try {
    await api('DELETE', '/revision/seances/' + id);
    ouvrirDossier(_revisionDossierCourant);
  } catch(e) {
    toast('Erreur lors de la suppression', 'error');
  }
}
async function renommerSchema(id) {
  var sc = _revisionSchemas.find(function(x) { return x.id === id; });
  var titre = await customPrompt('Nouveau nom du schéma', sc ? sc.titre : '');
  if (!titre || !titre.trim()) return;
  try {
    await api('PATCH', '/revision/seances/' + _revisionSeanceCourante + '/schemas/' + id, { titre: titre.trim() });
    ouvrirSeance(_revisionSeanceCourante);
  } catch(e) {
    toast('Erreur lors du renommage', 'error');
  }
}
async function supprimerSchema(id) {
  if (!await customConfirm('Supprimer ce schéma ? Cette action est irréversible.')) return;
  try {
    await api('DELETE', '/revision/seances/' + _revisionSeanceCourante + '/schemas/' + id);
    ouvrirSeance(_revisionSeanceCourante);
  } catch(e) {
    toast('Erreur lors de la suppression', 'error');
  }
}
async function ouvrirDossier(dossierId) {
  var list = document.getElementById('revision-list');
  var dossier = _revisionDossiers.find(function(d) { return d.id === dossierId; });
  if (!dossier || !list) return;
  _revisionDossierCourant = dossierId;
  list.innerHTML = '<div class="dashboard-empty">Chargement...</div>';
  try {
    const seances = await api('GET', '/revision/seances?dossierId=' + dossierId);
    _revisionSeances = seances;
    var isAdmin = currentUser && currentUser.role === 'admin';
    var html = '<button class="btn-action" onclick="loadRevision()" style="margin-bottom:16px">← Retour</button>';
    html += '<div style="font-size:16px;font-weight:700;color:var(--text);margin-bottom:14px">' + dossier.titre + '</div>';
    if (isAdmin) {
      html += '<button class="btn-action" onclick="creerSeance()" style="margin-bottom:16px">+ Nouvelle séance</button>';
    }
    if (!seances.length) {
      html += '<div class="dashboard-empty">Aucune séance dans ce dossier</div>';
    } else {
      html += seances.map(function(s) {
        return '<div class="seance-card" data-id="' + s.id + '" style="display:flex;align-items:center;gap:16px;padding:20px 22px;border-radius:20px;border:1.5px solid rgba(139,92,246,0.2);margin-bottom:14px;cursor:pointer;background:linear-gradient(135deg,rgba(139,92,246,0.12),rgba(59,130,246,0.08));backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:0 4px 24px rgba(139,92,246,0.1);transition:all 0.22s" onmouseover="this.style.transform=\'translateY(-2px)\';this.style.boxShadow=\'0 8px 32px rgba(139,92,246,0.2)\'" onmouseout="this.style.transform=\'translateY(0)\';this.style.boxShadow=\'0 4px 24px rgba(139,92,246,0.1)\'">' +
  '<div style="width:48px;height:48px;border-radius:14px;background:linear-gradient(135deg,#8B5CF6,#3B82F6);display:flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 4px 12px rgba(139,92,246,0.35)">' +
    '<svg viewBox="0 0 24 24" fill="white" style="width:22px;height:22px"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 14H9V8h2v8zm4 0h-2V8h2v8z"/></svg>' +
  '</div>' +
  '<div style="flex:1;min-width:0">' +
    '<div style="font-size:15px;font-weight:700;color:var(--text);letter-spacing:-0.2px">' + s.titre + '</div>' +
    '<div style="font-size:12px;color:#8B5CF6;margin-top:4px;font-weight:600">' + s.schemaCount + ' schéma(s)</div>' +
  '</div>' +
  (isAdmin ? revActionButtons(s.id) : '') +
'</div>';
      }).join('');
    }
    list.innerHTML = html;
    list.querySelectorAll('.seance-card').forEach(function(card) {
      card.addEventListener('click', function() { ouvrirSeance(parseInt(card.dataset.id)); });
    });
    if (isAdmin) revWireActions(list, 'seance');
  } catch(e) {
    list.innerHTML = '<div class="dashboard-empty">Erreur de chargement</div>';
  }
}
async function ouvrirSeance(id) {
  var list = document.getElementById('revision-list');
  var seance = _revisionSeances.find(function(s) { return s.id === id; });
  if (!seance || !list) return;
  _revisionSeanceCourante = id;
  list.innerHTML = '<div class="dashboard-empty">Chargement...</div>';
  try {
    const schemas = await api('GET', '/revision/seances/' + id + '/schemas');
    _revisionSchemas = schemas;
    _revisionSchemaQueue = schemas;
    var isAdmin = currentUser && currentUser.role === 'admin';
    var html = '<button class="btn-action" onclick="ouvrirDossier(_revisionDossierCourant)" style="margin-bottom:16px">← Retour</button>';
    html += '<div style="font-size:16px;font-weight:700;color:var(--text);margin-bottom:14px">' + seance.titre + '</div>';
    if (isAdmin) {
      html += '<button class="btn-action" onclick="afficherFormulaireSchema(' + id + ')" style="margin-bottom:16px">+ Ajouter un schéma</button>';
      html += '<div id="schema-form-zone"></div>';
    }
    if (!schemas.length) {
      html += '<div class="dashboard-empty">Aucun schéma pour le moment</div>';
    } else {
      html += '<button class="btn-action" onclick="ouvrirSchema(' + id + ',' + schemas[0].id + ')" style="margin-bottom:12px;background:var(--teal,#0097A7);color:#fff;border:none">▶ Tout réviser</button>';
      html += schemas.map(function(sc) {
        var date = revFormatDate(sc.derniereRevision);
        return '<div class="schema-card" data-id="' + sc.id + '" style="display:flex;align-items:center;gap:16px;padding:16px 20px;border-radius:20px;border:1.5px solid rgba(139,92,246,0.2);margin-bottom:14px;cursor:pointer;background:linear-gradient(135deg,rgba(139,92,246,0.12),rgba(59,130,246,0.08));backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:0 4px 24px rgba(139,92,246,0.1);transition:all 0.22s" onmouseover="this.style.transform=\'translateY(-2px)\';this.style.boxShadow=\'0 8px 32px rgba(139,92,246,0.2)\'" onmouseout="this.style.transform=\'translateY(0)\';this.style.boxShadow=\'0 4px 24px rgba(139,92,246,0.1)\'">' +
  '<img src="/api/revision/seances/' + id + '/schemas/' + sc.id + '/image" style="width:52px;height:52px;object-fit:cover;border-radius:12px;border:2px solid rgba(139,92,246,0.25);flex-shrink:0">' +
  '<div style="flex:1;min-width:0">' +
    '<div style="font-size:15px;font-weight:700;color:var(--text);letter-spacing:-0.2px">' + sc.titre + '</div>' +
    '<div style="font-size:11px;color:#8B5CF6;margin-top:4px;font-weight:600">' + (date ? 'Dernière révision le ' + date : 'Pas encore révisé') + '</div>' +
  '</div>' +
  (isAdmin ? revActionButtons(sc.id) : '') +
'</div>';
      }).join('');
    }
    list.innerHTML = html;
    list.querySelectorAll('.schema-card').forEach(function(card) {
      card.addEventListener('click', function() { ouvrirSchema(id, parseInt(card.dataset.id)); });
    });
    if (isAdmin) revWireActions(list, 'schema');
  } catch(e) {
    list.innerHTML = '<div class="dashboard-empty">Erreur de chargement</div>';
  }
}
async function ouvrirSchema(seanceId, schemaId) {
  var list = document.getElementById('revision-list');
  if (!list) return;
  list.innerHTML = '<div class="dashboard-empty">Chargement...</div>';
  try {
    const schema = await api('GET', '/revision/seances/' + seanceId + '/schemas/' + schemaId);
    revPoints = schema.reperes;
    api('POST', '/revision/seances/' + seanceId + '/schemas/' + schemaId + '/vu').catch(function() {});
    var imgUrl = '/api/revision/seances/' + seanceId + '/schemas/' + schemaId + '/image';
    var qIdx = _revisionSchemaQueue.findIndex(function(s) { return s.id === schemaId; });
    var nextSchema = (qIdx >= 0 && qIdx < _revisionSchemaQueue.length - 1) ? _revisionSchemaQueue[qIdx + 1] : null;
    var html = '<button class="btn-action" onclick="ouvrirSeance(' + seanceId + ')" style="margin-bottom:16px">← Retour</button>';
    if (nextSchema) {
      html += '<button class="btn-action" onclick="ouvrirSchema(' + seanceId + ',' + nextSchema.id + ')" style="margin-bottom:16px;margin-left:8px">Schéma suivant →</button>';
    }
    html += '<div style="font-size:16px;font-weight:700;color:var(--text);margin-bottom:14px">' + schema.titre + '</div>';
    html += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px">' +
      '<div id="rev-tab-1" onclick="revShowTab(1)" style="position:relative;cursor:pointer;text-align:center;padding:14px 8px;border-radius:14px;border:2px solid var(--teal,#0097A7);background:rgba(0,151,167,0.10)">' +
        '<svg viewBox="0 0 24 24" fill="currentColor" style="width:22px;height:22px;color:var(--teal-dark,#006064)"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5C21.27 7.61 17 4.5 12 4.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>' +
        '<div style="font-size:12px;font-weight:700;color:var(--text);margin-top:6px">Cacher / révéler</div>' +
        '<div style="font-size:10.5px;color:var(--text2);margin-top:2px">Mémorise puis vérifie</div>' +
        '<div id="rev-tab-1-badge" style="display:none;position:absolute;top:6px;right:6px;width:18px;height:18px;border-radius:50%;background:var(--success,#2E7D32);color:#fff;font-size:11px;font-weight:800;align-items:center;justify-content:center">✓</div>' +
      '</div>' +
      '<div id="rev-tab-2" onclick="revShowTab(2)" style="position:relative;cursor:pointer;text-align:center;padding:14px 8px;border-radius:14px;border:1.5px solid var(--border);background:var(--surface,#fff)">' +
        '<svg viewBox="0 0 24 24" fill="currentColor" style="width:22px;height:22px;color:var(--text2)"><path d="M10 9h4V6h3l-5-5-5 5h3v3zm-1 1H6V7l-5 5 5 5v-3h3v-4zm14 2l-5-5v3h-3v4h3v3l5-5zm-9 3h-4v3H7l5 5 5-5h-3v-3z"/></svg>' +
        '<div style="font-size:12px;font-weight:700;color:var(--text);margin-top:6px">Glisser-déposer</div>' +
        '<div style="font-size:10.5px;color:var(--text2);margin-top:2px">Place chaque étiquette</div>' +
        '<div id="rev-tab-2-badge" style="display:none;position:absolute;top:6px;right:6px;width:18px;height:18px;border-radius:50%;background:var(--success,#2E7D32);color:#fff;font-size:11px;font-weight:800;align-items:center;justify-content:center">✓</div>' +
      '</div>' +
      '<div id="rev-tab-3" onclick="revShowTab(3)" style="position:relative;cursor:pointer;text-align:center;padding:14px 8px;border-radius:14px;border:1.5px solid var(--border);background:var(--surface,#fff)">' +
        '<svg viewBox="0 0 24 24" fill="currentColor" style="width:22px;height:22px;color:var(--text2)"><path d="M12 8c-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4-1.79-4-4-4zm8.94 3c-.46-4.17-3.77-7.48-7.94-7.94V1h-2v2.06C6.83 3.52 3.52 6.83 3.06 11H1v2h2.06c.46 4.17 3.77 7.48 7.94 7.94V23h2v-2.06c4.17-.46 7.48-3.77 7.94-7.94H23v-2h-2.06zM12 19c-3.87 0-7-3.13-7-7s3.13-7 7-7 7 3.13 7 7-3.13 7-7 7z"/></svg>' +
        '<div style="font-size:12px;font-weight:700;color:var(--text);margin-top:6px">Pointer-cliquer</div>' +
        '<div style="font-size:10.5px;color:var(--text2);margin-top:2px">Clique au bon endroit</div>' +
        '<div id="rev-tab-3-badge" style="display:none;position:absolute;top:6px;right:6px;width:18px;height:18px;border-radius:50%;background:var(--success,#2E7D32);color:#fff;font-size:11px;font-weight:800;align-items:center;justify-content:center">✓</div>' +
      '</div>' +
    '</div>';
    html += '<div id="rev-panel-1">' +
      '<div id="rev-m1-stage" style="position:relative;width:100%;border-radius:12px;overflow:hidden;border:1px solid var(--border)">' +
        '<img src="' + imgUrl + '" style="display:block;width:100%;height:auto">' +
      '</div>' +
      '<ul id="rev-m1-list" style="list-style:none;padding:0;margin:16px 0 0;display:grid;gap:8px"></ul>' +
      '<div style="margin-top:12px;display:flex;gap:8px">' +
        '<button class="btn-action" onclick="revM1SetAll(false)">Tout cacher</button>' +
        '<button class="btn-action" onclick="revM1SetAll(true)">Tout révéler</button>' +
      '</div>' +
    '</div>';
    html += '<div id="rev-panel-2" style="display:none">' +
      '<div id="rev-m2-stage" style="position:relative;width:100%;border-radius:12px;overflow:hidden;border:1px solid var(--border)">' +
        '<img src="' + imgUrl + '" style="display:block;width:100%;height:auto;filter:saturate(.85)">' +
      '</div>' +
      '<div id="rev-m2-tray" style="display:flex;flex-wrap:wrap;gap:9px;margin-top:16px"></div>' +
      '<div id="rev-m2-score" style="margin-top:10px;font-size:12.5px;font-weight:700;color:var(--text2)"></div>' +
      '<button class="btn-action" onclick="revInitM2()" style="margin-top:10px">Recommencer</button>' +
    '</div>';
    html += '<div id="rev-panel-3" style="display:none">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:10px 12px;margin-bottom:12px">' +
        '<div id="rev-m3-question" style="font-size:14px"></div>' +
        '<div id="rev-m3-progress" style="font-size:12px;color:var(--text2);font-weight:700"></div>' +
      '</div>' +
      '<div id="rev-m3-stage" style="position:relative;width:100%;border-radius:12px;overflow:hidden;border:1px solid var(--border);cursor:crosshair">' +
        '<img src="' + imgUrl + '" style="display:block;width:100%;height:auto;filter:saturate(.85)">' +
      '</div>' +
      '<div id="rev-m3-summary" style="display:none"></div>' +
      '<button class="btn-action" onclick="revInitM3()" style="margin-top:10px">Recommencer</button>' +
    '</div>';
    list.innerHTML = html;
    revInitM1();
    revInitM2();
    revInitM3();
  } catch(e) {
    list.innerHTML = '<div class="dashboard-empty">Erreur de chargement</div>';
  }
}

var revPoints = [];
var revTol = 9;
var revDrag = null;
var revM3Queue = [], revM3Idx = 0, revM3Score = 0, revM3Locked = false, revM3Attempts = 0;
var revM3MaxAttempts = 3;

function revShuffle(arr) {
  var a = arr.slice();
  for (var i = a.length - 1; i > 0; i--) {
    var j = Math.floor(Math.random() * (i + 1));
    var tmp = a[i]; a[i] = a[j]; a[j] = tmp;
  }
  return a;
}
function revFadeIn(el) {
  el.style.opacity = '0';
  el.style.transition = 'none';
  requestAnimationFrame(function() {
    requestAnimationFrame(function() {
      el.style.transition = 'opacity .25s ease';
      el.style.opacity = '1';
    });
  });
}
function revUpdateBadges() {
  var s1 = document.getElementById('rev-m1-stage');
  var s2 = document.getElementById('rev-m2-stage');
  var s3 = document.getElementById('rev-m3-summary');
  var b1 = document.getElementById('rev-tab-1-badge');
  var b2 = document.getElementById('rev-tab-2-badge');
  var b3 = document.getElementById('rev-tab-3-badge');
  if (s1 && b1) {
    var pins = s1.querySelectorAll('[data-rev-pin]');
    var revealed = s1.querySelectorAll('[data-rev-pin][data-revealed="true"]');
    b1.style.display = (pins.length && revealed.length === pins.length) ? 'flex' : 'none';
  }
  if (s2 && b2) {
    var hotspots = s2.querySelectorAll('[data-rev-hotspot]');
    var filled = s2.querySelectorAll('[data-rev-hotspot][data-filled="true"]');
    b2.style.display = (hotspots.length && filled.length === hotspots.length) ? 'flex' : 'none';
  }
  if (b3) {
    b3.style.display = (s3 && s3.style.display === 'block') ? 'flex' : 'none';
  }
}
function revShowTab(n) {
  for (var i = 1; i <= 3; i++) {
    var panel = document.getElementById('rev-panel-' + i);
    var tab = document.getElementById('rev-tab-' + i);
    if (!panel || !tab) continue;
    if (i === n) {
      tab.style.border = '2px solid var(--teal,#0097A7)';
      tab.style.background = 'rgba(0,151,167,0.10)';
      panel.style.display = 'block';
      revFadeIn(panel);
    } else {
      tab.style.border = '1.5px solid var(--border)';
      tab.style.background = 'var(--surface,#fff)';
      panel.style.display = 'none';
    }
  }
}
function revInitM1() {
  var stage = document.getElementById('rev-m1-stage');
  var list = document.getElementById('rev-m1-list');
  if (!stage || !list) return;
  stage.querySelectorAll('[data-rev-pin]').forEach(function(p) { p.remove(); });
  list.innerHTML = '';
  revPoints.forEach(function(p, i) {
    var pin = document.createElement('div');
    pin.setAttribute('data-rev-pin', p.id);
    pin.style.cssText = 'position:absolute;min-width:26px;height:26px;transform:translate(-50%,-50%);border-radius:50%;background:var(--teal-dark,#006064);color:#fff;border:2px solid #fff;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:800;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,0.25);padding:0;white-space:nowrap;transition:background .15s ease,border-radius .15s ease,padding .15s ease';
    pin.style.left = p.x + '%';
    pin.style.top = p.y + '%';
    pin.textContent = (i + 1);
    pin.addEventListener('click', function() { revM1Reveal(p.id, pin.dataset.revealed !== 'true'); });
    stage.appendChild(pin);
    var row = document.createElement('li');
    row.setAttribute('data-rev-row', p.id);
    row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:10px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:10px 12px;font-size:13.5px';
    row.innerHTML = '<span style="width:22px;height:22px;border-radius:50%;background:var(--teal-dark,#006064);color:#fff;font-size:11px;font-weight:800;display:flex;align-items:center;justify-content:center;flex-shrink:0">' + (i + 1) + '</span><span style="flex:1;font-weight:600;color:var(--text3)">? ? ? ? ? ?</span><button class="btn-action" style="font-size:11.5px;padding:5px 10px">Révéler</button>';
    row.querySelector('button').addEventListener('click', function() { revM1Reveal(p.id, true); });
    list.appendChild(row);
  });
}
function revM1Reveal(id, show) {
  var point = revPoints.find(function(p) { return p.id === id; });
  var pin = document.querySelector('[data-rev-pin="' + id + '"]');
  var row = document.querySelector('[data-rev-row="' + id + '"]');
  if (!point || !pin || !row) return;
  var ans = row.querySelector('span:nth-child(2)');
  var btn = row.querySelector('button');
  if (show) {
    pin.style.background = 'var(--success,#2E7D32)';
    pin.style.borderRadius = '999px';
    pin.style.padding = '4px 12px';
    pin.style.height = 'auto';
    pin.textContent = point.label;
    pin.dataset.revealed = 'true';
    ans.textContent = point.label;
    ans.style.color = 'var(--success,#2E7D32)';
    btn.textContent = 'Cacher';
    btn.onclick = function() { revM1Reveal(id, false); };
  } else {
    pin.style.background = 'var(--teal-dark,#006064)';
    pin.style.borderRadius = '50%';
    pin.style.padding = '0';
    pin.style.height = '26px';
    var idx = revPoints.findIndex(function(p) { return p.id === id; });
    pin.textContent = (idx + 1);
    pin.dataset.revealed = 'false';
    ans.textContent = '? ? ? ? ? ?';
    ans.style.color = 'var(--text3)';
    btn.textContent = 'Révéler';
    btn.onclick = function() { revM1Reveal(id, true); };
  }
  revUpdateBadges();
}
function revM1SetAll(show) {
  revPoints.forEach(function(p) { revM1Reveal(p.id, show); });
}
function revInitM2() {
  var stage = document.getElementById('rev-m2-stage');
  var tray = document.getElementById('rev-m2-tray');
  var scoreEl = document.getElementById('rev-m2-score');
  if (!stage || !tray || !scoreEl) return;
  stage.querySelectorAll('[data-rev-hotspot]').forEach(function(h) { h.remove(); });
  tray.innerHTML = '';
  scoreEl.textContent = '0 / ' + revPoints.length + ' placés';
  revPoints.forEach(function(p) {
    var h = document.createElement('div');
    h.setAttribute('data-rev-hotspot', p.id);
    h.style.cssText = 'position:absolute;min-width:30px;height:30px;transform:translate(-50%,-50%);border-radius:50%;border:2.5px dashed var(--teal,#0097A7);background:rgba(255,255,255,0.5);white-space:nowrap;padding:0';
    h.style.left = p.x + '%';
    h.style.top = p.y + '%';
    stage.appendChild(h);
  });
  revShuffle(revPoints).forEach(function(p) {
    var chip = document.createElement('div');
    chip.setAttribute('data-rev-chip', p.id);
    chip.textContent = p.label;
    chip.style.cssText = 'touch-action:none;cursor:grab;background:var(--surface,#fff);border:1.5px solid var(--teal,#0097A7);color:var(--teal-dark,#006064);font-size:12.5px;font-weight:700;padding:8px 13px;border-radius:999px';
    chip.addEventListener('pointerdown', revM2DragStart);
    tray.appendChild(chip);
  });
}
function revM2DragStart(e) {
  var chip = e.currentTarget;
  var r = chip.getBoundingClientRect();
  revDrag = { chip: chip, offX: e.clientX - r.left, offY: e.clientY - r.top, parent: chip.parentNode, next: chip.nextSibling, w: r.width };
  document.body.appendChild(chip);
  chip.style.position = 'fixed';
  chip.style.zIndex = '9999';
  chip.style.width = revDrag.w + 'px';
  chip.style.cursor = 'grabbing';
  chip.style.boxShadow = '0 8px 24px rgba(0,0,0,0.25)';
  revM2DragMove(e);
  chip.setPointerCapture(e.pointerId);
  chip.addEventListener('pointermove', revM2DragMove);
  chip.addEventListener('pointerup', revM2DragEnd);
  chip.addEventListener('pointercancel', revM2DragEnd);
}
function revM2DragMove(e) {
  if (!revDrag) return;
  revDrag.chip.style.left = (e.clientX - revDrag.offX) + 'px';
  revDrag.chip.style.top = (e.clientY - revDrag.offY) + 'px';
  revM2AutoScroll(e);
}
function revM2AutoScroll(e) {
  if (!revDrag) return;
  var margin = 80, speed = 14, dir = 0;
  if (e.clientY < margin) { dir = -1; }
  else if (e.clientY > window.innerHeight - margin) { dir = 1; }
  revDrag.scrollDir = dir;
  if (dir !== 0 && !revDrag.scrollTimer) {
    revDrag.scrollTimer = setInterval(function() {
      if (!revDrag || !revDrag.scrollDir) return;
      window.scrollBy(0, revDrag.scrollDir * speed);
    }, 16);
  } else if (dir === 0 && revDrag.scrollTimer) {
    clearInterval(revDrag.scrollTimer);
    revDrag.scrollTimer = null;
  }
}
function revM2DragEnd(e) {
  if (!revDrag) return;
  if (revDrag.scrollTimer) { clearInterval(revDrag.scrollTimer); revDrag.scrollTimer = null; }
  var chip = revDrag.chip;
  chip.removeEventListener('pointermove', revM2DragMove);
  chip.removeEventListener('pointerup', revM2DragEnd);
  chip.removeEventListener('pointercancel', revM2DragEnd);
  var stage = document.getElementById('rev-m2-stage');
  var sRect = stage.getBoundingClientRect();
  var px = ((e.clientX - sRect.left) / sRect.width) * 100;
  var py = ((e.clientY - sRect.top) / sRect.height) * 100;
  var nearest = null, nearestDist = Infinity;
  stage.querySelectorAll('[data-rev-hotspot]').forEach(function(h) {
    if (h.dataset.filled === 'true') return;
    var hx = parseFloat(h.style.left), hy = parseFloat(h.style.top);
    var d = Math.hypot(px - hx, py - hy);
    if (d < nearestDist) { nearestDist = d; nearest = h; }
  });
  var placed = false;
  if (nearest && nearestDist <= revTol && nearest.dataset.revHotspot === chip.dataset.revChip) {
    nearest.style.borderStyle = 'solid';
    nearest.style.background = 'var(--success,#2E7D32)';
    nearest.style.borderColor = 'var(--success,#2E7D32)';
    nearest.style.color = '#fff';
    nearest.style.display = 'flex';
    nearest.style.alignItems = 'center';
    nearest.style.justifyContent = 'center';
    nearest.style.fontWeight = '800';
    nearest.style.borderRadius = '999px';
    nearest.style.height = 'auto';
    nearest.style.padding = '4px 12px';
    nearest.style.fontSize = '12px';
    nearest.textContent = chip.textContent;
    nearest.dataset.filled = 'true';
    placed = true;
    var scoreEl = document.getElementById('rev-m2-score');
    var filledCount = document.querySelectorAll('#rev-m2-stage [data-filled="true"]').length;
    scoreEl.textContent = filledCount + ' / ' + revPoints.length + ' placés';
  } else if (nearest && nearestDist <= revTol) {
    nearest.style.borderColor = 'var(--danger,#E57373)';
    nearest.style.background = 'rgba(229,115,115,0.18)';
    setTimeout(function() {
      nearest.style.borderColor = 'var(--teal,#0097A7)';
      nearest.style.background = 'rgba(255,255,255,0.5)';
    }, 450);
  }
  chip.style.position = '';
  chip.style.left = '';
  chip.style.top = '';
  chip.style.width = '';
  chip.style.zIndex = '';
  chip.style.cursor = 'grab';
  chip.style.boxShadow = '';
  revDrag.parent.insertBefore(chip, revDrag.next);
  if (placed) { chip.style.display = 'none'; }
  revDrag = null;
  revUpdateBadges();
}
function revInitM3() {
  var stage = document.getElementById('rev-m3-stage');
  var summary = document.getElementById('rev-m3-summary');
  if (!stage || !summary) return;
  stage.style.display = '';
  stage.querySelectorAll('[data-rev-mark]').forEach(function(m) { m.remove(); });
  summary.style.display = 'none';
  revM3Queue = revShuffle(revPoints);
  revM3Idx = 0;
  revM3Score = 0;
  revM3Locked = false;
  stage.onclick = revM3Click;
  revM3Render();
}
function revM3Render() {
  var stage = document.getElementById('rev-m3-stage');
  var qEl = document.getElementById('rev-m3-question');
  var pEl = document.getElementById('rev-m3-progress');
  if (revM3Idx >= revM3Queue.length) { revM3End(); return; }
  var p = revM3Queue[revM3Idx];
  qEl.innerHTML = 'Où se trouve : <b>' + p.label + '</b> ?';
  pEl.textContent = 'Repère ' + (revM3Idx + 1) + ' / ' + revM3Queue.length;
  pEl.style.cssText = 'font-size:12px;color:var(--text2);font-weight:700';
  pEl.onclick = null;
  stage.querySelectorAll('[data-rev-mark]').forEach(function(m) { m.remove(); });
  var oldBtn = document.getElementById('rev-m3-next-btn');
  if (oldBtn) oldBtn.remove();
  revM3Attempts = 0;
  revM3Locked = false;
}
function revM3Click(e) {
  if (revM3Locked || revM3Idx >= revM3Queue.length) return;
  var stage = document.getElementById('rev-m3-stage');
  var pEl = document.getElementById('rev-m3-progress');
  var qEl = document.getElementById('rev-m3-question');
  var r = stage.getBoundingClientRect();
  var px = ((e.clientX - r.left) / r.width) * 100;
  var py = ((e.clientY - r.top) / r.height) * 100;
  var target = revM3Queue[revM3Idx];
  var dist = Math.hypot(px - target.x, py - target.y);
  stage.querySelectorAll('[data-rev-mark="attempt"]').forEach(function(m) { m.remove(); });
  var mark = document.createElement('div');
  mark.setAttribute('data-rev-mark', 'attempt');
  mark.style.cssText = 'position:absolute;width:30px;height:30px;margin:-15px 0 0 -15px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:14px;color:#fff;pointer-events:none';
  mark.style.left = px + '%';
  mark.style.top = py + '%';
  if (dist <= revTol) {
    mark.style.background = 'var(--success,#2E7D32)';
    mark.textContent = '✓';
    stage.appendChild(mark);
    revM3Score++;
    revM3Locked = true;
    qEl.innerHTML = '<span style="color:var(--success,#2E7D32);font-weight:700">Correct ✓</span>';
    setTimeout(function() { revM3Idx++; revM3Render(); }, 700);
  } else {
    revM3Attempts++;
    mark.style.background = 'var(--danger,#E57373)';
    mark.textContent = '✕';
    stage.appendChild(mark);
    if (revM3Attempts >= revM3MaxAttempts) {
      var tmark = document.createElement('div');
      tmark.setAttribute('data-rev-mark', 'target');
      tmark.style.cssText = 'position:absolute;width:30px;height:30px;margin:-15px 0 0 -15px;border-radius:50%;background:var(--success,#2E7D32);opacity:.55;pointer-events:none';
      tmark.style.left = target.x + '%';
      tmark.style.top = target.y + '%';
      stage.appendChild(tmark);
      revM3Locked = true;
      revM3ShowNextBtn();
    } else {
      pEl.textContent = 'Essai ' + revM3Attempts + ' / ' + revM3MaxAttempts;
    }
  }
}
function revM3ShowNextBtn() {
  var pEl = document.getElementById('rev-m3-progress');
  pEl.textContent = 'Suivant →';
  pEl.style.cssText = 'cursor:pointer;background:#1565C0;color:#fff;font-weight:700;font-size:13px;padding:8px 16px;border-radius:999px;box-shadow:0 2px 8px rgba(0,0,0,0.2)';
  pEl.onclick = function() { revM3Idx++; revM3Render(); };
}
function revM3End() {
  var stage = document.getElementById('rev-m3-stage');
  var summary = document.getElementById('rev-m3-summary');
  stage.style.display = 'none';
  summary.style.display = 'block';
  summary.innerHTML = '<div style="text-align:center;padding:30px 10px"><div style="font-size:34px;font-weight:800;color:var(--teal-dark,#006064)">' + revM3Score + ' / ' + revM3Queue.length + '</div><div style="color:var(--text2);font-size:13.5px;margin-top:6px">repères correctement localisés</div></div>';
  revUpdateBadges();
}

function afficherFormulaireSchema(seanceId) {
  var zone = document.getElementById('schema-form-zone');
  if (!zone) return;
  if (zone.innerHTML) { zone.innerHTML = ''; return; }
  zone.innerHTML =
    '<div style="border:1px solid var(--border);border-radius:12px;padding:16px;margin-bottom:16px">' +
      '<div style="font-size:12px;color:var(--text2);margin-bottom:10px">Sélectionne tous les PNG d\'un coup, puis tous les JSON d\'un coup. Les paires sont reconnues par leur nom de fichier (ex: abdomen.png + abdomen.json).</div>' +
      '<label style="font-size:12px;color:var(--text2);display:block;margin-bottom:4px">Images (PNG, plusieurs possibles)</label>' +
      '<input type="file" id="schema-images-input" accept="image/png,image/jpeg" multiple style="margin-bottom:10px;display:block">' +
      '<label style="font-size:12px;color:var(--text2);display:block;margin-bottom:4px">Fichiers JSON des repères (plusieurs possibles)</label>' +
      '<input type="file" id="schema-jsons-input" accept=".json,application/json" multiple style="margin-bottom:14px;display:block">' +
      '<button class="btn-action" onclick="soumettreSchemas(' + seanceId + ')">Ajouter les schémas</button>' +
      '<div id="schema-form-status" style="font-size:12px;color:var(--text2);margin-top:10px"></div>' +
    '</div>';
}
function baseNameSansExtension(filename) {
  return filename.replace(/\.[^/.]+$/, '');
}
async function soumettreSchemas(seanceId) {
  var imageFiles = Array.from(document.getElementById('schema-images-input').files);
  var jsonFiles = Array.from(document.getElementById('schema-jsons-input').files);
  var statusEl = document.getElementById('schema-form-status');
  if (!imageFiles.length || !jsonFiles.length) { toast('Sélectionne au moins une image et un JSON', 'error'); return; }
  var jsonByName = {};
  jsonFiles.forEach(function(f) { jsonByName[baseNameSansExtension(f.name)] = f; });
  var paires = [];
  var sansJson = [];
  imageFiles.forEach(function(img) {
    var base = baseNameSansExtension(img.name);
    if (jsonByName[base]) { paires.push({ base: base, image: img, json: jsonByName[base] }); }
    else { sansJson.push(img.name); }
  });
  if (!paires.length) { toast('Aucune paire image+JSON trouvée (vérifie que les noms correspondent)', 'error'); return; }
  var reussis = 0, echoues = [];
  for (var i = 0; i < paires.length; i++) {
    var p = paires[i];
    statusEl.textContent = 'Envoi ' + (i+1) + '/' + paires.length + ' : ' + p.base + '...';
    try {
      var jsonText = await p.json.text();
      var parsed = JSON.parse(jsonText);
      var reperes;
      if (Array.isArray(parsed)) reperes = parsed;
      else if (Array.isArray(parsed.reperes)) reperes = parsed.reperes;
      else if (Array.isArray(parsed.labels)) {
        reperes = parsed.labels.map(function(l) { return { id: l.id, label: l.text, x: l.tx, y: l.ty }; });
      } else throw new Error('Format JSON non reconnu');
      var titre = p.base.replace(/[-_]+/g, ' ').trim();
      var fd = new FormData();
      fd.append('image', p.image);
      fd.append('titre', titre);
      fd.append('reperes', JSON.stringify(reperes));
      await api('POST', '/revision/seances/' + seanceId + '/schemas', fd);
      reussis++;
    } catch(e) {
      echoues.push(p.base);
    }
  }
  var msg = reussis + ' schéma(s) ajouté(s)';
  if (sansJson.length) msg += ' — ' + sansJson.length + ' image(s) sans JSON correspondant ignorée(s)';
  if (echoues.length) msg += ' — échecs : ' + echoues.join(', ');
  statusEl.textContent = msg;
  toast(reussis + ' schéma(s) ajouté(s)');
  ouvrirSeance(seanceId);
}
  
async function creerSeance() {
  var titre = await customPrompt('Nom de la séance (ex: CM4 — Anatomie abdominale)');
  if (!titre || !titre.trim()) return;
  try {
    await api('POST', '/revision/seances', { titre: titre.trim(), dossierId: _revisionDossierCourant });
    ouvrirDossier(_revisionDossierCourant);
  } catch(e) {
    toast('Erreur lors de la création', 'error');
  }
}

  
// ── FAVORIS ───────────────────────────────────────────────────────────────────
function getFavoritesKey() { return currentUser ? 'mp_favs_' + currentUser.id : null; }

function loadFavorites() {
  var key = getFavoritesKey();
  var favs = key ? JSON.parse(localStorage.getItem(key) || '[]') : [];
  var list = document.getElementById('favorites-list');
  if (!list) return;
  if (!favs.length) {
    list.innerHTML = '<div style="padding:48px;text-align:center;color:var(--text3)"><div style="font-size:40px;margin-bottom:12px">⭐</div><div>Aucun favori pour l&#39;instant</div></div>';
    return;
  }
  var isAdmin = currentUser?.role === 'admin' || currentUser?.role === 'subadmin';
  list.innerHTML = favs.map(function(f) {
    return buildFileRow(f, isAdmin,
      'openPreviewById(this)" data-fileid="' + f.id + '" data-type="' + f.type + '" data-basepath="/api/folders/' + (f.folderId||0) + '/files/' + f.id,
      '/api/folders/' + (f.folderId||0) + '/files/' + f.id,
      null, null, f.folderId, f.subId
    );
  }).join('');
}

function toggleFavorite(e, fileObj) {
  if (e) e.stopPropagation();
  var key = getFavoritesKey();
  if (!key) return;
  var favs = JSON.parse(localStorage.getItem(key) || '[]');
  var idx = favs.findIndex(function(f) { return f.id === fileObj.id; });
  if (idx >= 0) {
    favs.splice(idx, 1);
    toast('Retiré des favoris');
  } else {
    favs.push(fileObj);
    toast('Ajouté aux favoris ⭐');
  }
  localStorage.setItem(key, JSON.stringify(favs));
  var isFav = idx < 0; // after toggle: if was found (idx>=0) it's now removed, else added
  document.querySelectorAll('.btn-favorite[data-id="' + fileObj.id + '"]').forEach(function(btn) {
    if (isFav) {
      btn.classList.add('active');
      var svg = btn.querySelector('svg');
      if (svg) { svg.setAttribute('fill', 'currentColor'); }
    } else {
      btn.classList.remove('active');
      var svg = btn.querySelector('svg');
      if (svg) { svg.setAttribute('fill', 'none'); }
    }
  });
}

// ── RÉGLAGES ──────────────────────────────────────────────────────────────────
async function saveSettings() {
  try {
    var name = document.getElementById('settings-name')?.value?.trim();
    var discord = document.getElementById('settings-discord')?.value?.trim();
    if (!name) { toast('Nom requis', 'error'); return; }
    await api('PATCH', '/users/' + currentUser.id, { name, discord });
    currentUser.name = name;
    currentUser.discord = discord;
    toast('Réglages sauvegardés ✅');
  } catch(e) { toast(e.message, 'error'); }
}

async function saveAvatar() {
  var input = document.getElementById('avatar-input');
  if (!input || !input.files[0]) return;
  var reader = new FileReader();
  reader.onload = async function() {
    try {
      await api('POST', '/avatar', { avatar: reader.result });
      currentUser.avatar = reader.result;
      toast('Photo mise à jour ✅');
      updateAvatarPreview();
    } catch(e) { toast(e.message, 'error'); }
  };
  reader.readAsDataURL(input.files[0]);
}

// ── CODES D'INVITATION ────────────────────────────────────────────────────────
function switchCodesTab(tab) {
  // tab is 'available' or 'used'
  var listBody = document.getElementById('codes-list-body');
  var tabAvail = document.getElementById('tab-available');
  var tabUsed = document.getElementById('tab-used');
  // Visual active state on buttons
  if (tabAvail) { tabAvail.style.background = tab === 'available' ? 'var(--teal-dark)' : 'transparent'; tabAvail.style.color = tab === 'available' ? 'white' : 'var(--text2)'; }
  if (tabUsed) { tabUsed.style.background = tab === 'used' ? 'var(--teal-dark)' : 'transparent'; tabUsed.style.color = tab === 'used' ? 'white' : 'var(--text2)'; }
  // Reload codes filtered by tab
  if (listBody) loadCodes(tab);
}

function toggleDarkMode() {
  var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  var newDark = !isDark;
  document.documentElement.setAttribute('data-theme', newDark ? 'dark' : '');
  localStorage.setItem('mp_dark_mode', newDark ? '1' : '0');
  var icon = document.getElementById('dark-mode-icon');
  var label = document.getElementById('dark-mode-label');
  if (icon) icon.textContent = newDark ? '☀️' : '🌙';
  if (label) label.textContent = newDark ? 'Mode clair' : 'Mode sombre';
}

// Mode sombre par défaut — respecte le choix manuel si existant
(function() {
  var saved = localStorage.getItem('mp_dark_mode');
  if (saved === '0') {
    document.documentElement.setAttribute('data-theme', '');
  } else {
    // Par défaut : toujours sombre (sauf si l'utilisateur a explicitement choisi le mode clair)
    document.documentElement.setAttribute('data-theme', 'dark');
    var icon = document.getElementById('dark-mode-icon');
    var label = document.getElementById('dark-mode-label');
    if (icon) icon.textContent = '☀️';
    if (label) label.textContent = 'Mode clair';
  }
})();

// Suppression du mode auto par intervalle — le mode sombre est maintenant par défaut

function copyInviteCode(code, btn) {
  var msg = "Salut ! Tu es invité(e) à rejoindre MasterPASS, la plateforme de cours créée spécialement pour vous aider en PASS.\n\nVoici ton code d'invitation personnel (valable une seule fois) :\n\n" + code + "\n\nRends-toi sur https://masterpass-production.up.railway.app\nClique sur \"Créer mon compte avec un code d'invitation\" et entre ce code.\n\nC'est parti ! 🚀";
  navigator.clipboard.writeText(msg).then(function(){
    toast('Message copié ! 📋');
    if (btn) {
      var orig = btn.textContent;
      btn.textContent = 'Copié !';
      btn.style.background = '#2E7D32';
      btn.style.color = 'white';
      btn.style.borderColor = '#2E7D32';
    }
  }).catch(function(){ toast(msg, 'info'); });
}

async function loadCodes(tab) {
  tab = tab || 'available';
  try {
    var codes = await api('GET', '/invite-codes');
    var users = [];
    try { users = await api('GET', '/users'); } catch(e) {}
    var listBody = document.getElementById('codes-list-body');
    if (!listBody) return;
    var listAvail = listBody;
    var listUsed = listBody;
    if (!codes.length) {
      if (listAvail) listAvail.innerHTML = '<div style="padding:20px;color:var(--text3)">Aucun code disponible</div>';
      if (listUsed) listUsed.innerHTML = '<div style="padding:20px;color:var(--text3)">Aucun code utilisé</div>';
      return;
    }
    var available = codes.filter(function(c) { return !c.usedBy; });
    var used = codes.filter(function(c) { return c.usedBy; });
    

    var showAvail = tab === 'available';
    var codesHtml = '';
    if (showAvail && available.length) {
      codesHtml += available.map(function(c) {
        return '<div style="display:flex;align-items:center;gap:12px;padding:12px 18px;background:transparent;border-bottom:1px solid var(--border)">' +
          '<code style="flex:1;font-size:15px;font-weight:800;color:var(--teal-dark);letter-spacing:1px">' + c.code + '</code>' +
          '<button data-code="' + c.code + '" onclick="copyInviteCode(this.dataset.code,this)" style="padding:5px 12px;border-radius:7px;border:1.5px solid var(--teal);background:transparent;color:var(--teal-dark);cursor:pointer;font-size:11px;font-weight:600;font-family:Inter,sans-serif">Copier</button>' +
          '<button data-code="' + c.code + '" onclick="deleteCode(this.dataset.code)" style="background:none;border:none;color:var(--danger);cursor:pointer;font-size:16px">🗑</button>' +
          '</div>';
      }).join('');
    }
    if (!showAvail && used.length) {
      codesHtml += used.map(function(c) {
        var usedDate = c.usedAt ? new Date(c.usedAt).toLocaleDateString('fr-FR') : '';
        var usedUser = c.usedBy ? (users.find(function(u){return u.login===c.usedBy||u.id===c.usedBy;})||{name:c.usedBy}).name : '';
        return '<div style="display:flex;align-items:center;gap:12px;padding:12px 18px;background:transparent;border-bottom:1px solid var(--border);opacity:0.6">' +
          '<code style="flex:1;font-size:14px;font-weight:700;color:var(--text3)">' + c.code + '</code>' +
          '<span style="font-size:11px;color:var(--text3)">✅ ' + usedDate + (usedUser ? ' · ' + usedUser : '') + '</span>' +
          '<button data-code="' + c.code + '" onclick="deleteCode(this.dataset.code)" style="background:none;border:none;color:var(--danger);cursor:pointer;font-size:16px">🗑</button>' +
          '</div>';
      }).join('');
    }
    if (!codesHtml) codesHtml = '<div style="padding:20px;color:var(--text3)">Aucun code ' + (showAvail ? 'disponible' : 'utilisé') + '</div>';
    listBody.innerHTML = codesHtml;
    var ba = document.getElementById('badge-available');
    var bu = document.getElementById('badge-used');
    if (ba) ba.textContent = available.length;
    if (bu) bu.textContent = used.length;
  } catch(e) { toast(e.message, 'error'); }
}

async function generateCodes() { return generateCode(); }

async function generateCode() {
  try {
    var res = await api('POST', '/invite-codes/generate');
    // Server returns array of codes
    var code = Array.isArray(res) ? res[0].code : res.code;
    toast('Code créé : ' + code);
    loadCodes();
  } catch(e) { toast(e.message, 'error'); }
}

async function deleteCode(code) {
  if (!await customConfirm('Supprimer ce code ?')) return;
  try {
    await api('DELETE', '/invite-codes/' + code);
    loadCodes();
  } catch(e) { toast(e.message, 'error'); }
}

// ── EXPORT CSV ────────────────────────────────────────────────────────────────
async function exportCSV() {
  try {
    var users = await api('GET', '/users');
    var rows = [['Nom', 'Identifiant', 'Email', 'Mineure', 'Discord', 'Rôle', 'Inscrit le']];
    users.forEach(function(u) {
      rows.push([u.name, u.login, u.email||'', u.mineure||'', u.discord||'', u.role, u.registeredAt ? new Date(u.registeredAt).toLocaleDateString('fr-FR') : '']);
    });
    var csv = rows.map(function(r) { return r.map(function(c) { return '"' + String(c).replace(/"/g, '""') + '"'; }).join(','); }).join('\n');
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = 'etudiants.csv'; a.click();
    URL.revokeObjectURL(url);
  } catch(e) { toast(e.message, 'error'); }
}

// ── UPLOAD SOUS-DOSSIER ───────────────────────────────────────────────────────
async function uploadSubfolderFiles(files, subId, parentId) {
  if (!files || !files.length) return;
  toast('Upload en cours...');
  for (var i = 0; i < files.length; i++) {
    var fd = new FormData();
    fd.append('files', files[i]);
    try {
      await fetch('/api/folders/' + parentId + '/subfolders/' + subId + '/files', {
        method: 'POST', body: fd, credentials: 'include'
      });
    } catch(e) { toast('Erreur: ' + e.message, 'error'); }
  }
  toast('Upload terminé ✅');
  loadSubfolderFiles(parentId, subId);
}

// ── DOSSIERS ──────────────────────────────────────────────────────────────────
async function renameFolder(id) {
  var name = await customPrompt('Nouveau nom :');
  if (!name) return;
  try {
    await api('PATCH', '/folders/' + id, { name });
    loadFolders();
  } catch(e) { toast(e.message, 'error'); }
}

async function moveFolder(id) {
  toast('Fonctionnalité de déplacement disponible depuis la vue dossiers', 'info');
}

// ── LECTURE FICHIERS ──────────────────────────────────────────────────────────
function getReadKey() { return currentUser ? 'mp_read_' + currentUser.id : null; }

function isFavorite(fileId) {
  var key = getFavoritesKey();
  if (!key) return false;
  var favs = JSON.parse(localStorage.getItem(key) || '[]');
  return favs.some(function(f) { return f.id == fileId; });
}

function isFileRead(fileId) {
  var key = getReadKey();
  if (!key) return false;
  var read = JSON.parse(localStorage.getItem(key) || '{}');
  return !!read[String(fileId)];
}

function markAsRead(fileId) { markRead(fileId); }

function markRead(fileId) {
  var key = getReadKey();
  if (!key) return;
  var read = JSON.parse(localStorage.getItem(key) || '{}');
  read[String(fileId)] = true;
  localStorage.setItem(key, JSON.stringify(read));
}

// ── ANNONCES ──────────────────────────────────────────────────────────────────
async function postAnnouncement() {
  var text = document.getElementById('announcement-text')?.value?.trim();
  if (!text) { toast('Message requis', 'error'); return; }
  try {
    await api('POST', '/announcements', { message: text });
    document.getElementById('announcement-text').value = '';
    loadAnnouncements();
    toast('Annonce publiée ✅');
  } catch(e) { toast(e.message, 'error'); }
}

// ── TRI ───────────────────────────────────────────────────────────────────────
function applySort() {
  if (currentSubfolder) {
    loadSubfolderFiles(currentFolder.id, currentSubfolder.id);
  } else if (currentFolder) {
    loadFiles();
  }
}

function toggleSortMenu(e, btn) {
  e.stopPropagation();
  var menu = document.getElementById('sort-dropdown');
  if (!menu) return;
  if (menu.style.display !== 'none') { menu.style.display = 'none'; return; }
  var rect = btn.getBoundingClientRect();
  var menuWidth = 190;
  var left = rect.right - menuWidth;
  if (left < 8) left = 8;
  var top = rect.bottom + 4;
  if (top + 260 > window.innerHeight) top = rect.top - 264;
  menu.style.left = Math.round(left) + 'px';
  menu.style.top = Math.round(top) + 'px';
  menu.style.display = 'block';
  var labels = {'date-desc':'📅 Plus récent','date-asc':'📅 Plus ancien','name-asc':'🔤 A → Z','name-desc':'🔤 Z → A','size-desc':'📦 Plus lourd','size-asc':'📦 Plus léger'};
  menu.querySelectorAll('.sort-item').forEach(function(el) {
    el.classList.toggle('active', el.textContent.trim() === (labels[_currentSort]||''));
  });
  setTimeout(function() { document.addEventListener('click', function() { menu.style.display = 'none'; }, { once: true }); }, 10);
}

function setSortMenu(s, label) {
  var menu = document.getElementById('sort-dropdown');
  if (menu) menu.style.display = 'none';
  var lbl = document.getElementById('sort-label');
  if (lbl) lbl.textContent = label.replace(/^[^\s]+ /,'');
  setSort(s);
}

async function loadFolders(){
  const grid=$('folders-grid');
  grid.innerHTML='<div class="empty-state" style="grid-column:1/-1"><div class="empty-state-title">Chargement…</div></div>';
  try{const folders=await api('GET','/folders');renderFolders(folders);}
  catch(e){grid.innerHTML='<div class="empty-state" style="grid-column:1/-1"><div class="empty-state-title">Erreur de chargement</div></div>';}
}

function renderFolders(folders){
  const grid=$('folders-grid'),isAdmin=currentUser?.role==='admin';
  $('folder-count-sub').textContent=`${folders.length} dossier${folders.length!==1?'s':''}`;
  if(!folders.length){
    grid.innerHTML=`<div class="empty-state" style="grid-column:1/-1">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>
      <div class="empty-state-title">Aucun dossier</div>
      <div class="empty-state-sub">${isAdmin?'Créez votre premier dossier.':'Aucun dossier disponible pour le moment.'}</div>
    </div>`;return;
  }
  grid.innerHTML=folders.map(f=>`
    <div class="folder-card" draggable="${isAdmin?'true':'false'}" data-folder-id="${f.id}"
      onclick="openFolder(${f.id},'${f.name.replace(/'/g,"\\'")}' )"
      ondragstart="dragFolderStart(event,${f.id})"
      ondragover="dragFolderOver(event)"
      ondrop="dragFolderDrop(event,${f.id})"
      ondragend="dragFolderEnd(event)">
      ${isAdmin?`<div class="folder-actions">
        <button class="icon-btn" onclick="event.stopPropagation();openMoveFolderModal(${f.id},'${f.name.replace(/'/g,'')}')" title="Déplacer" style="font-size:13px">📁→</button>
        <button class="icon-btn" onclick="event.stopPropagation();deleteFolder(${f.id})" title="Supprimer"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg></button></div>`:''}
      <div class="folder-card-inner">
        <div class="folder-icon-wrap">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>
        </div>
        <div class="folder-name">${f.name}</div>
        <div class="folder-meta">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M6 2c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6H6zm7 7V3.5L18.5 9H13z"/></svg>
          ${f.fileCount} fichier${f.fileCount!==1?'s':''}${f.totalSize>0?' · '+formatSize(f.totalSize):''}
        </div>
      </div>
    </div>`).join('');
}

function backToRoot(){
  currentFolder=null;
  $('view-folders').style.display='block';
  $('view-files').style.display='none';
  const dp2 = document.getElementById('discussion-panel'); if(dp2) dp2.style.display='none';
  $('topbar-title').textContent='Espace documentaire';
  const topbarEl = document.querySelector('.topbar');
  if(topbarEl) topbarEl.style.display = 'flex';
  // Réafficher le banner étudiant et les stats à la racine
  const isAnyAdmin = currentUser?.role==='admin'||currentUser?.role==='subadmin';
  const _isAnyAdmin = currentUser?.role === 'admin' || currentUser?.role === 'subadmin';
  if($('student-banner') && !_isAnyAdmin && $('dashboard-view').style.display !== 'block') $('student-banner').style.display='flex';
  if($('admin-stats')) $('admin-stats').style.display='none';
  const wrap = document.getElementById('folder-page-title-wrap');
if(wrap) wrap.style.display='none';
  updateBreadcrumb();loadFolders();updateTopbar();
}
function goBack() {
  // Si on est dans un sous-dossier → retour au dossier parent
  if (currentSubfolder) {
    openFolder(currentFolder.id, currentFolder.name);
  } else {
    backToRoot();
  }
}
async function loadSubfolders(folderId) {
  try {
    return await api('GET', '/folders/' + folderId + '/subfolders');
  } catch(e) {
    return [];
  }
}

async function openFolder(id,name){
  currentSubfolder = null;
  currentFolder={id,name};
  saveNavState('lastFolder', { id, name });
  clearNavState('lastFileScroll');
  $('view-folders').style.display='none';
  $('view-files').style.display='block';
  // Mettre le nom du dossier dans la topbar
  $('topbar-title').textContent='';
  // Afficher le titre en grand dans la page
  const folderTitle = document.getElementById('folder-page-title');
  const wrap = document.getElementById('folder-page-title-wrap');
if(wrap){ wrap.style.display='flex'; }
if(folderTitle){ folderTitle.textContent=name; }
const backBtn = document.getElementById('btn-back-folder');
if(backBtn) backBtn.style.display='flex';
  // Masquer le banner étudiant et les stats
  if($('student-banner')) $('student-banner').style.display='none';
  if($('admin-stats')) $('admin-stats').style.display='none';
  // Vider le container de sous-dossiers AVANT de charger les nouveaux
  const subContainerOld = document.getElementById('subfolders-container');
  if(subContainerOld) subContainerOld.innerHTML = '';
  updateBreadcrumb();updateTopbar();
  // Load subfolders and files
  const [subs] = await Promise.all([loadSubfolders(id), loadFiles()]);
  // Inject subfolders above the file table
  const subHtml = renderSubfolders(subs, id, name);
  const container = $('view-files');
  let subContainer = document.getElementById('subfolders-container');
  if (!subContainer) {
    subContainer = document.createElement('div');
    subContainer.id = 'subfolders-container';
    // Insert after folder-page-title
    const wrap = document.getElementById('folder-page-title-wrap');
    const insertAfter = wrap || document.getElementById('folder-page-title');
    if(insertAfter && insertAfter.nextSibling) {
      container.insertBefore(subContainer, insertAfter.nextSibling);
    } else {
      container.appendChild(subContainer);
    }
  }
  subContainer.innerHTML = subHtml;
}

async function createFolder(){
  const name=$('folder-name-input').value.trim();if(!name)return;
  const btn=$('btn-create-folder');btn.disabled=true;btn.textContent='Création…';
  try{await api('POST','/folders',{name});$('folder-name-input').value='';closeModal('modal-folder');await loadFolders();loadStats();toast('Dossier créé avec succès');}
  catch(e){toast(e.message,'error');}finally{btn.disabled=false;btn.textContent='Créer le dossier';}
}
async function deleteFolder(id){
  if(!await customConfirm('Supprimer ce dossier et tous ses fichiers ?'))return;
  try{await api('DELETE','/folders/'+id);await loadFolders();loadStats();toast('Dossier supprimé');}
  catch(e){toast(e.message,'error');}
}

async function loadFiles(){
  const container=document.getElementById('files-list-body');
  if(container) container.innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-title">Chargement…</div></div>';
  try{const files=await api('GET',`/folders/${currentFolder.id}/files`);renderFilesSorted(files);
    const savedScroll = loadNavState('lastFileScroll');
    if (savedScroll) {
      setTimeout(() => { const el = document.getElementById('files-list-body'); if (el) el.scrollTop = savedScroll.top; }, 100);
    }
    clearNavState('lastFileScroll');
  }
  catch(e){if(container) container.innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-title">Erreur de chargement</div></div>';}
}

function getVideoIcon(){return '<svg viewBox="0 0 24 24" fill="currentColor" style="width:14px;height:14px"><path d="M8 5v14l11-7z"/></svg>';}

function getFileTypeBadge(type){
  const icons={
    pdf:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 2H8c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-8.5 7.5c0 .83-.67 1.5-1.5 1.5H9v2H7.5V7H10c.83 0 1.5.67 1.5 1.5v1zm5 2c0 .83-.67 1.5-1.5 1.5h-2.5V7H15c.83 0 1.5.67 1.5 1.5v3zm4-3H19v1h1.5V11H19v2h-1.5V7h3v1.5zM9 9.5h1v-1H9v1zM4 6H2v14c0 1.1.9 2 2 2h14v-2H4V6zm10 5.5h1v-3h-1v3z"/></svg><span>PDF</span>`,
    doc:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zM6 20V4h7v5h5v11H6z"/></svg><span>DOC</span>`,
    xls:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2v7zm4 0h-2V7h2v10zm4 0h-2v-4h2v4z"/></svg><span>XLS</span>`,
    ppt:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 6h-2v2h2v2h-2v2H10v-2H8v-2h2v-2H8V7h2V5h2v2h2v2z"/></svg><span>PPT</span>`,
    img:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg><span>IMG</span>`,
    video:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M17 10.5V7c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4z"/></svg><span>VID</span>`,
    audio:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z"/></svg><span>SON</span>`,
    zip:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 6h-2.18c.07-.33.18-.65.18-1 0-2.21-1.79-4-4-4s-4 1.79-4 4c0 .35.11.67.18 1H6c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/></svg><span>ZIP</span>`,
    other:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M6 2c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6H6zm7 7V3.5L18.5 9H13z"/></svg><span>FIC</span>`,
  };
  return `<div class="file-type-badge badge-${type}">${icons[type]||icons.other}</div>`;
}

function buildFileRow(f, isAdmin, previewFn, downloadBasePath, toggleFn, deleteFn, folderId, subId){
  folderId = folderId || (currentFolder ? currentFolder.id : '');
  subId = subId || (currentFolder ? currentFolder.subId : '');
  const dlAllowed = f.downloadable !== false;
  const canPreview = ['pdf','img','video','audio'].includes(f.type);
  const isVideo = f.type === 'video';
  const canDownload = isAdmin ? true : (!isVideo && dlAllowed);
  const downloadUrl = downloadBasePath ? downloadBasePath + '/download' : '';

  const downloadBtn = canDownload
    ? `<a class="btn-download" href="${downloadBasePath}/download">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg>Télécharger</a>`
    : (!isAdmin
        ? isVideo
          ? `<span class="dl-locked"><svg viewBox="0 0 24 24" fill="currentColor" style="width:12px;height:12px"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>Visionnage uniquement</span>`
          : `<span class="dl-locked"><svg viewBox="0 0 24 24" fill="currentColor" style="width:12px;height:12px"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>Non disponible</span>`
        : '');

  const toggleBtn = isAdmin
    ? `<button class="btn-toggle-dl ${dlAllowed?'allowed':'blocked'}" onclick="${toggleFn}" title="${dlAllowed?'Bloquer':'Autoriser'}">
        <svg viewBox="0 0 24 24" fill="currentColor" style="width:11px;height:11px">${dlAllowed?'<path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/>':'<path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>'}
        </svg>${dlAllowed?'✅ Autorisé':'🔒 Bloqué'}</button>` : '';

  const deleteBtn = isAdmin
    ? `<button class="btn-delete" onclick="${deleteFn}">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>Supprimer</button>` : '';

  const fileIsRead = isFileRead(f.id, folderId, subId);
  return `<div class="file-row${fileIsRead ? ' is-read' : ''}" data-file-id="${f.id}" data-subfolder="${subId||''}" ${canPreview ? `onclick="${previewFn}" style="cursor:pointer"` : ''}>    <div class="file-left" style="display:flex;align-items:center;gap:10px">
      <input type="checkbox" class="file-select-cb" data-id="${f.id}" data-download-url="${downloadUrl}" data-can-download="${canDownload}" onclick="event.stopPropagation()" onchange="onFileCheckboxChange()" style="display:none;width:18px;height:18px;cursor:pointer;accent-color:var(--teal);flex-shrink:0">
      ${getFileTypeBadge(f.type)}
      <div class="file-info">
        <div class="file-name" title="${f.name}">${f.name}${fileIsRead ? '<span class="file-read-badge">✓ Lu</span>' : ''}${(function(){ const added = f.addedAt ? new Date(f.addedAt) : null; const isNew = added && (Date.now() - added.getTime()) < 7 * 24 * 60 * 60 * 1000; return isNew ? '<span style="margin-left:6px;background:linear-gradient(135deg,var(--teal),var(--teal-dark));color:white;border-radius:6px;padding:2px 7px;font-size:9px;font-weight:700;letter-spacing:0.5px;vertical-align:middle">NOUVEAU</span>' : ''; })()}</div>
        <div class="file-meta-row">
          ${isAdmin && f.views ? `<span class="file-meta-pill" style="color:var(--teal-dark);font-weight:600">👁 ${f.views} vue${f.views > 1 ? 's' : ''}</span><span class="file-meta-pill" style="color:var(--teal-light)">·</span>` : ''}
          <span class="file-meta-pill"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 6h-2.18c.07-.33.18-.65.18-1a2 2 0 0 0-4 0c0 .35.11.67.18 1H4v2h.18l2 9.91C6.37 18.79 7.2 19.5 8 19.5c.53 0 1-.39 1-.89V19h6v.61c0 .5.47.89 1 .89.8 0 1.63-.71 1.82-1.59L19.82 8H20V6zM12 2a1 1 0 0 1 1 1 1 1 0 0 1-1 1 1 1 0 0 1-1-1 1 1 0 0 1 1-1z"/></svg>${formatSize(f.size)}</span>
          <span class="file-meta-pill" style="color:var(--teal-light)">·</span>
          <span class="file-meta-pill"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67V7z"/></svg>${f.addedAt}</span>
        </div>
      </div>
    </div>
    <div class="file-actions-cell">
      <button onclick="event.stopPropagation();openDiscussion('${f.id}','${f.name.replace(/'/g,String.fromCharCode(39))}')"
        id="disc-btn-${f.id}"
        style="display:flex;align-items:center;gap:5px;padding:6px 12px;border-radius:8px;border:1.5px solid var(--border);background:transparent;color:var(--text2);cursor:pointer;font-size:12px;font-weight:500;font-family:'Inter',sans-serif;white-space:nowrap;position:relative">
        <svg viewBox="0 0 24 24" fill="currentColor" style="width:13px;height:13px"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg>
        Discussion
        <span id="disc-badge-${f.id}" style="display:none;position:absolute;top:-4px;right:-4px;background:#ef5350;color:white;border-radius:10px;padding:1px 5px;font-size:9px;font-weight:700;min-width:14px;text-align:center;line-height:14px"></span>
      </button>
      <button class="btn-favorite ${isFavorite(f.id, folderId, subId) ? 'active' : ''}" data-id="${f.id}"
        onclick="event.stopPropagation();toggleFavorite(event, ${JSON.stringify({id:f.id,name:f.name,type:f.type,size:f.size,addedAt:f.addedAt}).replace(/"/g,'&quot;')}, '${folderId}', '${subId || ''}')"
        title="${isFavorite(f.id, folderId, subId) ? 'Retirer des favoris' : 'Ajouter aux favoris'}">
        <svg viewBox="0 0 24 24" fill="${isFavorite(f.id, folderId, subId) ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2">
          <path d="M12 17.27L18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z"/>
        </svg>
      </button>
      <div style="display:flex;align-items:center;gap:6px;flex-shrink:0">
        ${isAdmin ? `<button onclick="event.stopPropagation();${toggleFn}" title="${dlAllowed ? 'Bloquer le téléchargement' : 'Autoriser le téléchargement'}"
          style="display:flex;align-items:center;gap:4px;padding:5px 10px;border-radius:8px;border:1.5px solid ${dlAllowed ? 'rgba(46,125,50,0.3)' : 'rgba(229,115,115,0.3)'};background:${dlAllowed ? 'rgba(46,125,50,0.06)' : 'rgba(229,115,115,0.06)'};color:${dlAllowed ? '#2E7D32' : 'var(--danger)'};cursor:pointer;font-size:11px;font-weight:600;font-family:Inter,sans-serif;white-space:nowrap">
          ${dlAllowed ? '✅ DL on' : '🔒 DL off'}</button>` : ''}
        <div style="position:relative">
        <button class="file-menu-btn" data-menu="menu-${f.id}" onclick="event.stopPropagation();toggleFileMenu(event,this)" title="Actions">⋮</button>
        <div id="menu-${f.id}" class="file-action-menu">

          ${canDownload && downloadUrl ? `<div class="file-action-item" onclick="closeAllFileMenus();window.location.href='${downloadUrl}'">⬇️ Télécharger</div>` : ''}
          ${isAdmin ? `<div class="file-action-item" onclick="closeAllFileMenus();openFileModal(event,${f.id},'${f.name.replace(/'/g,'\'').replace(/"/g,'')}','${folderId}','${subId||''}')">✏️ Renommer / Déplacer</div>` : ''}

          ${isAdmin ? `<div class="file-action-item danger" onclick="closeAllFileMenus();${deleteFn}">🗑 Supprimer</div>` : ''}
        </div>
        </div>
      </div>
    </div>
  </div>`;
}

let _currentSort = 'date-desc';

function setSort(val) {
  _currentSort = val;
  // Re-render current files with new sort
  if (currentSubfolder) {
    loadSubfolderFiles(currentFolder.id, currentSubfolder.id);
  } else if (currentFolder) {
    loadFiles();
  }
}

function sortFiles(files, sort) {
  var arr = files ? files.slice() : [];
  if (sort === 'date-desc') arr.sort(function(a,b){ return new Date(b.uploadedAt||0) - new Date(a.uploadedAt||0); });
  else if (sort === 'date-asc') arr.sort(function(a,b){ return new Date(a.uploadedAt||0) - new Date(b.uploadedAt||0); });
  else if (sort === 'name-asc') arr.sort(function(a,b){ return a.name.localeCompare(b.name); });
  else if (sort === 'name-desc') arr.sort(function(a,b){ return b.name.localeCompare(a.name); });
  else if (sort === 'size-desc') arr.sort(function(a,b){ return (b.size||0) - (a.size||0); });
  else if (sort === 'size-asc') arr.sort(function(a,b){ return (a.size||0) - (b.size||0); });
  return arr;
}

function updateFolderProgress(files) {
  // Update progress bar for folder reading
  if (!currentUser || !files || !files.length) return;
  var key = 'mp_read_' + currentUser.id;
  var read = JSON.parse(localStorage.getItem(key) || '{}');
  var count = files.filter(function(f) { return read[f.id]; }).length;
  var bar = document.getElementById('folder-progress-bar');
  if (!bar) return;
  if (count === 0) { bar.style.display = 'none'; return; }
  var pct = Math.round(count / files.length * 100);
  bar.style.display = 'block';
  bar.innerHTML = '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">' +
    '<div style="flex:1;height:6px;background:var(--border);border-radius:99px;overflow:hidden">' +
    '<div style="height:100%;width:' + pct + '%;background:var(--teal);border-radius:99px;transition:width 0.3s"></div></div>' +
    '<span style="font-size:12px;color:var(--text3);white-space:nowrap">' + count + '/' + files.length + ' lus</span></div>';
}

function renderFilesSorted(files) {
  // Apply current sort then render
  var sorted = sortFiles(files, _currentSort || 'date-desc');
  renderFiles(sorted);
}

function renderFiles(files){
  currentFiles = files;
  const isAdmin=currentUser?.role==='admin';
  const container = document.getElementById('files-list-body');
  if($('files-count-sub')) $('files-count-sub').textContent=`${files.length} fichier${files.length!==1?'s':''}`;
  $('files-count-tag').textContent=files.length;
  // Afficher/masquer la barre de tri
  const sortBar = document.getElementById('sort-bar');
  if (sortBar) sortBar.style.display = files.length > 0 ? 'flex' : 'none';
  // Mettre à jour la barre de progression du dossier
  updateFolderProgress(files);
  // Charger les badges de discussion non lus
  if (files.length) {
    const validFileIds = (files||[]).filter(f => f && f.id).map(f => String(f.id));
    if (validFileIds.length) setTimeout(() => updateDiscussionBadges(validFileIds), 300);
  }
  if(!files.length){
    if(container) container.innerHTML=`<div class="empty-state" style="padding:40px">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M6 2c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6H6zm7 7V3.5L18.5 9H13z"/></svg>
      <div class="empty-state-title">Aucun fichier</div>
      <div class="empty-state-sub">${isAdmin?'Déposez des fichiers dans ce dossier.':'Aucun fichier disponible pour le moment.'}</div>
    </div>`;
    // Also clear legacy tbody if present
    const tbody=$('files-tbody');
    if(tbody) tbody.innerHTML='';
    return;
  }
  const html = files.map(f=>buildFileRow(
    f, isAdmin,
    `openPreviewById(this)" data-fileid="${f.id}" data-type="${f.type}`,
    `/api/folders/${currentFolder.id}/files/${f.id}`,
    `toggleDownload(${f.id})`,
    `deleteFile(${f.id})`
  )).join('');
  if(container) {
    container.innerHTML = html;
    container.querySelectorAll('.file-row').forEach(function(card) {
      var id = card.getAttribute('data-file-id');
      var timer = null; var startX = 0; var startY = 0; var longPressed = false;
      card.addEventListener('touchstart', function(e) {
        startX = e.touches[0].clientX; startY = e.touches[0].clientY; longPressed = false;
        timer = setTimeout(function() { longPressed = true; if (navigator.vibrate) navigator.vibrate(50); enterFileSelectionMode(id); }, 500);
      }, { passive: true });
      card.addEventListener('touchmove', function(e) {
        if (Math.abs(e.touches[0].clientX-startX) > 10 || Math.abs(e.touches[0].clientY-startY) > 10) clearTimeout(timer);
      }, { passive: true });
      card.addEventListener('touchend', function(e) { clearTimeout(timer); if (longPressed) { longPressed = false; e.preventDefault(); e.stopPropagation(); } });
      card.addEventListener('mousedown', function() { longPressed = false; timer = setTimeout(function() { longPressed = true; enterFileSelectionMode(id); }, 600); });
      card.addEventListener('mouseup', function() { clearTimeout(timer); });
      card.addEventListener('mouseleave', function() { clearTimeout(timer); });
    });
  }
  // Keep legacy tbody empty (hidden)
  const tbody=$('files-tbody');
  if(tbody) tbody.innerHTML='';
}

function handleFileSelect(e){
  const files = Array.from(e.target.files);
  if (currentSubfolder) {
    uploadSubfolderFiles(files, currentSubfolder.id, currentSubfolder.parentId);
  } else {
    uploadFiles(files);
  }
  e.target.value='';
}
function onDragOver(e){e.preventDefault();e.currentTarget.classList.add('dragover');}
function onDragLeave(e){e.currentTarget.classList.remove('dragover');}
function onDrop(e){
  e.preventDefault();
  e.currentTarget.classList.remove('dragover');
  const files = Array.from(e.dataTransfer.files);
  if (currentSubfolder) {
    uploadSubfolderFiles(files, currentSubfolder.id, currentSubfolder.parentId);
  } else {
    uploadFiles(files);
  }
}

async function uploadFiles(files){
  if(!currentFolder||!files.length)return;
  const prog=$('upload-progress'),bar=$('progress-bar'),label=$('progress-label');
  prog.style.display='block';
  bar.style.width='5%';
  let uploaded=0;
  for(const file of files){
    label.textContent=`Envoi de "${file.name}" (${formatSize(file.size)})...`;
    try{
      if(file.size > 40*1024*1024){
        // Gros fichier : upload direct navigateur -> R2
        const presign=await api('POST',`/folders/${currentFolder.id}/presign`,{filename:file.name,contentType:file.type||'application/octet-stream',size:file.size});
        await new Promise((resolve,reject)=>{
          const xhr=new XMLHttpRequest();
          xhr.open('PUT',presign.putUrl);
          xhr.setRequestHeader('Content-Type',file.type||'application/octet-stream');
          xhr.upload.onprogress=(e)=>{
            if(e.lengthComputable){
              const pct=Math.round((e.loaded/e.total)*85)+5;
              bar.style.width=pct+'%';
              label.textContent=`"${file.name}" — ${formatSize(e.loaded)} / ${formatSize(e.total)}`;
            }
          };
          xhr.onload=async()=>{
            if(xhr.status>=200&&xhr.status<300){
              try{ await api('POST',`/folders/${currentFolder.id}/files/${presign.fileId}/confirm`,{size:file.size}); }catch(e){ console.log('confirm err:',e.message); }
              resolve();
            }else{reject(new Error(`Erreur upload R2: HTTP ${xhr.status}. Vérifiez la config CORS du bucket.`));}
          };
          xhr.onerror=()=>reject(new Error('Erreur réseau (CORS bloqué ?). Configurez CORS sur votre bucket R2.'));
          xhr.send(file);
        });
      }else{
        // Petit fichier : upload via serveur
        const form=new FormData();
        form.append('files',file);
        await api('POST',`/folders/${currentFolder.id}/files`,form);
      }
      uploaded++;
      bar.style.width=Math.round((uploaded/files.length)*100)+'%';
    }catch(e){toast(`Erreur "${file.name}": ${e.message}`,'error');}
  }
  bar.style.width='100%';
  await loadFiles();loadStats();
  if(uploaded>0)toast(`${uploaded} fichier${uploaded>1?'s':''} ajouté${uploaded>1?'s':''}`);
  setTimeout(()=>{prog.style.display='none';bar.style.width='0%';},600);
}
// ── Sélection multiple fichiers ───────────────────────────────────────────────
let _fileSelectionMode = false;

function handleFileCardClick(e, card, previewFn) {
  if (_fileSelectionMode) {
    e.stopPropagation();
    const cb = card.querySelector('.file-select-cb');
    if (cb) { cb.checked = !cb.checked; onFileCheckboxChange(); }
    return;
  }
  // Ne rien faire ici, le onclick original gère le preview
}

document.addEventListener('DOMContentLoaded', function() {
  document.addEventListener('long-press-file', function(e) {
    enterFileSelectionMode(e.detail.id);
  });
});

function enterFileSelectionMode(firstId) {
  _fileSelectionMode = true;
  document.querySelectorAll('.file-select-cb').forEach(cb => cb.style.display = 'inline-block');
  if (firstId) {
    const cb = document.querySelector(`.file-select-cb[data-id="${firstId}"]`);
    if (cb) cb.checked = true;
  }
  if (currentUser?.role === 'admin') document.getElementById('files-delete-selected-btn').style.display = 'block';
  document.getElementById('files-cancel-selection-btn').style.display = 'block';
  onFileCheckboxChange();
}

function exitFileSelectionMode() {
  _fileSelectionMode = false;
  document.querySelectorAll('.file-select-cb').forEach(cb => { cb.style.display = 'none'; cb.checked = false; });
  document.getElementById('files-delete-selected-btn').style.display = 'none';
  document.getElementById('files-download-selected-btn').style.display = 'none';
  document.getElementById('files-cancel-selection-btn').style.display = 'none';
}

function onFileCheckboxChange() {
  const checked = Array.from(document.querySelectorAll('.file-select-cb:checked'));
  if (currentUser?.role === 'admin') {
    document.getElementById('files-delete-selected-btn').style.display = checked.length > 0 ? 'block' : 'none';
  }
  const canDownloadAny = checked.some(cb => cb.getAttribute('data-can-download') === 'true');
  document.getElementById('files-download-selected-btn').style.display = canDownloadAny ? 'block' : 'none';
}

async function downloadSelectedFiles() {
  const checked = Array.from(document.querySelectorAll('.file-select-cb:checked'));
  const downloadable = checked.filter(cb => cb.getAttribute('data-can-download') === 'true');
  if (!downloadable.length) return;
  for (const cb of downloadable) {
    const url = cb.getAttribute('data-download-url');
    if (!url) continue;
    const a = document.createElement('a');
    a.href = url;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    await new Promise(r => setTimeout(r, 500));
  }
  exitFileSelectionMode();
}

async function deleteSelectedFiles() {
  const checked = document.querySelectorAll('.file-select-cb:checked');
  if (!checked.length) return;
  if (!await customConfirm(`Supprimer ${checked.length} fichier(s) ?`)) return;
  for (const cb of checked) {
    const id = cb.getAttribute('data-id');
    const card = cb.closest('.file-row');
    const subId = card ? card.getAttribute('data-subfolder') : '';
    try {
      if (subId) {
        await api('DELETE', `/folders/${currentFolder.id}/subfolders/${subId}/files/${id}`);
      } else {
        await api('DELETE', `/folders/${currentFolder.id}/files/${id}`);
      }
    } catch(e) { console.error(e); }
  }
  exitFileSelectionMode();
  await loadFiles();
  loadStats();
  toast('Fichiers supprimés');
}
async function deleteFile(id){
 if(!await customConfirm('Supprimer ce fichier ?'))return;
  try{await api('DELETE',`/folders/${currentFolder.id}/files/${id}`);await loadFiles();loadStats();toast('Fichier supprimé');}
  catch(e){toast(e.message,'error');}
}

// Store current files for preview lookup
let currentFiles = [];

function openPreviewById(btn) {
  const fileId = parseInt(btn.getAttribute('data-fileid'));
  const type = btn.getAttribute('data-type');
  const file = currentFiles.find(f => f.id === fileId);
  const filename = file ? file.name : 'Fichier';
  if (!currentSubfolder) {
    openPreview(fileId, filename, type);
  } else {
    openSubPreviewById(btn);
  }
}

function openSubPreviewById(btn) {
  const fileId = parseInt(btn.getAttribute('data-fileid'));
  const type = btn.getAttribute('data-type');
  const basePath = btn.getAttribute('data-basepath');
  const file = currentFiles.find(f => f.id === fileId);
  const filename = file ? file.name : 'Fichier';
  const previewUrl = basePath + '/preview';
  const downloadUrl = basePath + '/download';
  const streamUrl = basePath + '/stream';
  openPreviewWithUrls(filename, type, previewUrl, downloadUrl, streamUrl);
}
  
function openPreviewWithUrls(filename, type, previewUrl, downloadUrl, streamUrl) {
  var overlay = document.getElementById('preview-overlay');
  var body = document.getElementById('preview-body');
  var fnEl = document.getElementById('preview-filename');
  if (!overlay || !body) return;
  var sidebar = document.getElementById('sidebar');
  if (sidebar && window.innerWidth > 768) {
    sidebar.classList.add('collapsed');
    localStorage.setItem('sidebar_collapsed', '1');
  } else if (sidebar) {
    sidebar.classList.remove('open');
  }
  if (fnEl) fnEl.textContent = filename;
  var html = '';
  if (type === 'pdf') {
    html = '<div style="width:100%;height:100%;position:relative" id="pdf-preview-wrap">' +
  '<div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;background:#111;color:white;font-size:13px" id="pdf-loading">Chargement du document...</div>' +
  '</div>';
// Fetch le PDF avec session puis créer un blob URL pour l'iframe
fetch(previewUrl, { credentials: 'include' })
  .then(function(r) {
    if (!r.ok) throw new Error('Erreur ' + r.status);
    return r.blob();
  })
  .then(function(blob) {
    var blobUrl = URL.createObjectURL(blob);
    var wrap = document.getElementById('pdf-preview-wrap');
    if (wrap) {
      wrap.innerHTML = '<iframe src="' + blobUrl + '" style="width:100%;height:100%;border:none"></iframe>';
    }
  })
  .catch(function(err) {
    var loading = document.getElementById('pdf-loading');
    if (loading) loading.textContent = 'Erreur de chargement : ' + err.message;
  });
  } else if (type === 'img') {
    html = '<div style="display:flex;align-items:center;justify-content:center;height:100%;padding:20px"><img src="' + previewUrl + '" style="max-width:100%;max-height:100%;object-fit:contain;border-radius:8px"></div>';
  } else if (type === 'video') {
    // Stream URL returns JSON with signed R2 URL - fetch it first
    html = '<div style="display:flex;align-items:center;justify-content:center;height:100%;background:#000" id="video-loading"><div style="color:white">Chargement...</div></div>';
    // Async load the real URL
    fetch(streamUrl||previewUrl, {credentials:'include'})
      .then(function(r){ return r.json(); })
      .then(function(data){
        var videoUrl = data.url || data.urlLegacy || streamUrl;
        var body = document.getElementById('preview-body');
        if (body) body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;background:#000"><video controls autoplay src="' + videoUrl + '" style="max-width:100%;max-height:90vh"></video></div>';
      })
      .catch(function(){ console.error('Video load failed'); });
  } else if (type === 'audio') {
    html = '<div style="display:flex;align-items:center;justify-content:center;height:100%"><audio controls src="' + previewUrl + '" style="width:80%;max-width:400px"></audio></div>';
  } else {
    html = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:white;flex-direction:column;gap:16px"><div style="font-size:48px">📄</div><div>' + filename + '</div><a href="' + (downloadUrl||previewUrl) + '" download style="padding:10px 24px;background:var(--teal);color:white;border-radius:10px;text-decoration:none;font-weight:700">Télécharger</a></div>';
  }
  body.innerHTML = html;
  overlay.classList.add('open');
  document.body.style.overflow = 'hidden';
}

function openPreview(fileId, filename, type) {
  if (!currentFolder) return;
  // Marquer comme lu
  markAsRead(fileId, currentFolder.id, currentFolder.subId);
  // Ajouter le badge "Lu" dynamiquement dans la ligne
  const row = document.querySelector(`.file-row[data-file-id="${fileId}"]`);
  if (row) {
    row.classList.add('is-read');
    const fileName = row.querySelector('.file-name');
    if (fileName && !fileName.querySelector('.file-read-badge')) {
      const badge = document.createElement('span');
      badge.className = 'file-read-badge';
      badge.textContent = '✓ Lu';
      fileName.appendChild(badge);
    }
  }
  // Mettre à jour la barre de progression
  const allRows = document.querySelectorAll('.file-row[data-file-id]');
  const allFiles = [...allRows].map(r => ({ id: parseInt(r.getAttribute('data-file-id')) }));
  updateFolderProgress(allFiles);
  const previewUrl = `/api/folders/${currentFolder.id}/files/${fileId}/preview`;
  const downloadUrl = `/api/folders/${currentFolder.id}/files/${fileId}/download`;
  const streamUrl = `/api/folders/${currentFolder.id}/files/${fileId}/stream`;
  openPreviewWithUrls(filename, type, previewUrl, downloadUrl, streamUrl);
}


function closePreview() {
  var overlay = document.getElementById('preview-overlay');
  var body = document.getElementById('preview-body');
  if (overlay) overlay.classList.remove('open');
  if (body) {
    // Libérer les blob URLs pour éviter les fuites mémoire
    body.querySelectorAll('iframe[src^="blob:"]').forEach(function(el) {
      URL.revokeObjectURL(el.src);
    });
    body.innerHTML = '';
  }
  document.body.style.overflow = '';
}

// Fermer avec Échap
document.addEventListener('keydown', e => { if(e.key === 'Escape') closePreview(); });

async function toggleDownload(fileId){
  if(!currentFolder)return;
  try{
    const result = await api('PATCH',`/folders/${currentFolder.id}/files/${fileId}/downloadable`);
    await loadFiles();
    toast(result.downloadable ? 'Téléchargement autorisé ✅' : 'Téléchargement bloqué 🔒');
  }catch(e){toast(e.message,'error');}
}

async function clearDoubleConnection(e, userId) {
  e.stopPropagation();
  if (!await customConfirm("Effacer l'alerte de double connexion pour cet étudiant ?")) return;
  try {
    await api('DELETE', '/users/' + userId + '/double-connection');
    await loadUsers();
    toast('Alerte effacée');
  } catch(e) { toast(e.message, 'error'); }
}

async function loadUsers(){
  const grid=$('users-grid');grid.innerHTML='<div style="color:var(--text3);font-size:14px">Chargement…</div>';
  try{const users=await api('GET','/users');renderUsers(users);}
  catch(e){grid.innerHTML='<div style="color:var(--text3)">Erreur de chargement</div>';}
}

function renderUsers(users){
  const grid=$('users-grid');
  if(!users.length){grid.innerHTML='<div style="padding:24px;color:var(--text3);font-size:14px">Aucun compte.</div>';return;}
  const admins=users.filter(u=>u.role==='admin'||u.role==='subadmin');
  const students=users.filter(u=>u.role==='student');

  const renderSection = (list, title) => {
    if (!list.length) return '';
    const rows = list.map((u, i) => {
      const initials = u.name.split(' ').map(w=>w[0]).join('').substring(0,2).toUpperCase();
      const isSelf = u.id === currentUser.id;
      const doubleConn = u.doubleConnection;
      const bg = doubleConn ? 'rgba(239,83,80,0.04)' : (i%2===0 ? 'transparent' : 'rgba(0,0,0,0.015)');
      return `<tr style="background:${bg}">
        <td style="padding:9px 14px;white-space:nowrap">
          <div style="display:flex;align-items:center;gap:8px">
            <div style="width:28px;height:28px;border-radius:50%;background:${u.role==='admin'?'linear-gradient(135deg,#004D61,#003340)':'linear-gradient(135deg,var(--teal),var(--teal-dark))'};display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:white;flex-shrink:0">${initials}</div>
            <span style="font-weight:600;font-size:13px;color:var(--text)">${u.name}${isSelf?' <small style="color:var(--text3)">(vous)</small>':''}</span>
            ${doubleConn?`<button onclick="clearDoubleConnection(event,${u.id})" title="Double connexion — cliquer pour effacer" style="background:#FFEBEE;border:none;color:#C62828;cursor:pointer;font-size:10px;padding:2px 6px;border-radius:6px;font-weight:700">⚠️</button>`:''}
          </div>
        </td>
        <td style="padding:9px 14px;font-size:11.5px;color:var(--text3)">${u.login}</td>
        <td style="padding:9px 14px;font-size:11.5px;color:var(--text3);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${u.email||'—'}</td>
        <td style="padding:9px 14px;font-size:11px;color:var(--teal-dark)">${u.mineure||'—'}</td>
        <td style="padding:9px 14px;font-size:11px;color:#5865F2">${u.discord||'—'}</td>
        <td style="padding:9px 14px;text-align:right">
          ${!isSelf?`<button class="icon-btn" onclick="deleteUser(${u.id})" title="Supprimer"><svg viewBox="0 0 24 24" fill="currentColor" style="width:13px;height:13px"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg></button>`:''}
        </td>
      </tr>`;
    }).join('');

    return `<div style="margin-bottom:20px">
      <div style="font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.8px;margin-bottom:8px">${title}</div>
      <div style="background:white;border-radius:14px;border:1.5px solid var(--border);overflow:hidden">
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr style="background:rgba(0,151,167,0.04);border-bottom:1px solid var(--border)">
              <th style="padding:8px 14px;text-align:left;font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px">Nom</th>
              <th style="padding:8px 14px;text-align:left;font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px">Identifiant</th>
              <th style="padding:8px 14px;text-align:left;font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px">Email</th>
              <th style="padding:8px 14px;text-align:left;font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px">Mineure</th>
              <th style="padding:8px 14px;text-align:left;font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px">Discord</th>
              <th style="padding:8px 14px"></th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
  };

  grid.innerHTML = renderSection(admins, 'Administrateurs') + renderSection(students, `Étudiants (${students.length})`);
}

async function createUser(){
  const name=$('user-name-input').value.trim(),login=$('user-login-input').value.trim();
  const password=$('user-password-input').value,role=$('user-role-input').value;
  const errEl=$('user-error');errEl.style.display='none';
  if(!name||!login||!password){errEl.textContent='Veuillez remplir tous les champs.';errEl.style.display='block';return;}
  const btn=$('btn-create-user');btn.disabled=true;btn.textContent='Création…';
  try{
    await api('POST','/users',{name,login,password,role});
    $('user-name-input').value='';$('user-login-input').value='';$('user-password-input').value='';
    closeModal('modal-user');await loadUsers();loadStats();toast(`Compte créé : ${login}`);
  }catch(e){errEl.textContent=e.message;errEl.style.display='block';}
  finally{btn.disabled=false;btn.textContent='Créer le compte';}
}

async function deleteUser(id){
  if(!await customConfirm('Supprimer ce compte ?'))return;
  try{await api('DELETE','/users/'+id);await loadUsers();loadStats();toast('Compte supprimé');}
  catch(e){toast(e.message,'error');}
}

function updateBreadcrumb(){
  const bc=$('breadcrumb');
  if(!currentFolder){bc.innerHTML=`<span class="breadcrumb-item active"><svg style="width:13px;height:13px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>Tous les dossiers</span>`;return;}
  if (!currentSubfolder) {
    bc.innerHTML=`<span class="breadcrumb-item" onclick="backToRoot()"><svg style="width:13px;height:13px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>Tous les dossiers</span><span class="breadcrumb-sep">›</span><span class="breadcrumb-item active">${currentFolder.name}</span>`;
  } else {
    bc.innerHTML=`<span class="breadcrumb-item" onclick="backToRoot()"><svg style="width:13px;height:13px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>Tous les dossiers</span><span class="breadcrumb-sep">›</span><span class="breadcrumb-item" onclick="openFolder(currentFolder.id,currentFolder.name)">${currentFolder.name}</span><span class="breadcrumb-sep">›</span><span class="breadcrumb-item active">${currentSubfolder.name}</span>`;
  }
}
function openModal(id){$(id).classList.add('open');}
function closeModal(id){$(id).classList.remove('open');}
document.querySelectorAll('.modal-overlay').forEach(o=>o.addEventListener('click',e=>{if(e.target===o)o.classList.remove('open');}));


// ── RÉGLAGES ──────────────────────────────────────────────────────────────────
async function doChangePassword() {
  const currentPw = document.getElementById('settings-current-pw').value;
  const newPw = document.getElementById('settings-new-pw').value;
  const confirmPw = document.getElementById('settings-confirm-pw').value;
  const errEl = document.getElementById('settings-pw-error');
  const okEl = document.getElementById('settings-pw-success');
  errEl.style.display = 'none'; okEl.style.display = 'none';
  if (!currentPw || !newPw) { errEl.textContent = 'Remplis tous les champs.'; errEl.style.display = 'block'; return; }
  if (newPw.length < 6) { errEl.textContent = 'Minimum 6 caractères.'; errEl.style.display = 'block'; return; }
  if (newPw !== confirmPw) { errEl.textContent = 'Les mots de passe ne correspondent pas.'; errEl.style.display = 'block'; return; }
  try {
    await api('POST', '/users/change-password', { currentPassword: currentPw, newPassword: newPw });
    okEl.textContent = 'Mot de passe modifié avec succès !';
    okEl.style.display = 'block';
    document.getElementById('settings-current-pw').value = '';
    document.getElementById('settings-new-pw').value = '';
    document.getElementById('settings-confirm-pw').value = '';
    toast('Mot de passe modifié ✅');
  } catch(e) {
    errEl.textContent = e.message;
    errEl.style.display = 'block';
  }
}

async function doSaveEmail() {
  const email = document.getElementById('settings-email').value.trim();
  const okEl = document.getElementById('settings-email-success');
  okEl.style.display = 'none';
  if (!email || !email.includes('@')) { toast('Entre une adresse email valide.', 'error'); return; }
  try {
    await api('PATCH', '/users/' + currentUser.id + '/email', { email });
    currentUser.email = email;
    okEl.textContent = 'Email enregistré !';
    okEl.style.display = 'block';
    toast('Email enregistré ✅');
  } catch(e) { toast(e.message, 'error'); }
}

function loadSettingsPanel() {
  const emailEl = document.getElementById('settings-email');
  if (emailEl && currentUser && currentUser.email) {
    emailEl.value = currentUser.email;
  }
  const pwErr = document.getElementById('settings-pw-error');
  if (pwErr) pwErr.style.display = 'none';
  const pwOk = document.getElementById('settings-pw-success');
  if (pwOk) pwOk.style.display = 'none';
  const emailOk = document.getElementById('settings-email-success');
  if (emailOk) emailOk.style.display = 'none';
  const prefs = currentUser?.notifPrefs || { announcements: true, discussions: true, files: true, mentions: true };
  ['announcements','discussions','files','mentions'].forEach(function(key) {
    const cb = document.getElementById('notif-pref-' + key);
    if (cb) cb.checked = prefs[key] !== false;
  });
}
async function toggleNotifPref(key, checkbox) {
  const prefs = currentUser?.notifPrefs || { announcements: true, discussions: true, files: true, mentions: true };
  prefs[key] = checkbox.checked;
  try {
    await api('PATCH', '/me/notif-prefs', prefs);
    currentUser.notifPrefs = prefs;
  } catch(e) {
    checkbox.checked = !checkbox.checked;
    toast('Erreur lors de la mise à jour', 'error');
  }
}

// ── AUTH FORMS ────────────────────────────────────────────────────────────────
function openLegal(e) {
  if (e) e.preventDefault();
  document.getElementById('legal-modal').style.display = 'block';
}
function closeLegal() {
  document.getElementById('legal-modal').style.display = 'none';
}
function showLoginForm() {
  document.querySelectorAll('.auth-card-body').forEach(function(el) { el.style.display = 'none'; });
  var forgotForm = document.getElementById('forgot-form');
  var resetForm = document.getElementById('reset-form');
  if (forgotForm) forgotForm.style.display = 'none';
  if (resetForm) resetForm.style.display = 'none';
  var loginBody = document.querySelector('.auth-card-body:not(#register-form)');
  if (loginBody) loginBody.style.display = 'block';
  else { var bodies = document.querySelectorAll('.auth-card-body'); if (bodies[0]) bodies[0].style.display = 'block'; }
}
function showForgotForm() {
  document.querySelector('.auth-card-body').style.display = 'none';
  document.getElementById('reset-form').style.display = 'none';
  document.getElementById('forgot-form').style.display = '';
  document.getElementById('forgot-error').style.display = 'none';
  document.getElementById('forgot-success').style.display = 'none';
}
async function doForgotPassword() {
  const login = document.getElementById('forgot-login-input').value.trim();
  const btn = document.getElementById('forgot-btn');
  const errEl = document.getElementById('forgot-error');
  const okEl = document.getElementById('forgot-success');
  errEl.style.display = 'none'; okEl.style.display = 'none';
  if (!login) { errEl.textContent = 'Entre ton identifiant.'; errEl.style.display = 'block'; return; }
  btn.disabled = true; btn.textContent = 'Envoi...';
  try {
    const data = await api('POST', '/forgot-password', { login });
    if (data.resetLink) {
      okEl.innerHTML = '<strong>Lien généré !</strong><br><a href="' + data.resetLink + '" style="color:var(--teal-dark);word-break:break-all;font-size:12px">' + data.resetLink + '</a><br><small style="color:#888;font-size:11px">Partage ce lien directement si tu ne reçois pas d\'email.</small>';
    } else {
      okEl.textContent = 'Un lien de réinitialisation a été envoyé à ton adresse email.';
    }
    okEl.style.display = 'block';
  } catch(e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
  finally { btn.disabled = false; btn.textContent = 'Envoyer le lien'; }
}
async function doResetPassword() {
  const token = new URLSearchParams(window.location.search).get('reset');
  const pw = document.getElementById('reset-password-input').value;
  const pw2 = document.getElementById('reset-password-confirm').value;
  const errEl = document.getElementById('reset-error');
  const okEl = document.getElementById('reset-success');
  const btn = document.getElementById('reset-btn');
  errEl.style.display = 'none'; okEl.style.display = 'none';
  if (pw.length < 6) { errEl.textContent = 'Minimum 6 caractères.'; errEl.style.display = 'block'; return; }
  if (pw !== pw2) { errEl.textContent = 'Les mots de passe ne correspondent pas.'; errEl.style.display = 'block'; return; }
  btn.disabled = true; btn.textContent = 'Enregistrement...';
  try {
    await api('POST', '/reset-password', { token, password: pw });
    okEl.textContent = 'Mot de passe mis à jour ! Retour à la connexion dans 3s...';
    okEl.style.display = 'block';
    setTimeout(() => { history.replaceState({}, '', '/'); document.getElementById('reset-form').style.display = 'none'; document.querySelector('.auth-card-body').style.display = ''; }, 3000);
  } catch(e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
  finally { btn.disabled = false; btn.textContent = 'Enregistrer'; }
}



// ── ANNONCES ─────────────────────────────────────────────────────────────────
async function loadAnnouncements() {
  const list = $('announcements-list');
  list.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3)">Chargement...</div>';
  try {
    const anns = await api('GET', '/announcements');
    if (!anns.length) {
      list.innerHTML = `<div class="search-no-results">
        <svg viewBox="0 0 24 24" fill="currentColor" style="width:40px;height:40px;opacity:0.2;margin-bottom:12px"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg>
        <div>Aucune annonce pour l'instant.</div>
      </div>`;
      return;
    }
    const isAdmin = currentUser?.role === 'admin' || currentUser?.role === 'subadmin';
    const colors = { info:'ℹ️', success:'✅', urgent:'🚨', tip:'💡' };
    list.innerHTML = anns.map(a => `
      <div class="ann-card ${a.color}" id="ann-${a.id}">
        ${isAdmin ? `<button class="ann-delete-btn" onclick="deleteAnnouncement(${a.id})" title="Supprimer"><svg viewBox="0 0 24 24" fill="currentColor" style="width:12px;height:12px"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg></button>` : ''}
        <div class="ann-card-title">${colors[a.color] || 'ℹ️'} ${a.title}</div>
        <div class="ann-card-message">${a.message}</div>
        <div class="ann-card-date">${new Date(a.createdAt).toLocaleDateString('fr-FR', {day:'numeric',month:'long',year:'numeric'})}</div>
        <div style="display:flex;align-items:center;gap:6px;margin-top:10px;flex-wrap:wrap">
          ${['👍','❤️','🔥','😮','👏','✅','🐏','😂','⏱️','💪🏽','😉'].map(em => {
            const users = (a.reactions && a.reactions[em]) || [];
            const iReacted = users.includes(currentUser?.id);
            return `<button onclick="reactAnnouncement(${a.id},'${em}')" style="display:flex;align-items:center;gap:4px;padding:4px 10px;border-radius:20px;border:1.5px solid ${iReacted ? 'var(--teal)' : 'var(--border)'};background:${iReacted ? 'rgba(0,151,167,0.1)' : 'transparent'};cursor:pointer;font-size:13px;transition:all 0.15s" id="ann-react-${a.id}-${em}">${em}${users.length ? ' <span style="font-size:11px;font-weight:700;color:var(--teal-dark)">' + users.length + '</span>' : ''}</button>`;
          }).join('')}
        </div>
      </div>`).join('');
 markAnnouncementsSeen(anns.map(a => a.id));
    updateAnnouncementsBadge();
  } catch(e) {
    list.innerHTML = '<div style="padding:20px;color:var(--danger)">Erreur de chargement</div>';
  }
}

function showNewAnnForm() {
  $('ann-form').style.display = '';
  $('ann-title').focus();
}

function hideAnnForm() {
  $('ann-form').style.display = 'none';
  $('ann-title').value = '';
  $('ann-message').value = '';
}

async function submitAnnouncement() {
  const title = ($('ann-title').value || '').trim();
  const message = ($('ann-message').value || '').trim();
  const color = document.querySelector('input[name="ann-color"]:checked')?.value || 'info';
  if (!title || !message) { toast('Titre et message requis', 'error'); return; }
  try {
    await api('POST', '/announcements', { title, message, color });
    hideAnnForm();
    await loadAnnouncements();
    toast('Annonce publiée ✅');
  } catch(e) { toast(e.message, 'error'); }
}
async function reactAnnouncement(id, emoji) {
  try {
    const res = await api('POST', '/announcements/' + id + '/react', { emoji });
    await loadAnnouncements();
  } catch(e) { toast(e.message, 'error'); }
}
async function deleteAnnouncement(id) {
  if (!await customConfirm('Supprimer cette annonce ?')) return;
  try {
    await api('DELETE', '/announcements/' + id);
    await loadAnnouncements();
    toast('Annonce supprimée');
  } catch(e) { toast(e.message, 'error'); }
}

// ── LOGS DE CONNEXION ────────────────────────────────────────────────────────
async function loadConnectionLogs() {
  const container = $('connection-logs');
  if (!container) return;
  container.innerHTML = '<div style="padding:16px;text-align:center;color:var(--text3)">Chargement…</div>';
  try {
    const logs = await api('GET', '/connection-logs');
    if (!logs.length) {
      container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3)">Aucune connexion enregistrée</div>';
      return;
    }
    container.innerHTML = logs.map((l, i) => {
      const date = new Date(l.date).toLocaleString('fr-FR');
      const border = i < logs.length-1 ? 'border-bottom:1px solid rgba(178,223,219,0.3)' : '';
      return `<div style="display:flex;align-items:center;gap:14px;padding:10px 16px;${border}">
        <div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--teal),var(--teal-dark));display:flex;align-items:center;justify-content:center;color:white;font-size:12px;font-weight:700;flex-shrink:0">${(l.name||l.login).substring(0,2).toUpperCase()}</div>
        <div style="flex:1;min-width:0">
          <div style="font-weight:600;color:var(--text);font-size:13px">${l.name || l.login}</div>
          <div style="color:var(--text3);font-size:11px">${l.login}</div>
        </div>
        <div style="text-align:right;flex-shrink:0">
          <div style="color:var(--text2);font-size:12px">${date}</div>
          <div style="color:var(--text3);font-size:11px;font-family:monospace">${l.ip}</div>
        </div>
      </div>`;
    }).join('');
  } catch(e) {
    container.innerHTML = '<div style="padding:16px;color:var(--danger)">Erreur de chargement</div>';
  }
}

// ── LOGS DE CONNEXION ────────────────────────────────────────────────────────
function getSeenAnnouncements() {
  if (!currentUser) return [];
  try { return JSON.parse(localStorage.getItem('masterpass_seen_ann_' + currentUser.id) || '[]'); }
  catch { return []; }
}
function markAnnouncementsSeen(ids) {
  if (!currentUser) return;
  const seen = getSeenAnnouncements();
  const merged = [...new Set([...seen, ...ids])];
  localStorage.setItem('masterpass_seen_ann_' + currentUser.id, JSON.stringify(merged));
}



async function updateAnnouncementsBadge() {
  try {
    const anns = await api('GET', '/announcements');
    const seen = getSeenAnnouncements();
    const unread = anns.filter(a => !seen.includes(a.id)).length;
    const badge = $('announcements-badge');
    if (!badge) return;
    if (unread > 0) {
      badge.textContent = unread;
      badge.style.display = 'inline-block';
    } else {
      badge.style.display = 'none';
    }
  } catch(e) {}
}

function showNewAnnouncementForm() {
  $('new-announcement-form').style.display = '';
  $('ann-title').focus();
}
function hideNewAnnouncementForm() {
  $('new-announcement-form').style.display = 'none';
  $('ann-title').value = '';
  $('ann-message').value = '';
}

async function publishAnnouncement() {
  const title = $('ann-title').value.trim();
  const message = $('ann-message').value.trim();
  const color = document.querySelector('input[name="ann-color"]:checked')?.value || 'info';
  if (!title || !message) { toast('Titre et message requis', 'error'); return; }
  try {
    await api('POST', '/announcements', { title, message, color });
    hideNewAnnouncementForm();
    await loadAnnouncements();
    toast('Annonce publiée ✅');
  } catch(e) { toast(e.message, 'error'); }
}



// ── NOTIFICATIONS PUSH ───────────────────────────────────────────────────────
// APRÈS
async function initPushNotifications() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
  try {
    const reg = await navigator.serviceWorker.register('/sw.js');
    console.log('[PUSH] Service Worker enregistré');

    // Demander la permission seulement si pas encore décidé
    if (Notification.permission === 'default') {
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') return;
    }
    if (Notification.permission !== 'granted') return;

    const { key } = await api('GET', '/push/vapid-key');

    // Vérifier si un abonnement existe déjà
    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      // Pas d'abonnement — en créer un
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(key)
      });
    }

    // Toujours renvoyer au serveur pour s'assurer que le userId est à jour
    await api('POST', '/push/subscribe', { subscription: sub.toJSON() });
    console.log('[PUSH] Abonné aux notifications');
  } catch(e) {
    console.log('[PUSH] Non disponible:', e.message);
  }
}

async function unsubscribePush() {
  try {
    if (!('serviceWorker' in navigator)) return;
    const reg = await navigator.serviceWorker.getRegistration();
    if (!reg) return;
    const sub = await reg.pushManager.getSubscription();
    if (sub) {
      await api('POST', '/push/unsubscribe', { endpoint: sub.endpoint }).catch(()=>{});
      await sub.unsubscribe();
      console.log('[PUSH] Désabonné');
    }
  } catch(e) {
    console.log('[PUSH] Erreur désabonnement:', e.message);
  }
}

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  return new Uint8Array([...rawData].map(c => c.charCodeAt(0)));
}

// ── AVATAR ───────────────────────────────────────────────────────────────────
async function uploadAvatar(input) {
  const file = input.files[0];
  if (!file) return;
  const status = document.getElementById('avatar-status');
  status.textContent = 'Upload en cours...';
  status.style.color = 'var(--text3)';
  const formData = new FormData();
  formData.append('avatar', file);
  try {
    const r = await fetch('/api/avatar', { method:'POST', body:formData, credentials:'include' });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error);
    // Mettre à jour l'aperçu
    currentUser.avatar = data.avatar;
    updateAvatarPreview();
    status.textContent = '✅ Photo mise à jour !';
    status.style.color = '#2E7D32';
    // Mettre à jour l'avatar dans la sidebar
    updateSidebarAvatar();
  } catch(e) {
    status.textContent = '❌ ' + e.message;
    status.style.color = 'var(--danger)';
  }
}

function updateAvatarPreview() {
  const preview = document.getElementById('avatar-preview');
  const initials = document.getElementById('avatar-initials');
  if (!preview) return;
  if (currentUser?.avatar) {
    preview.style.background = 'transparent';
    preview.innerHTML = '<img src="' + currentUser.avatar + '" style="width:100%;height:100%;object-fit:cover;border-radius:50%">';
  } else if (currentUser?.name) {
    const ini = currentUser.name.split(' ').map(w=>w[0]).join('').substring(0,2).toUpperCase();
    preview.innerHTML = '<span>' + ini + '</span>';
    preview.style.background = 'linear-gradient(135deg,var(--teal),var(--teal-dark))';
  }
}

function updateSidebarAvatar() {
  const avatarEl = document.getElementById('nav-avatar');
  if (!avatarEl || !currentUser) return;
  if (currentUser.avatar) {
    avatarEl.innerHTML = '<img src="' + currentUser.avatar + '" style="width:100%;height:100%;object-fit:cover;border-radius:50%">';
    avatarEl.style.overflow = 'hidden';
    avatarEl.style.padding = '0';
    avatarEl.style.fontSize = '0';
  }
}

// ── MENU CONTEXTUEL MESSAGES ─────────────────────────────────────────────────
let _ctxComment = null; // { id, userId, userName, message, isOwn, canDelete }
let _longPressTimer = null;

// Map to store comment data by id
var _commentDataMap = {};
var _repliesCache = []; // cache des replies pour le swipe
var _menuJustOpened = false;

function showMsgContextMenu(e, commentId) {
  var comment = _commentDataMap[commentId];
  if (!comment) return;
  _ctxComment = comment;
  const menu = document.getElementById('msg-context-menu');
  var canEdit = comment.isOwn && !comment.audio;
  var canDelete = comment.canDelete;
  document.getElementById('ctx-edit').style.display = canEdit ? 'flex' : 'none';
  document.getElementById('ctx-delete').style.display = canDelete ? 'flex' : 'none';
  var clientX = e.clientX || (e.touches && e.touches[0] ? e.touches[0].clientX : window.innerWidth/2);
  var clientY = e.clientY || (e.touches && e.touches[0] ? e.touches[0].clientY : window.innerHeight/2);
  var x = Math.min(clientX, window.innerWidth - 8) - 395;
  if (x < 8) x = 8;
  var y = Math.min(clientY, window.innerHeight - 220);
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
  menu.style.display = 'block';
  _menuJustOpened = true;
  setTimeout(function() {
    _menuJustOpened = false;
    document.addEventListener('click', closeMsgContextMenu, { once: true });
  }, 600);
}

function closeMsgContextMenu() {
  if (_menuJustOpened) return;
  document.getElementById('msg-context-menu').style.display = 'none';
}

function msgLongPressStart(e, commentId) {
  // Capture coordinates immediately (touches disappear after touchend)
  var captured = {
    clientX: e.clientX || (e.touches && e.touches[0] ? e.touches[0].clientX : window.innerWidth/2),
    clientY: e.clientY || (e.touches && e.touches[0] ? e.touches[0].clientY : window.innerHeight/2)
  };
  _longPressTimer = setTimeout(function() {
    if (navigator.vibrate) navigator.vibrate(50);
    showMsgContextMenu(captured, commentId);
  }, 500);
}

function msgLongPressEnd() {
  clearTimeout(_longPressTimer);
}

// Event delegation for bubbles - attached after loadDiscussion renders
function initBubbleEvents(containerId) {
  // Works for both thread-replies (new system) and discussion-messages (legacy)
  var list = containerId
    ? document.getElementById(containerId)
    : (document.getElementById('thread-replies') || document.getElementById('discussion-messages'));
  if (!list) return;
  list.onmousedown = function(e) {
    var bubble = e.target.closest('.msg-bubble');
    if (!bubble) return;
    var cid = parseInt(bubble.getAttribute('data-cid'));
    msgLongPressStart(e, cid);
  };
  list.onmouseup = function() { msgLongPressEnd(); };
  list.onmouseleave = function() { msgLongPressEnd(); };
  var _touchStartX = 0, _touchStartY = 0, _swipeBubble = null, _swipeRow = null, _swiping = false;
  list.ontouchstart = function(e) {
    var bubble = e.target.closest('.msg-bubble');
    if (!bubble) return;
    _touchStartX = e.touches[0].clientX;
    _touchStartY = e.touches[0].clientY;
    _swipeBubble = bubble;
    _swipeRow = bubble.closest('[style*="flex-direction:column"]') || bubble.parentElement;
    _swiping = false;
    var cid = parseInt(bubble.getAttribute('data-cid'));
    msgLongPressStart(e, cid);
  };
  list.ontouchmove = function(e) {
    if (!_swipeBubble) return;
    var dx = e.touches[0].clientX - _touchStartX;
    var dy = Math.abs(e.touches[0].clientY - _touchStartY);
    if (dy > 20) { msgLongPressEnd(); return; }
    if (Math.abs(dx) > 10) {
      msgLongPressEnd();
      _swiping = true;
      // Limiter le déplacement à 80px
      var clamped = Math.max(-80, Math.min(80, dx));
      _swipeBubble.style.transform = 'translateX(' + clamped + 'px)';
      _swipeBubble.style.transition = 'none';
      // Icône répondre (droite) ou supprimer (gauche)
      var hint = _swipeRow.querySelector('.swipe-hint');
      if (!hint) {
        hint = document.createElement('div');
        hint.className = 'swipe-hint';
        hint.style.cssText = 'position:absolute;top:50%;transform:translateY(-50%);font-size:20px;pointer-events:none;opacity:0;transition:opacity 0.15s';
        _swipeRow.style.position = 'relative';
        _swipeRow.appendChild(hint);
      }
      if (dx > 30) { hint.textContent = '↩️'; hint.style.left = '4px'; hint.style.right = ''; hint.style.opacity = '1'; }
      else if (dx < -30) { hint.textContent = '🗑️'; hint.style.right = '4px'; hint.style.left = ''; hint.style.opacity = '1'; }
      else { hint.style.opacity = '0'; }
      e.preventDefault();
    }
  };
  list.ontouchend = async function(e) {
    msgLongPressEnd();
    if (!_swipeBubble || !_swiping) { _swipeBubble = null; _swipeRow = null; _swiping = false; return; }
    var dx = e.changedTouches[0].clientX - _touchStartX;
    _swipeBubble.style.transition = 'transform 0.25s ease';
    _swipeBubble.style.transform = 'translateX(0)';
    var hint = _swipeRow ? _swipeRow.querySelector('.swipe-hint') : null;
    if (hint) hint.style.opacity = '0';
    var cid = parseInt(_swipeBubble.getAttribute('data-cid'));
    if (dx > 60) {
      // Swipe droite → répondre
      var comment = _repliesCache.find(function(r){ return r.id === cid; });
      if (comment) setReply(comment.id, comment.userName, comment.message || 'Vocal');
    } else if (dx < -60) {
      var comment = _repliesCache.find(function(r){ return r.id === cid; });
      var canDel = comment && (String(comment.userId) === String(currentUser?.id) || currentUser?.role === 'admin' || currentUser?.role === 'subadmin');
      if (canDel && await customConfirm('Supprimer ce message ?')) {
        // Appel direct API sans double confirm
        var container2 = document.getElementById('thread-replies2');
        var isInline = container2 && container2.innerHTML.trim() !== '' && document.getElementById('disc-inline-view') && document.getElementById('disc-inline-view').style.display !== 'none' && (document.getElementById('disc-inline-view').offsetWidth || 0) > 0;
        if (isInline) deleteReplyInline(cid, true); else deleteReply(cid, true);
      }
    }
    _swipeBubble = null; _swipeRow = null; _swiping = false;
  };
}

function ctxReply() {
  closeMsgContextMenu();
  if (!_ctxComment) return;
  setReply(_ctxComment.id, _ctxComment.userName, _ctxComment.message || 'Vocal');
}

async function ctxEdit() {
  closeMsgContextMenu();
  if (!_ctxComment) return;
  const newMsg = await customPrompt('Modifier le message :', _ctxComment.message);
  if (!newMsg || newMsg.trim() === _ctxComment.message) return;
  // Edit reply in thread
  api('PATCH', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/replies/' + _ctxComment.id, { message: newMsg.trim() })
    .then(function() {
      var isInline = document.getElementById('disc-inline-view')?.style.display !== 'none' && (document.getElementById('disc-inline-view')?.offsetWidth || 0) > 0;
      if (isInline) loadThreadRepliesInline(true); else loadThreadReplies(true);
    })
    .catch(e => toast(e.message, 'error'));
}

async function ctxDelete() {
  closeMsgContextMenu();
  if (!_ctxComment) return;
  if (!await customConfirm('Supprimer ce message ?')) return;
  var isInline = document.getElementById('disc-inline-view')?.style.display !== 'none' && (document.getElementById('disc-inline-view')?.offsetWidth || 0) > 0;
  api('DELETE', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/replies/' + _ctxComment.id)
    .then(function() { if (isInline) loadThreadRepliesInline(true); else loadThreadReplies(true); })
    .catch(function(e) { toast(e.message, 'error'); });
}

async function reactMsg(emoji, commentId) {
  closeMsgContextMenu();
  var cid = commentId || (_ctxComment && _ctxComment.id);
  if (!cid || !_discussionFileId || !_currentThreadId) return;
  try {
    await api('POST', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/replies/' + cid + '/react', { emoji });
    var isInline = document.getElementById('disc-inline-view')?.style.display !== 'none' && (document.getElementById('disc-inline-view')?.offsetWidth || 0) > 0;
    if (isInline) await loadThreadRepliesInline(true); else await loadThreadReplies(true);
  } catch(e) { toast(e.message, 'error'); }
}

// ── ACTIONS FICHIER (RENOMMER / DÉPLACER) ────────────────────────────────────
let _fileModalData = null; // { fileId, currentName, folderId, subId }

function openFileModal(e, fileId, currentName, folderId, subId) {
  e.stopPropagation();
  _fileModalData = { fileId, currentName, folderId: String(folderId), subId: String(subId||'') };
  document.getElementById('file-modal-title').textContent = '✏️ ' + currentName;
  document.getElementById('rename-input').value = currentName;
  // Build destination list
  buildMoveDestinations(folderId, subId);
  // Show modal
  const modal = document.getElementById('file-actions-modal');
  modal.style.display = 'flex';
  setTimeout(() => document.getElementById('rename-input').focus(), 100);
}

function closeFileModal() {
  document.getElementById('file-actions-modal').style.display = 'none';
  _fileModalData = null;
}

async function doRenameFile() {
  if (!_fileModalData) return;
  const newName = document.getElementById('rename-input').value.trim();
  if (!newName || newName === _fileModalData.currentName) { closeFileModal(); return; }
  const { fileId, folderId, subId } = _fileModalData;
  // Always use folder route (server searches subfolders too)
  const route = '/folders/' + folderId + '/files/' + fileId + '/rename';
  try {
    await api('PATCH', route, { name: newName });
    closeFileModal();
    toast('Fichier renommé ✅');
    // Update DOM directly without full reload
    const nameEl = document.querySelector('.file-row[data-file-id="' + fileId + '"] .file-name');
    if (nameEl) {
      // Keep read badge if present
      const readBadge = nameEl.querySelector('.file-read-badge');
      nameEl.textContent = newName;
      if (readBadge) nameEl.appendChild(readBadge);
    }
    // Also reload to ensure consistency
    if (subId) setTimeout(() => loadSubfolderFiles(subId, folderId), 200);
    else setTimeout(() => loadFiles(), 200);
  } catch(err) { toast(err.message, 'error'); }
}

async function buildMoveDestinations(currentFolderId, currentSubId) {
  const container = document.getElementById('move-destinations');
  container.innerHTML = '<div style="color:var(--text3);font-size:13px;padding:8px 0">Chargement...</div>';
  try {
    const folders = await api('GET', '/folders');
    container.innerHTML = '';

    folders.forEach(function(folder) {
      const isCurrent = String(folder.id) === String(currentFolderId) && !currentSubId;
      const hasSubs = folder.subfolders && folder.subfolders.length > 0;

      // Dossier racine
      const row = document.createElement('div');
      row.style.cssText = 'margin-bottom:4px';

      const folderBtn = document.createElement('div');
      folderBtn.style.cssText = 'display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;border:1.5px solid ' + (isCurrent ? 'var(--teal)' : 'var(--border)') + ';background:' + (isCurrent ? 'rgba(0,151,167,0.06)' : 'var(--bg)') + ';cursor:pointer;font-size:13px;color:var(--text);user-select:none';

      const arrow = document.createElement('span');
      arrow.textContent = hasSubs ? '▶' : ' ';
      arrow.style.cssText = 'font-size:10px;color:var(--text3);width:14px;flex-shrink:0;transition:transform 0.2s';

      const folderIcon = document.createElement('span');
      folderIcon.textContent = '📁';
      folderIcon.style.cssText = 'flex-shrink:0';

      const folderName = document.createElement('span');
      folderName.textContent = folder.name;
      folderName.style.cssText = 'flex:1';

      if (isCurrent) {
        const badge = document.createElement('small');
        badge.textContent = '📍 actuel';
        badge.style.cssText = 'color:var(--text3);font-size:10px';
        folderBtn.appendChild(arrow);
        folderBtn.appendChild(folderIcon);
        folderBtn.appendChild(folderName);
        folderBtn.appendChild(badge);
      } else {
        folderBtn.appendChild(arrow);
        folderBtn.appendChild(folderIcon);
        folderBtn.appendChild(folderName);
      }

      // Sous-dossiers container (caché par défaut)
      const subsContainer = document.createElement('div');
      subsContainer.style.cssText = 'display:none;padding-left:20px;margin-top:4px';

      // Clic sur le dossier : déplacer ici OU ouvrir/fermer les sous-dossiers
      folderBtn.onclick = function() {
        if (isCurrent) return;
        if (hasSubs) {
          // Toggle sous-dossiers
          const isOpen = subsContainer.style.display !== 'none';
          subsContainer.style.display = isOpen ? 'none' : 'block';
          arrow.style.transform = isOpen ? '' : 'rotate(90deg)';
        } else {
          // Pas de sous-dossiers → déplacer directement
          doMoveFile(String(folder.id), '');
        }
      };

      // Double-clic ou bouton "Déposer ici" si a des sous-dossiers
      if (hasSubs && !isCurrent) {
        const moveHereBtn = document.createElement('button');
        moveHereBtn.textContent = '↳ Déposer dans ce dossier';
        moveHereBtn.style.cssText = 'display:block;width:100%;padding:7px 14px;margin-top:4px;margin-bottom:4px;border-radius:8px;border:1.5px dashed var(--teal);background:rgba(0,151,167,0.04);color:var(--teal-dark);cursor:pointer;font-size:12px;font-weight:600;text-align:left;font-family:Inter,sans-serif';
        var fId = folder.id;
        moveHereBtn.onclick = function(e) { e.stopPropagation(); doMoveFile(String(fId), ''); };
        subsContainer.appendChild(moveHereBtn);
      }

      // Sous-dossiers
      (folder.subfolders || []).forEach(function(sub) {
        const isCurrentSub = String(folder.id) === String(currentFolderId) && String(sub.id) === String(currentSubId);
        const subBtn = document.createElement('div');
        subBtn.style.cssText = 'display:flex;align-items:center;gap:10px;padding:9px 14px;border-radius:10px;border:1.5px solid ' + (isCurrentSub ? 'var(--teal)' : 'var(--border)') + ';background:' + (isCurrentSub ? 'rgba(0,151,167,0.06)' : 'var(--surface,white)') + ';cursor:pointer;font-size:12px;color:var(--text2);margin-bottom:4px';
        subBtn.innerHTML = '<span style="flex-shrink:0">📂</span><span style="flex:1">' + sub.name + '</span>' + (isCurrentSub ? '<small style="color:var(--text3);font-size:10px">📍 actuel</small>' : '');
        if (!isCurrentSub) {
          var fId2 = folder.id, sId2 = sub.id;
          subBtn.onclick = function() { doMoveFile(String(fId2), String(sId2)); };
          subBtn.onmouseover = function() { this.style.background = 'rgba(0,151,167,0.06)'; this.style.borderColor = 'var(--teal)'; };
          subBtn.onmouseout = function() { this.style.background = 'var(--surface,white)'; this.style.borderColor = 'var(--border)'; };
        }
        subsContainer.appendChild(subBtn);
      });

      row.appendChild(folderBtn);
      if (hasSubs) row.appendChild(subsContainer);
      container.appendChild(row);
    });

    if (!container.children.length) {
      container.innerHTML = '<div style="color:var(--text3);font-size:13px">Aucun dossier disponible</div>';
    }
  } catch(err) {
    container.innerHTML = '<div style="color:var(--danger);font-size:13px">Erreur: ' + err.message + '</div>';
  }
}


async function doMoveFile(toFolderId, toSubId) {
  if (!_fileModalData) return;
  const { fileId, folderId, subId } = _fileModalData;
  try {
    await api('POST', '/files/' + fileId + '/move', {
      fromFolderId: folderId, fromSubId: subId,
      toFolderId, toSubId
    });
    closeFileModal();
    toast('Fichier déplacé ✅');
    if (subId) await loadSubfolderFiles(subId, folderId);
    else await loadFiles();
  } catch(err) { toast(err.message, 'error'); }
}

// Remove old renameFile duplicate
// ── CENTRE DE DISCUSSIONS ────────────────────────────────────────────────────
let _allThreads = [];
let _discCenterFilter = 'all';

async function loadDiscussionsCenter() {
  // Toujours réinitialiser l'état visuel au retour sur la vue liste
  document.getElementById('disc-inline-view').style.display = 'none';
  document.getElementById('disc-center-list').style.display = 'block';
  _discussionFileId = null;
  _currentThreadId = null;
  stopDiscussionRefresh();
  const list = document.getElementById('disc-center-list');
  list.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text3)">Chargement...</div>';
  try {
    _allThreads = await api('GET', '/threads/all');
    // One-time: initialize lastSeen for threads never seen before
    // Use their createdAt so only NEW replies after first load appear red
    _lastSeenComments = loadLastSeen();
    var changed = false;
    _allThreads.forEach(function(t) {
      if (!_lastSeenComments['thread_' + t.threadId]) {
        _lastSeenComments['thread_' + t.threadId] = t.createdAt;
        changed = true;
      }
    });
    if (changed) {
      var key = getLastSeenKey();
      if (key) localStorage.setItem(key, JSON.stringify(_lastSeenComments));
      updateDiscCenterBadge();
    }
    renderDiscCenter();
    // Update global badge
    updateDiscCenterBadge();
  } catch(e) {
    list.innerHTML = '<div style="color:var(--danger);padding:20px">Erreur: ' + e.message + '</div>';
  }
}

function filterDiscCenter(filter) {
  _discCenterFilter = filter;
  ['all','open','resolved'].forEach(f => {
    const btn = document.getElementById('disc-filter-' + f);
    if (btn) {
      btn.style.background = f === filter ? 'var(--teal-dark)' : '';
      btn.style.color = f === filter ? 'white' : '';
    }
  });
  renderDiscCenter();
}

let _discSort = 'recent';
let _discFolderOpen = null;

function toggleDiscSort(e, btn) {
  e.stopPropagation();
  const menu = document.getElementById('disc-sort-dropdown');
  if (menu.style.display !== 'none') { menu.style.display = 'none'; return; }
  const rect = btn.getBoundingClientRect();
  menu.style.left = Math.round(rect.right - 210) + 'px';
  menu.style.top = Math.round(rect.bottom + 4) + 'px';
  menu.style.display = 'block';
  setTimeout(() => document.addEventListener('click', () => menu.style.display = 'none', { once: true }), 10);
}

function setDiscSort(sort) {
  _discSort = sort;
  _discFolderOpen = null;
  document.getElementById('disc-sort-dropdown').style.display = 'none';
  renderDiscCenter();
}

function renderDiscCenter() {
  const list = document.getElementById('disc-center-list');
  const prevScroll = list ? list.scrollTop : 0;
  let threads = _allThreads;
  if (_discCenterFilter === 'open') threads = threads.filter(t => !t.resolved);
  if (_discCenterFilter === 'resolved') threads = threads.filter(t => t.resolved);

  // Sort
  if (_discSort === 'recent') threads = [...threads].sort((a,b) => new Date(b.lastActivity) - new Date(a.lastActivity));
  else if (_discSort === 'open') threads = [...threads].sort((a,b) => a.resolved - b.resolved || new Date(b.lastActivity) - new Date(a.lastActivity));

  if (!threads.length) {
    list.innerHTML = '<div style="padding:48px;text-align:center;color:var(--text3)"><div style="font-size:32px;margin-bottom:12px">💬</div><div>Aucune discussion</div></div>';
    return;
  }

  // Group by folder if needed
  if (_discSort === 'folder') {
    const groups = {};
    threads.forEach(t => {
      const key = t.folderName || 'Sans dossier';
      if (!groups[key]) groups[key] = [];
      groups[key].push(t);
    });
    if (!_discFolderOpen) {
      let html = Object.entries(groups).sort().map(([folder, ts]) => {
        const openCount = ts.filter(t => !t.resolved).length;
        const _ls = loadLastSeen();
const unreadCount = ts.filter(t => {
  const ls = _ls['thread_' + t.threadId] ? new Date(_ls['thread_' + t.threadId]) : null;
  return ls ? new Date(t.lastActivity) > ls : true;
}).length;
return '<div class="disc-folder-card" data-folder="' + encodeURIComponent(folder) + '" style="display:flex;align-items:center;gap:12px;padding:16px 18px;border-radius:12px;border:1.5px solid var(--border);background:var(--surface,white);margin-bottom:8px;cursor:pointer;transition:box-shadow 0.15s">' +
  '<div style="width:40px;height:40px;border-radius:10px;background:rgba(0,151,167,0.1);display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0">📁</div>' +
  '<div style="flex:1">' +
    '<div style="font-weight:700;font-size:14px;color:var(--text)">' + folder + '</div>' +
    '<div style="font-size:12px;color:var(--text2);margin-top:2px">' + ts.length + ' discussion(s)' + (openCount ? ' · ' + openCount + ' ouverte(s)' : '') + '</div>' +
  '</div>' +
  (unreadCount > 0 ? '<span style="background:#ef5350;color:white;border-radius:10px;padding:2px 8px;font-size:11px;font-weight:700;min-width:20px;text-align:center">' + (unreadCount > 9 ? '9+' : unreadCount) + '</span>' : '') +
'</div>';
      }).join('');
      list.innerHTML = html;
      list.querySelectorAll('.disc-folder-card').forEach(function(card) {
        card.addEventListener('click', function() { openDiscFolder(decodeURIComponent(card.dataset.folder)); });
      });
      return;
    }
    const ts = groups[_discFolderOpen] || [];
    const _lastSeen = loadLastSeen();
    let html = '<button class="btn-action" onclick="closeDiscFolderView()" style="margin-bottom:14px">← Retour aux dossiers</button>';
    html += '<div style="font-size:14px;font-weight:700;color:var(--text);margin-bottom:12px">📁 ' + _discFolderOpen + '</div>';
    html += ts.map(t => {
      const threadSeenKey = 'thread_' + t.threadId;
      const lastSeenTime = _lastSeen[threadSeenKey] ? new Date(_lastSeen[threadSeenKey]) : null;
      const isNew = lastSeenTime ? new Date(t.lastActivity) > lastSeenTime : true;
      return renderThreadCard(t, isNew);
    }).join('');
    list.innerHTML = html;
    attachDiscCenterListeners();
    return;
  }
  
  const _lastSeen = loadLastSeen();

  list.innerHTML = threads.map(function(t) {
    const threadSeenKey = 'thread_' + t.threadId;
    const lastSeenTime = _lastSeen[threadSeenKey] ? new Date(_lastSeen[threadSeenKey]) : null;
    const isNew = lastSeenTime ? new Date(t.lastActivity) > lastSeenTime : true;
   return renderThreadCard(t, isNew);
  }).join('');
  attachDiscCenterListeners();
  const savedScroll = loadNavState('lastDiscCenterScroll');
  if (savedScroll) setTimeout(() => { if (list) list.scrollTop = savedScroll.top; }, 50);
}
function openDiscFolder(name) { _discFolderOpen = name; renderDiscCenter(); }
function closeDiscFolderView() { _discFolderOpen = null; renderDiscCenter(); }

function renderThreadCard(t, isNew) {
  var date = new Date(t.lastActivity).toLocaleString('fr-FR', { day:'numeric', month:'short', hour:'2-digit', minute:'2-digit' });
  var div = document.createElement('div');
  div.className = 'disc-center-card';
  div.style.cssText = 'display:flex;align-items:center;gap:10px;padding:14px 16px;border-radius:12px;border:1.5px solid ' + (isNew ? 'var(--teal)' : 'var(--border)') + ';background:' + (isNew ? 'rgba(0,151,167,0.04)' : 'var(--surface,white)') + ';margin-bottom:8px;cursor:pointer;transition:box-shadow 0.15s';
  div.onmouseover = function() { this.style.boxShadow = '0 4px 12px var(--shadow)'; };
  div.onmouseout = function() { this.style.boxShadow = ''; };
  div.setAttribute('data-fid', t.fileId);
  div.setAttribute('data-fname', encodeURIComponent(t.fileName));
  div.setAttribute('data-tid', t.threadId);
  div.innerHTML =
    '<input type="checkbox" class="disc-center-cb" data-tid="' + t.threadId + '" data-fid="' + t.fileId + '" onclick="event.stopPropagation()" onchange="onDiscCenterCheckboxChange()" style="display:none;width:18px;height:18px;cursor:pointer;accent-color:var(--teal);flex-shrink:0">' +
    '<div style="flex:1;min-width:0">' +
    '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">' +
      (isNew ? '<span style="width:8px;height:8px;border-radius:50%;background:#ef5350;flex-shrink:0;display:inline-block"></span>' : '') +
      (t.resolved ? '<span style="background:#2E7D32;color:white;border-radius:6px;padding:2px 8px;font-size:10px;font-weight:700">✓ Résolu</span>' : '<span style="background:rgba(0,151,167,0.1);color:var(--teal-dark);border-radius:6px;padding:2px 8px;font-size:10px;font-weight:700">💬 Ouvert</span>') +
      '<span style="font-size:11px;color:var(--text3)">' + (t.folderName || '') + '</span>' +
    '</div>' +
    '<div style="font-weight:700;font-size:14px;color:var(--text);margin-bottom:4px">' + t.title + '</div>' +
    '<div style="display:flex;align-items:center;justify-content:space-between;font-size:11px;color:var(--text3)">' +
      '<span>📄 ' + t.fileName + '</span>' +
      '<span>' + t.replyCount + ' rép. · ' + date + '</span>' +
    '</div>' +
    '</div>';
  return div.outerHTML;
}

// ── Sélection multiple "Toutes les discussions" ───────────────────────────────
let _discCenterSelectionMode = false;

function attachDiscCenterListeners() {
  document.querySelectorAll('#disc-center-list .disc-center-card').forEach(function(card) {
    var fid = card.getAttribute('data-fid');
    var fname = card.getAttribute('data-fname');
    var tid = parseInt(card.getAttribute('data-tid'));
    var timer = null; var startX = 0; var startY = 0; var longPressed = false; var didScroll = false;
    card.addEventListener('touchstart', function(e) {
      startX = e.touches[0].clientX; startY = e.touches[0].clientY; longPressed = false; didScroll = false;
      timer = setTimeout(function() { longPressed = true; if (navigator.vibrate) navigator.vibrate(50); enterDiscCenterSelection(tid); }, 500);
    }, { passive: true });
    card.addEventListener('touchmove', function(e) {
      if (Math.abs(e.touches[0].clientX-startX) > 8 || Math.abs(e.touches[0].clientY-startY) > 8) { clearTimeout(timer); didScroll = true; }
    }, { passive: true });
    card.addEventListener('touchend', function(e) {
      clearTimeout(timer);
      if (longPressed) { longPressed = false; e.preventDefault(); e.stopPropagation(); return; }
      if (didScroll) return;
      if (_discCenterSelectionMode) { var cb = card.querySelector('.disc-center-cb'); if (cb) { cb.checked = !cb.checked; onDiscCenterCheckboxChange(); } }
      else goToThread(fid, decodeURIComponent(fname), tid);
    });
    card.addEventListener('mousedown', function() { longPressed = false; timer = setTimeout(function() { longPressed = true; enterDiscCenterSelection(tid); }, 600); });
    card.addEventListener('mouseup', function() { clearTimeout(timer); });
    card.addEventListener('mouseleave', function() { clearTimeout(timer); });
    card.addEventListener('click', function(e) {
      if (longPressed) { e.stopPropagation(); return; }
      if (_discCenterSelectionMode) { var cb = card.querySelector('.disc-center-cb'); if (cb) { cb.checked = !cb.checked; onDiscCenterCheckboxChange(); } }
      else goToThread(fid, decodeURIComponent(fname), tid);
    });
  });
}

function enterDiscCenterSelection(firstTid) {
  _discCenterSelectionMode = true;
  document.querySelectorAll('#disc-center-list .disc-center-cb').forEach(cb => cb.style.display = 'inline-block');
  const cb = document.querySelector('#disc-center-list .disc-center-cb[data-tid="' + firstTid + '"]');
  if (cb) cb.checked = true;
  document.getElementById('disc-delete-selected-btn').style.display = 'block';
  document.getElementById('disc-cancel-selection-btn').style.display = 'block';
  document.getElementById('disc-refresh-btn').style.display = 'none';
  onDiscCenterCheckboxChange();
}

function exitDiscCenterSelection() {
  _discCenterSelectionMode = false;
  document.querySelectorAll('#disc-center-list .disc-center-cb').forEach(cb => { cb.style.display = 'none'; cb.checked = false; });
  document.getElementById('disc-delete-selected-btn').style.display = 'none';
  document.getElementById('disc-cancel-selection-btn').style.display = 'none';
  document.getElementById('disc-refresh-btn').style.display = 'block';
}

function onDiscCenterCheckboxChange() {
  const checked = document.querySelectorAll('#disc-center-list .disc-center-cb:checked');
  document.getElementById('disc-delete-selected-btn').style.display = checked.length > 0 ? 'block' : 'none';
}

async function deleteSelectedDiscCenter() {
  const checked = document.querySelectorAll('#disc-center-list .disc-center-cb:checked');
  if (!checked.length) return;
  if (!await customConfirm('Supprimer ' + checked.length + ' fil(s) ?')) return;
  for (const cb of checked) {
    var fid = cb.getAttribute('data-fid');
    var tid = cb.getAttribute('data-tid');
    try { await api('DELETE', '/threads/' + fid + '/' + tid); } catch(e) {}
  }
  exitDiscCenterSelection();
  await loadDiscussionsCenter();
}

function goToThreadEl(el) {
  var fid = el.getAttribute('data-fid');
  var fname = el.getAttribute('data-fname');
  var tid = parseInt(el.getAttribute('data-tid'));
  goToThread(fid, decodeURIComponent(fname), tid);
}

async function goToThread(fileId, fileName, threadId) {
  _discussionFileId = fileId;
  _discussionFileName = fileName;
  _currentThreadId = threadId || null;

  // Afficher le panel sans déclencher loadDiscussionsCenter
  document.querySelectorAll('.panel').forEach(p=>{p.classList.remove('active');p.style.display='none';});
  const target = document.getElementById('panel-discussions-center');
  target.classList.add('active');
  target.style.display = 'block';
  // Show inline discussion view, hide disc center list
  document.getElementById('disc-center-list').style.display = 'none';
  document.getElementById('disc-inline-view').style.display = 'block';
  const sb = document.getElementById('topbar-search'); if(sb) sb.style.display='none';
  var discControls = document.getElementById('disc-controls-bar');
  if (discControls) discControls.style.display = 'none';
  var discFilters = document.getElementById('disc-filters-bar');
  if (discFilters) discFilters.style.display = 'none';
  document.getElementById('inline-disc-filename').textContent = '💬 ' + fileName;

  if (threadId) {
    // Go directly to thread - skip list
    document.getElementById('threads-list-view2').style.display = 'none';
    document.getElementById('thread-detail-view2').style.display = 'block';
    const tb = document.querySelector('.topbar'); if(tb) tb.style.display='none';
    const aa = document.getElementById('thread-admin-actions2');
    if (aa) aa.style.display = currentUser?.role === 'admin' ? 'block' : 'none';
    await new Promise(r => requestAnimationFrame(r));
    await new Promise(r => requestAnimationFrame(r));
    await new Promise(r => setTimeout(r, 100));
    await loadThreadRepliesInline();
  } else {
    // Show threads list
    document.getElementById('threads-list-view2').style.display = 'block';
    document.getElementById('thread-detail-view2').style.display = 'none';
    await loadThreadsInline(false);
  }
  startDiscussionRefresh();
}

function closeInlineDiscussion() {
  stopDiscussionRefresh();
  window.scrollTo({top: 0, behavior: 'instant'});
  document.getElementById('disc-inline-view').style.display = 'none';
  const topbar = document.querySelector('.topbar'); if(topbar) topbar.style.display='flex';
  const sb = document.getElementById('topbar-search'); if(sb) sb.style.display='block';
  document.getElementById('thread-detail-view2').style.display = 'none';
  document.getElementById('threads-list-view2').style.display = 'block';
  document.getElementById('disc-center-list').style.display = 'block';
  var discControls = document.getElementById('disc-controls-bar');
  if (discControls) discControls.style.display = 'flex';
  var discFilters = document.getElementById('disc-filters-bar');
  if (discFilters) discFilters.style.display = 'flex';
  _discussionFileId = null;
  _currentThreadId = null;
  // Reload all threads from server to get fresh data, then update UI
  api('GET', '/threads/all').then(function(threads) {
    _allThreads = threads;
    renderDiscCenter();
    updateDiscCenterBadge();
  }).catch(function() {
    renderDiscCenter();
    updateDiscCenterBadge();
  });
}

async function loadThreadsInline(silent) {
  const list = document.getElementById('threads-list2');
  const countEl = document.getElementById('inline-threads-count');
  if (!silent) list.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3)">Chargement...</div>';
  try {
    const threads = await api('GET', '/threads/' + _discussionFileId);
    if (countEl) countEl.textContent = threads.length + ' fil' + (threads.length > 1 ? 's' : '');
    if (!threads.length) {
      list.innerHTML = '<div style="text-align:center;padding:48px;color:var(--text3)"><div style="font-size:40px;margin-bottom:12px">💬</div><div>Aucune question pour l&#39;instant</div></div>';
      return;
    }
    threads.sort(function(a,b) { return a.resolved - b.resolved || new Date(b.lastReplyAt) - new Date(a.lastReplyAt); });

    list.innerHTML = threads.map(function(t) {
      var date = new Date(t.lastReplyAt||t.createdAt).toLocaleString('fr-FR', { day:'numeric', month:'short', hour:'2-digit', minute:'2-digit' });
      return '<div data-thread-id="' + t.id + '" onclick="handleThreadCardClick(event,' + t.id + ')" style="display:flex;align-items:flex-start;gap:14px;padding:16px 20px;background:var(--surface,white);border-radius:14px;border:1.5px solid ' + (t.resolved?'rgba(46,125,50,0.3)':'var(--border)') + ';margin-bottom:10px;cursor:pointer;transition:background 0.15s,border-color 0.15s" class="thread-card">' +
        '<div style="flex:1">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap">' +
            (t.resolved?'<span style="background:#2E7D32;color:white;border-radius:8px;padding:4px 10px;font-size:11px;font-weight:700">✓ Résolu</span>':'<span style="background:rgba(0,151,167,0.1);color:var(--teal-dark);border-radius:8px;padding:4px 10px;font-size:11px;font-weight:700">💬 Ouvert</span>') +
            '<span style="font-weight:700;font-size:15px;color:var(--text)">' + t.title + '</span>' +
          '</div>' +
          '<div style="font-size:12px;color:var(--text3)">' + date + ' · ' + (t.replyCount||0) + ' réponse' + ((t.replyCount||0)>1?'s':'') + '</div>' +
        '</div>' +
        '<svg viewBox="0 0 24 24" fill="currentColor" style="width:16px;height:16px;color:var(--text3);flex-shrink:0;margin-top:4px"><path d="M8.59 16.59L13.17 12 8.59 7.41 10 6l6 6-6 6z"/></svg>' +
      '<div style="display:flex;align-items:center;gap:6px;flex-shrink:0">' +
        '<input type="checkbox" class="thread-select-cb" data-tid="' + t.id + '" onclick="event.stopPropagation()" onchange="onThreadCheckboxChange()" style="display:none;width:18px;height:18px;cursor:pointer;accent-color:var(--teal)">' +
        '<button onclick="event.stopPropagation();deleteThreadInline(' + t.id + ')" style="display:none;width:28px;height:28px;border-radius:8px;border:none;background:rgba(229,115,115,0.1);color:var(--danger);cursor:pointer;display:none;align-items:center;justify-content:center" class="thread-del-btn"><svg viewBox="0 0 24 24" fill="currentColor" style="width:13px;height:13px"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg></button>' +
      '</div>' +
      '</div>';
    }).join('');
    // Attach long press handlers after render
    document.querySelectorAll('#threads-list2 .thread-card').forEach(function(card) {
      var tid = parseInt(card.getAttribute('data-thread-id'));
      var timer = null; var startX = 0; var startY = 0;
      card.addEventListener('touchstart', function(e) {
        startX = e.touches[0].clientX; startY = e.touches[0].clientY;
        timer = setTimeout(function() {
          if (navigator.vibrate) navigator.vibrate(50);
          enterThreadSelectionMode(tid);
        }, 500);
      }, { passive: true });
      card.addEventListener('touchstart', function(e) {
        startX = e.touches[0].clientX; startY = e.touches[0].clientY; longPressed = false;
        timer = setTimeout(function() { longPressed = true; if (navigator.vibrate) navigator.vibrate(50); enterThreadSelectionMode(tid); }, 500);
      }, { passive: true });
      card.addEventListener('touchmove', function(e) {
        if (Math.abs(e.touches[0].clientX-startX) > 10 || Math.abs(e.touches[0].clientY-startY) > 10) clearTimeout(timer);
      }, { passive: true });
      card.addEventListener('touchend', function(e) { clearTimeout(timer); if (longPressed) { longPressed = false; e.preventDefault(); e.stopPropagation(); } });
      card.addEventListener('mousedown', function() { longPressed = false; timer = setTimeout(function() { longPressed = true; enterThreadSelectionMode(tid); }, 600); });
      card.addEventListener('mouseup', function() { clearTimeout(timer); });
      card.addEventListener('mouseleave', function() { clearTimeout(timer); });
    });
  } catch(e) {
    list.innerHTML = '<div style="color:var(--danger);padding:20px">Erreur: ' + e.message + '</div>';
  }
  updateDiscCenterBadge();
}

async function openThreadInline(threadId) {
  const discList = document.getElementById('disc-center-list');
  if (discList) saveNavState('lastDiscCenterScroll', { top: discList.scrollTop });
  _currentThreadId = threadId;
  document.getElementById('threads-list-view2').style.display = 'none';
  document.getElementById('thread-detail-view2').style.display = 'block';
  const discControls = document.getElementById('disc-controls-bar'); if(discControls) discControls.style.display='none'; const discFilters = document.getElementById('disc-filters-bar'); if(discFilters) discFilters.style.display='none';
  const topbar = document.querySelector('.topbar'); if(topbar) topbar.style.display='none';
  const resolveBtn2 = document.getElementById('resolve-btn2');
  if (resolveBtn2) resolveBtn2.style.display = currentUser?.role === 'admin' ? 'inline-block' : 'none';
  updateMuteBtn2();
  await loadThreadRepliesInline();
}
function updateMuteBtn2() {
  const btn = document.getElementById('mute-btn2');
  if (!btn) return;
  const muted = (currentUser?.mutedThreads || []).includes(_currentThreadId);
  btn.textContent = muted ? '🔕' : '🔔';
  btn.title = muted ? 'Réactiver les notifications' : 'Mettre en sourdine';
  btn.style.color = muted ? 'var(--danger)' : 'var(--text2)';
}
async function toggleMuteThread2() {
  try {
    const res = await api('POST', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/mute');
    if (!currentUser.mutedThreads) currentUser.mutedThreads = [];
    const idx = currentUser.mutedThreads.indexOf(_currentThreadId);
    if (res.muted && idx === -1) currentUser.mutedThreads.push(_currentThreadId);
    else if (!res.muted && idx !== -1) currentUser.mutedThreads.splice(idx, 1);
    updateMuteBtn2();
    toast(res.muted ? 'Discussion mise en sourdine' : 'Notifications réactivées', 'success');
  } catch(e) {
    toast('Erreur', 'error');
  }
}

function backToThreads2() {
  closeInlineDiscussion();
}

async function loadThreadRepliesInline(silent) {
  if (!currentUser) {
    try { currentUser = await api('GET', '/me'); } catch(e) {}
  }
  // Mark this thread as seen
  if (_currentThreadId) {
    _lastSeenComments['thread_' + _currentThreadId] = new Date().toISOString();
    const key = getLastSeenKey();
    if (key) localStorage.setItem(key, JSON.stringify(_lastSeenComments));
    updateDiscCenterBadge();
  }
  const container = document.getElementById('thread-replies2');
  const prevScrollTop = container.scrollTop;
  const prevScrollHeight = container.scrollHeight;
  const wasAtBottom = prevScrollHeight - prevScrollTop - container.clientHeight < 100;
  if (!silent) container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3)">Chargement...</div>';
  try {
    const data = await api('GET', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/replies');
    _mentionables = (data.mentionables || []).filter(u => u.id !== currentUser?.id);
    // Show "filename > thread title"
    var fname = _discussionFileName || '';
    try { fname = decodeURIComponent(fname); } catch(e) {}
    document.getElementById('thread-title-display2').innerHTML = 
      '<span style="font-size:12px;color:var(--teal-dark);font-weight:700;display:block;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px">📄 ' + fname + '</span>' +
      '<span style="font-size:18px;font-weight:800;color:var(--text)">' + data.thread.title + '</span>';
    const resolveBtn = document.getElementById('resolve-btn2');
    if (resolveBtn) {
      resolveBtn.textContent = data.thread.resolved ? '✓ Résolu' : '○ Marquer résolu';
      resolveBtn.style.background = data.thread.resolved ? 'transparent' : '#2E7D32';
      resolveBtn.style.color = data.thread.resolved ? '#2E7D32' : 'white';
    }
    if (!data.replies.length) {
      container.innerHTML = '<div style="padding:32px;text-align:center;color:var(--text3)">Aucune réponse — sois le premier !</div>';
      return;
    }
    _repliesCache = data.replies;
    container.innerHTML = data.replies.map(function(r) {
      var isMine = currentUser != null && String(r.userId) === String(currentUser.id);
      var isAdmin = r.userRole === 'admin' || r.userRole === 'subadmin';
      var date = new Date(r.createdAt).toLocaleString('fr-FR', { day:'numeric', month:'short', hour:'2-digit', minute:'2-digit' });
      var initials = (r.userName||'?').split(' ').map(function(w){return w[0];}).join('').substring(0,2).toUpperCase();
      var avatarBg = isAdmin ? 'linear-gradient(135deg,#004D61,#003340)' : 'linear-gradient(135deg,var(--teal),var(--teal-dark))';
      var avatarHtml = r.userAvatar ? '<img src="' + r.userAvatar + '" style="width:100%;height:100%;object-fit:cover">' : initials;
      var bubbleBg = isMine ? 'linear-gradient(135deg,var(--teal),var(--teal-dark))' : 'rgba(255,255,255,0.15)';
      var bubbleColor = isMine ? 'white' : 'var(--text)';
      var bubbleBorder = isMine ? 'none' : '1px solid var(--border)';
      // Audio
      var msgHtml;
      if (r.audio) {
        var durSec = r.audioDuration || 0;
        var durStr = Math.floor(durSec/60) + ':' + (durSec%60<10?'0':'') + durSec%60;
        var aId = 'ia-' + r.id; var bId = 'ib-' + r.id; var barId = 'ic-' + r.id; var tId = 'it-' + r.id;
        msgHtml = '<audio id="' + aId + '" src="' + r.audio + '" style="display:none"></audio>' +
          '<div style="display:flex;align-items:center;gap:10px;padding:4px 0;min-width:160px">' +
          '<button id="' + bId + '" onclick="toggleInlineAudio(\'' + aId + '\',\'' + bId + '\',\'' + barId + '\',\'' + tId + '\',event)" style="width:32px;height:32px;border-radius:50%;background:' + (isMine?'rgba(255,255,255,0.25)':'var(--teal-dark)') + ';color:white;border:none;cursor:pointer;font-size:14px;flex-shrink:0">▶</button>' +
          '<canvas id="' + barId + '" data-mine="' + isMine + '" height="28" style="width:120px;height:28px;border-radius:3px;display:block"></canvas>' +
          '<div style="display:flex;justify-content:space-between;font-size:10px;color:' + (isMine?'rgba(255,255,255,0.7)':'var(--text3)') + '"><span id="' + tId + '">0:00</span><span>🎤 ' + durStr + '</span></div>' +
          '</div>';
      } else {
        msgHtml = (r.message||'').split('\n').join('<br>')
          .replace(/@\[([^\]]+)\]/g, function(m, name) { return renderMention(name, isMine); })
          .replace(/(?<!\])\B@([\w\-éèêëàâùûüôîïçÀ-ÿ][^\s@<]*(?:\s+[\w\-éèêëàâùûüôîïçÀ-ÿ][^\s@<]*)?)/g, function(m, name) { return renderMention(name, isMine); });
      }
      if (r.imageUrl) {
        msgHtml += '<div style="margin-top:6px"><img src="' + r.imageUrl + '" style="max-width:220px;max-height:200px;border-radius:10px;display:block;cursor:pointer" onclick=\"openImageLightbox(this.src)\"></div>';
      }
     var canDelete = currentUser && (currentUser.role === 'admin' || String(r.userId) === String(currentUser.id));
      var reactHtml = '';
      if (r.reactions && Object.keys(r.reactions).length) {
        reactHtml += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:4px">';
        Object.entries(r.reactions).forEach(function(entry) {
          var em = entry[0], users = entry[1];
          if (!users || !users.length) return;
          var iReacted = users.indexOf(currentUser ? currentUser.id : -1) !== -1;
          reactHtml += '<button onclick="reactMsg(' + JSON.stringify(em) + ',' + r.id + ')" style="display:flex;align-items:center;gap:3px;padding:2px 8px;border-radius:20px;border:1.5px solid ' + (iReacted ? 'var(--teal)' : 'var(--border)') + ';background:' + (iReacted ? 'rgba(0,151,167,0.1)' : 'transparent') + ';cursor:pointer;font-size:12px">' + em + ' ' + users.length + '</button>';
        });
        reactHtml += '</div>';
      }
      var row = '<div style="width:100%;display:flex;flex-direction:column;margin-bottom:10px;align-items:' + (isMine?'flex-end':'flex-start') + '">';
      if (!isMine) row += '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;padding-left:42px"><span style="font-size:11px;font-weight:700;color:' + (isAdmin?'var(--teal-dark)':'var(--text2)') + '">' + (r.userName||'') + (isAdmin?' 👨‍🏫':'') + '</span><span style="font-size:10px;color:var(--text3)">' + date + '</span></div>';
      row += '<div style="display:flex;align-items:flex-end;gap:8px;max-width:78%;margin:' + (isMine?'0 8px 0 auto':'0 auto 0 8px') + '">';
      if (!isMine) row += '<div style="width:32px;height:32px;border-radius:50%;background:' + avatarBg + ';display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:white;flex-shrink:0;overflow:hidden;margin-bottom:2px">' + avatarHtml + '</div>';
      row += '<div>';
      row += '<div data-cid="' + r.id + '" class="msg-bubble" style="background:' + bubbleBg + ';color:' + bubbleColor + ';border:' + bubbleBorder + ';border-left:' + (isAdmin && !isMine ? '3px solid var(--teal)' : bubbleBorder) + ';border-radius:' + (isMine?'18px 18px 4px 18px':'18px 18px 18px 4px') + ';padding:10px 14px;font-size:14px;line-height:1.5;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)">';
      if (r.replyToName) row += '<div style="opacity:0.8;font-size:11px;border-left:2px solid rgba(255,255,255,0.5);padding:2px 6px;margin-bottom:4px">↩ ' + r.replyToName + ': ' + String(r.replyToPreview||'').substring(0,40) + '</div>';
      row += msgHtml + '</div></div></div>';
      if (isMine) row += '<div style="font-size:10px;color:var(--text3);margin-top:3px;text-align:right">' + date + '</div>';
      row += reactHtml;
      row += '</div>';
      return row;
    }).join('');
    if (!silent || wasAtBottom) {
      container.scrollTop = container.scrollHeight; if (!silent) window.scrollTo({top: document.body.scrollHeight, behavior: 'smooth'});
    } else {
      container.scrollTop = prevScrollTop + (container.scrollHeight - prevScrollHeight);
    }
    setTimeout(function() {
      container.querySelectorAll('canvas[data-mine]').forEach(function(canvas) {
        canvas.width = 120;
        canvas.height = 28;
        redrawWaveformProgress(canvas, 0);
      });
    }, 300);
    data.replies.forEach(function(r) {
      _commentDataMap[r.id] = { id: r.id, userId: r.userId, userName: r.userName, message: r.message||'', audio: r.audio||null, isOwn: String(r.userId) === String(currentUser?.id), canDelete: (currentUser?.role==='admin') || String(r.userId) === String(currentUser?.id) };
    });
    initBubbleEvents('thread-replies2');
  } catch(e) {
    container.innerHTML = '<div style="color:var(--danger);padding:20px">Erreur: ' + e.message + '</div>';
  }
}

function openImageLightbox(src) {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.92);z-index:99999;display:flex;align-items:center;justify-content:center';
  overlay.innerHTML = '<img src="' + src + '" style="max-width:95vw;max-height:90vh;border-radius:10px;object-fit:contain"><button onclick="this.parentElement.remove()" style="position:absolute;top:16px;right:16px;background:rgba(255,255,255,0.15);border:none;color:white;font-size:28px;width:44px;height:44px;border-radius:50%;cursor:pointer;line-height:1">×</button>';
  overlay.onclick = function(e) { if (e.target === overlay) overlay.remove(); };
  document.body.appendChild(overlay);
}

function showNewThreadForm2() {
  document.getElementById('new-thread-form2').style.display = 'block';
  document.getElementById('new-thread-title2').focus();
}
function hideNewThreadForm2() {
  document.getElementById('new-thread-form2').style.display = 'none';
  document.getElementById('new-thread-title2').value = '';
}

async function toggleRecording2() {
  if (_mediaRecorder && _mediaRecorder.state === 'recording') {
    _mediaRecorder.stop();
    return;
  }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    _audioChunks = [];
    _mediaRecorder = new MediaRecorder(stream);
    _mediaRecorder.ondataavailable = function(e) { _audioChunks.push(e.data); };
    _mediaRecorder.onstop = function() {
      stream.getTracks().forEach(function(t) { t.stop(); });
      var blob = new Blob(_audioChunks, { type: 'audio/webm' });
      clearInterval(_recordTimer);
      document.getElementById('record-timer2').style.display = 'none';
      document.getElementById('record-label2').textContent = '🎤 Vocal';
      var rb = document.getElementById('record-btn2');
      if (rb) { rb.style.borderColor = 'var(--border)'; rb.style.color = 'var(--text2)'; }
      var reader = new FileReader();
      reader.onload = async function() {
        try {
          await api('POST', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/replies', {
            message: '', audio: reader.result, audioDuration: _recordSeconds
          });
          await loadThreadRepliesInline(true);
        } catch(e) { toast(e.message, 'error'); }
      };
      reader.readAsDataURL(blob);
    };
    _mediaRecorder.start();
    _recordSeconds = 0;
    document.getElementById('record-timer2').style.display = 'inline';
    document.getElementById('record-label2').textContent = '⏹ Stop';
    var rb = document.getElementById('record-btn2');
    if (rb) { rb.style.borderColor = '#ef5350'; rb.style.color = '#ef5350'; }
    _recordTimer = setInterval(function() {
      _recordSeconds++;
      var m = Math.floor(_recordSeconds/60);
      var s = _recordSeconds % 60;
      document.getElementById('record-timer2').textContent = '⏺ ' + m + ':' + (s<10?'0':'') + s;
      if (_recordSeconds >= 120) _mediaRecorder.stop();
    }, 1000);
  } catch(e) {
    toast('Micro non disponible: ' + e.message, 'error');
  }
}

let _threadSelectionMode = false;
let _threadLongPressTimer = null;
let _threadSelectionModeMain = false;
let _threadLongPressTimerMain = null;
let _threadSelectionModeSb = false;

function enterThreadSelectionModeSb(firstThreadId) {
  _threadSelectionModeSb = true;
  document.querySelectorAll('#threads-list .thread-select-cb-sb').forEach(cb => cb.style.display = 'inline-block');
  const cb = document.querySelector('#threads-list .thread-select-cb-sb[data-tid="' + firstThreadId + '"]');
  if (cb) cb.checked = true;
  document.getElementById('delete-selected-btn-sb').style.display = 'block';
  document.getElementById('cancel-selection-btn-sb').style.display = 'block';
  document.getElementById('new-thread-btn-sb').style.display = 'none';
  onThreadCheckboxChangeSb();
}

function exitThreadSelectionModeSb() {
  _threadSelectionModeSb = false;
  document.querySelectorAll('#threads-list .thread-select-cb-sb').forEach(cb => { cb.style.display = 'none'; cb.checked = false; });
  document.getElementById('delete-selected-btn-sb').style.display = 'none';
  document.getElementById('cancel-selection-btn-sb').style.display = 'none';
  document.getElementById('new-thread-btn-sb').style.display = 'flex';
}

function onThreadCheckboxChangeSb() {
  const checked = document.querySelectorAll('#threads-list .thread-select-cb-sb:checked');
  document.getElementById('delete-selected-btn-sb').style.display = checked.length > 0 ? 'block' : 'none';
}

async function deleteSelectedThreadsSb() {
  const checked = document.querySelectorAll('#threads-list .thread-select-cb-sb:checked');
  if (!checked.length) return;
  if (!await customConfirm('Supprimer ' + checked.length + ' fil(s) ?')) return;
  const ids = Array.from(checked).map(cb => cb.getAttribute('data-tid'));
  for (const id of ids) {
    try { await api('DELETE', '/threads/' + _discussionFileId + '/' + id); } catch(e) {}
  }
  exitThreadSelectionModeSb();
  await loadThreads(false);
}

function threadLongPressStartMain(e, threadId) {
  _threadLongPressTimerMain = setTimeout(function() {
    if (navigator.vibrate) navigator.vibrate(50);
    enterThreadSelectionModeMain(threadId);
  }, 500);
}
function threadLongPressEndMain() { clearTimeout(_threadLongPressTimerMain); }

function enterThreadSelectionModeMain(firstThreadId) {
  _threadSelectionModeMain = true;
  document.querySelectorAll('.thread-select-cb-main').forEach(cb => cb.style.display = 'inline-block');
  const cb = document.querySelector('.thread-select-cb-main[data-tid="' + firstThreadId + '"]');
  if (cb) { cb.checked = true; }
  const delBtn = document.getElementById('delete-selected-btn-main');
  if (delBtn) delBtn.style.display = 'block';
  const cancelBtn = document.getElementById('cancel-selection-btn-main');
  if (cancelBtn) cancelBtn.style.display = 'block';
  onThreadCheckboxChangeMain();
}

function exitThreadSelectionModeMain() {
  _threadSelectionModeMain = false;
  document.querySelectorAll('.thread-select-cb-main').forEach(cb => { cb.style.display = 'none'; cb.checked = false; });
  const delBtn = document.getElementById('delete-selected-btn-main');
  if (delBtn) delBtn.style.display = 'none';
  const cancelBtn = document.getElementById('cancel-selection-btn-main');
  if (cancelBtn) cancelBtn.style.display = 'none';
}

function handleThreadCardClickMain(e, threadId) {
  if (_threadSelectionModeMain) {
    e.stopPropagation();
    const cb = document.querySelector('.thread-select-cb-main[data-tid="' + threadId + '"]');
    if (cb) { cb.checked = !cb.checked; onThreadCheckboxChangeMain(); }
  } else {
    openThread(threadId);
  }
}

function onThreadCheckboxChangeMain() {
  const checked = document.querySelectorAll('.thread-select-cb-main:checked');
  const btn = document.getElementById('delete-selected-btn-main');
  if (btn) btn.style.display = checked.length > 0 ? 'block' : 'none';
}

async function deleteSelectedThreadsMain() {
  const checked = document.querySelectorAll('.thread-select-cb-main:checked');
  if (!checked.length) return;
  if (!await customConfirm('Supprimer ' + checked.length + ' fil(s) ?')) return;
  const ids = Array.from(checked).map(cb => cb.getAttribute('data-tid'));
  for (const id of ids) {
    try { await api('DELETE', '/threads/' + _discussionFileId + '/' + id); } catch(e) {}
  }
  exitThreadSelectionModeMain();
  await loadThreads(false);
}

function threadLongPressStart(e, threadId) {
  _threadLongPressTimer = setTimeout(function() {
    if (navigator.vibrate) navigator.vibrate(50);
    enterThreadSelectionMode(threadId);
  }, 500);
}
function threadLongPressEnd() { clearTimeout(_threadLongPressTimer); }

function enterThreadSelectionMode(firstThreadId) {
  _threadSelectionMode = true;
  // Show checkboxes and delete buttons on all cards
  document.querySelectorAll('.thread-select-cb').forEach(cb => cb.style.display = 'inline-block');
  document.querySelectorAll('.thread-del-btn').forEach(btn => btn.style.display = 'flex');
  // Check the first selected thread
  const cb = document.querySelector('.thread-select-cb[data-tid="' + firstThreadId + '"]');
  if (cb) { cb.checked = true; }
  // Show cancel + delete buttons
  const delBtn = document.getElementById('delete-selected-btn');
  if (delBtn) delBtn.style.display = 'block';
  const cancelBtn = document.getElementById('cancel-selection-btn');
  if (cancelBtn) cancelBtn.style.display = 'block';
  onThreadCheckboxChange();
}

function exitThreadSelectionMode() {
  _threadSelectionMode = false;
  document.querySelectorAll('.thread-select-cb').forEach(cb => { cb.style.display = 'none'; cb.checked = false; });
  document.querySelectorAll('.thread-del-btn').forEach(btn => btn.style.display = 'none');
  const delBtn = document.getElementById('delete-selected-btn');
  if (delBtn) delBtn.style.display = 'none';
  const cancelBtn = document.getElementById('cancel-selection-btn');
  if (cancelBtn) cancelBtn.style.display = 'none';
}

function handleThreadCardClick(e, threadId) {
  if (_threadSelectionMode) {
    e.stopPropagation();
    const cb = document.querySelector('.thread-select-cb[data-tid="' + threadId + '"]');
    if (cb) { cb.checked = !cb.checked; onThreadCheckboxChange(); }
  } else {
    openThreadInline(threadId);
  }
}

function onThreadCheckboxChange() {
  const checked = document.querySelectorAll('.thread-select-cb:checked');
  const btn = document.getElementById('delete-selected-btn');
  if (btn) btn.style.display = checked.length > 0 ? 'block' : 'none';
}

async function deleteSelectedThreads() {
  const checked = document.querySelectorAll('.thread-select-cb:checked');
  if (!checked.length) return;
  if (!await customConfirm('Supprimer ' + checked.length + ' fil(s) ?')) return;
  const ids = Array.from(checked).map(cb => cb.getAttribute('data-tid'));
  for (const id of ids) {
    try { await api('DELETE', '/threads/' + _discussionFileId + '/' + id); } catch(e) {}
  }
  exitThreadSelectionMode();
  await loadThreadsInline(false);
}

function showThreadsList() {
  _currentThreadId = null;
  document.getElementById('thread-detail-view2').style.display = 'none';
  document.getElementById('threads-list-view2').style.display = 'block';
  const topbar = document.querySelector('.topbar'); if(topbar) topbar.style.display='flex';
  loadThreadsInline(false);
  const isInline = document.getElementById('disc-inline-view')?.style.display !== 'none'; const discControls = document.getElementById('disc-controls-bar'); if(discControls) discControls.style.display=isInline?'none':'flex'; const discFilters = document.getElementById('disc-filters-bar'); if(discFilters) discFilters.style.display=isInline?'none':'flex';
}

async function deleteThreadInline(threadId) {
  if (!await customConfirm('Supprimer ce fil et toutes ses réponses ?')) return;
  try {
    await api('DELETE', '/threads/' + _discussionFileId + '/' + threadId);
    await loadThreadsInline(false);
  } catch(e) { toast(e.message, 'error'); }
}

function drawAllWaveformsInContainer(container) {
  container.querySelectorAll('canvas[data-mine]').forEach(function(canvas) {
    canvas.width = canvas.offsetWidth || 120;
    canvas.height = 28;
    redrawWaveformProgress(canvas, 0); // Draw at 0% progress (all unplayed)
  });
}

function toggleInlineAudio(audioId, btnId, barId, timeId, e) {
  if (e) { e.preventDefault(); e.stopPropagation(); }
  var audio = document.getElementById(audioId);
  var btn = document.getElementById(btnId);
  var canvas = document.getElementById(barId);
  if (!audio || !btn) return;
  if (audio.paused) {
    audio.play().catch(function(){});
    btn.textContent = '⏸';
    audio.ontimeupdate = function() {
      var pct = audio.duration ? (audio.currentTime / audio.duration) : 0;
      var time = document.getElementById(timeId);
      if (time) { var s = Math.floor(audio.currentTime); time.textContent = Math.floor(s/60) + ':' + (s%60<10?'0':'') + s%60; }
      if (canvas) redrawWaveformProgress(canvas, pct);
    };
    audio.onended = function() {
      btn.textContent = '▶';
      if (canvas) redrawWaveformProgress(canvas, 0);
    };
  } else {
    audio.pause();
    btn.textContent = '▶';
  }
}

function redrawWaveformProgress(canvas, pct) {
  var ctx2d = canvas.getContext('2d');
  if (!ctx2d) return;
  var W = canvas.width || canvas.offsetWidth || 120;
  var H = canvas.height || 28;
  canvas.width = W; canvas.height = H;
  var isMine = canvas.getAttribute('data-mine') === 'true';
  var playedColor = isMine ? 'rgba(255,255,255,1)' : 'var(--teal-dark)';
  var unplayedColor = isMine ? 'rgba(255,255,255,0.3)' : 'rgba(0,151,167,0.25)';
  // Utilise l'id pour générer une forme d'onde cohérente (même seed = même forme)
  var seed = 0;
  var idStr = canvas.id || '';
  for (var k = 0; k < idStr.length; k++) seed += idStr.charCodeAt(k) * (k + 1);
  var bars = Math.floor(W / 4);
  ctx2d.clearRect(0, 0, W, H);
  for (var i = 0; i < bars; i++) {
    var rnd = Math.abs(Math.sin((i + seed) * 2.3 + 1) * 0.5 + Math.sin((i * 0.7 + seed) * 1.3) * 0.3 + Math.sin((i * 0.3 + seed) * 3.1) * 0.2);
    var h = Math.max(3, Math.round(rnd * (H * 0.75) + H * 0.15));
    var y = (H - h) / 2;
    var played = (i / bars) < pct;
    ctx2d.fillStyle = played ? playedColor : unplayedColor;
    ctx2d.beginPath();
    ctx2d.roundRect ? ctx2d.roundRect(i * 4, y, 3, h, 1.5) : ctx2d.rect(i * 4, y, 3, h);
    ctx2d.fill();
  }
}

async function deleteReplyInline(replyId, skipConfirm) {
  if (!skipConfirm && !await customConfirm('Supprimer cette réponse ?')) return;
  try {
    await api('DELETE', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/replies/' + replyId);
    await loadThreadRepliesInline(true);
  } catch(e) { toast(e.message, 'error'); }
}

let _sendingReply2 = false;

function renderReplyHtml(r) {
  var isMine = currentUser != null && String(r.userId) === String(currentUser.id);
  var isAdmin = r.userRole === 'admin' || r.userRole === 'subadmin';
  var date = new Date(r.createdAt).toLocaleString('fr-FR', { day:'numeric', month:'short', hour:'2-digit', minute:'2-digit' });
  var initials = (r.userName||'?').split(' ').map(function(w){return w[0];}).join('').substring(0,2).toUpperCase();
  var avatarBg = isAdmin ? 'linear-gradient(135deg,#004D61,#003340)' : 'linear-gradient(135deg,var(--teal),var(--teal-dark))';
  var avatarHtml = r.userAvatar ? '<img src="' + r.userAvatar + '" style="width:100%;height:100%;object-fit:cover">' : initials;
  var bubbleBg = isMine ? 'linear-gradient(135deg,var(--teal),var(--teal-dark))' : 'rgba(255,255,255,0.15)';
  var bubbleColor = isMine ? 'white' : 'var(--text)';
  var bubbleBorder = isMine ? 'none' : '1px solid var(--border)';
  var msgHtml;
  if (r.audio) {
    var durSec = r.audioDuration || 0;
    var durStr = Math.floor(durSec/60) + ':' + (durSec%60<10?'0':'') + durSec%60;
    var aId = 'ia-' + r.id; var bId = 'ib-' + r.id; var barId = 'ic-' + r.id; var tId = 'it-' + r.id;
    msgHtml = '<audio id="' + aId + '" src="' + r.audio + '" style="display:none"></audio>' +
      '<div style="display:flex;align-items:center;gap:10px;padding:4px 0;min-width:160px">' +
      '<button id="' + bId + '" onclick="toggleInlineAudio(\'' + aId + '\',\'' + bId + '\',\'' + barId + '\',\'' + tId + '\',event)" style="width:32px;height:32px;border-radius:50%;background:' + (isMine?'rgba(255,255,255,0.25)':'var(--teal-dark)') + ';color:white;border:none;cursor:pointer;font-size:14px;flex-shrink:0">▶</button>' +
      '<canvas id="' + barId + '" data-mine="' + isMine + '" height="28" style="width:120px;height:28px;border-radius:3px;display:block"></canvas>' +
      '<div style="display:flex;justify-content:space-between;font-size:10px;color:' + (isMine?'rgba(255,255,255,0.7)':'var(--text3)') + '"><span id="' + tId + '">0:00</span><span>🎤 ' + durStr + '</span></div>' +
      '</div>';
  } else {
    msgHtml = (r.message||'').split('\n').join('<br>')
      .replace(/@\[([^\]]+)\]/g, function(m, name) { return renderMention(name, isMine); })
      .replace(/(?<!\])\B@([\w\-éèêëàâùûüôîïçÀ-ÿ][^\s@<]*(?:\s+[\w\-éèêëàâùûüôîïçÀ-ÿ][^\s@<]*)?)/g, function(m, name) { return renderMention(name, isMine); });
  }
  if (r.imageUrl) {
    msgHtml += '<div style="margin-top:6px"><img src="' + r.imageUrl + '" style="max-width:220px;max-height:200px;border-radius:10px;display:block;cursor:pointer" onclick="openImageLightbox(this.src)"></div>';
  }
  var row = '<div data-rid="' + r.id + '" style="width:100%;display:flex;flex-direction:column;margin-bottom:10px;align-items:' + (isMine?'flex-end':'flex-start') + '">';
  if (!isMine) row += '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;padding-left:42px"><span style="font-size:11px;font-weight:700;color:' + (isAdmin?'var(--teal-dark)':'var(--text2)') + '">' + (r.userName||'') + (isAdmin?' 👨‍🏫':'') + '</span><span style="font-size:10px;color:var(--text3)">' + date + '</span></div>';
  row += '<div style="display:flex;align-items:flex-end;gap:8px;max-width:78%;margin:' + (isMine?'0 8px 0 auto':'0 auto 0 8px') + '">';
  if (!isMine) row += '<div style="width:32px;height:32px;border-radius:50%;background:' + avatarBg + ';display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:white;flex-shrink:0;overflow:hidden;margin-bottom:2px">' + avatarHtml + '</div>';
  row += '<div>';
  row += '<div data-cid="' + r.id + '" class="msg-bubble" style="background:' + bubbleBg + ';color:' + bubbleColor + ';border:' + bubbleBorder + ';border-left:' + (isAdmin && !isMine ? '3px solid var(--teal)' : bubbleBorder) + ';border-radius:' + (isMine?'18px 18px 4px 18px':'18px 18px 18px 4px') + ';padding:10px 14px;font-size:14px;line-height:1.5;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)">';
  if (r.replyToName) row += '<div style="opacity:0.8;font-size:11px;border-left:2px solid rgba(255,255,255,0.5);padding:2px 6px;margin-bottom:4px">↩ ' + r.replyToName + ': ' + String(r.replyToPreview||'').substring(0,40) + '</div>';
  row += msgHtml + '</div></div></div>';
  if (isMine) row += '<div style="font-size:10px;color:var(--text3);margin-top:3px;text-align:right">' + date + '</div>';
  row += '</div>';
  return row;
}

async function postReply2() {
  if (_sendingReply2) return;
  _sendingReply2 = true;
  const input = document.getElementById('reply-input2');
  const message = input.value.trim();
  console.log('GUARD:', {message, _replyImageUrl2, _replyImageUploadPromise2, _voiceBlob: !!_voiceBlob, _discussionFileId});
  if ((!message && !_replyImageUrl2 && !_replyImageUploadPromise2 && !_voiceBlob) || !_discussionFileId) { _sendingReply2 = false; return; }
  const btn = document.querySelector('button[onclick="postReply2()"]');
  // Optimistic UI — immédiat
  const tempId = 'temp-' + Date.now();
  const container = document.getElementById('thread-replies2');
  const _tempImgHtml2 = _replyImageLocalUrl2 ? '<div style="margin-top:6px"><img src="' + _replyImageLocalUrl2 + '" style="max-width:200px;max-height:180px;border-radius:8px;display:block"></div>' : '';
  const tempHtml = '<div id="' + tempId + '" style="display:flex;justify-content:flex-end;margin:4px 0;padding:0 12px"><div style="max-width:75%;background:var(--teal-dark);color:white;border-radius:16px 16px 4px 16px;padding:10px 14px;opacity:0.6;font-size:14px">' + (message || (_voiceBlob ? '🎤 Vocal...' : '')) + _tempImgHtml2 + '</div></div>';
  if (container) { container.insertAdjacentHTML('beforeend', tempHtml); container.scrollTop = container.scrollHeight; }
  input.value = ''; input.style.height = 'auto';
  const _pendingVoiceBlob2 = _voiceBlob;
  const _voiceSecondsCopy2 = _voiceSeconds;
  if (_voiceBlob) cancelVoicePreview('side');
  cancelReply();
  if (btn) { btn.disabled = false; btn.textContent = 'Répondre'; }
  try {
    if (_replyImageUploadPromise2) { await _replyImageUploadPromise2; _replyImageUploadPromise2 = null; }
    const _pendingImageUrl2 = _replyImageUrl2; const _pendingR2Key2 = _replyR2Key2;
    cancelReplyImage('2');
    if (!message && !_pendingImageUrl2 && !_pendingVoiceBlob2) { const t = document.getElementById(tempId); if (t) t.remove(); _sendingReply2 = false; return; }
    const body = { message };
    if (_pendingVoiceBlob2) { await new Promise(resolve => { const r = new FileReader(); r.onload = async () => { body.audio = r.result; body.audioDuration = _voiceSecondsCopy2; resolve(); }; r.readAsDataURL(_pendingVoiceBlob2); }); }
    if (_pendingImageUrl2) { body.imageUrl = _pendingImageUrl2; body.r2Key = _pendingR2Key2 || null; }
    if (_replyTo) { body.replyToId = _replyTo.id; body.replyToName = _replyTo.userName; body.replyToPreview = _replyTo.msgPreview; }
    await api('POST', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/replies', body);
    await loadThreadRepliesInline(true);
    const tempEl = document.getElementById(tempId);
    if (tempEl) tempEl.remove();
    if (container) container.scrollTop = container.scrollHeight;
  } catch(e) {
    const tempEl = document.getElementById(tempId);
    if (tempEl) tempEl.innerHTML = '<div style="max-width:75%;background:#b71c1c;color:white;border-radius:16px 16px 4px 16px;padding:10px 14px;font-size:14px">' + (message || '🖼️') + '<div style="font-size:11px;margin-top:4px;opacity:0.85">⚠️ Non envoyé · <span style="text-decoration:underline;cursor:pointer" onclick="this.closest(\'[id^=temp-]\').remove();postReply2()">Réessayer</span></div></div>';
  }
  finally { _sendingReply2 = false; }
}
async function toggleResolve2() {
  try {
    await api('PATCH', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/resolve');
    await loadThreadRepliesInline(true);
  } catch(e) { toast(e.message, 'error'); }
}


function updateDiscCenterBadge() {
  const _lastSeen = loadLastSeen();
  const newCount = _allThreads.filter(function(t) {
    var ls = _lastSeen['thread_' + t.threadId] ? new Date(_lastSeen['thread_' + t.threadId]) : null;
    return ls ? new Date(t.lastActivity) > ls : true;
  }).length;
  const badge = document.getElementById('disc-center-badge');
  if (badge) {
    badge.textContent = newCount > 9 ? '9+' : newCount;
    badge.style.display = newCount > 0 ? 'inline-block' : 'none';
  }
}

// ── MENU ACTIONS FICHIER ──────────────────────────────────────────────────────
function toggleFileMenu(e, btn) {
  e.stopPropagation();
  closeAllFileMenus();
  const menuId = btn.getAttribute('data-menu');
  const menu = document.getElementById(menuId);
  if (!menu) return;

  if (menu.parentElement !== document.body) document.body.appendChild(menu);

  const rect = btn.getBoundingClientRect();
  // Sur mobile, visualViewport donne les vraies dimensions visibles
  const vw = window.visualViewport ? window.visualViewport.width : window.innerWidth;
  const vh = window.visualViewport ? window.visualViewport.height : window.innerHeight;
  // Offset si la page est zoomée/scrollée
  const offsetY = window.visualViewport ? window.visualViewport.offsetTop : 0;
  const menuWidth = 200;

  let left = rect.right - menuWidth;
  if (left < 8) left = 8;
  if (left + menuWidth > vw - 8) left = vw - menuWidth - 8;
  let top = rect.bottom + offsetY + 4;
  if (top + 200 > vh + offsetY) top = rect.top + offsetY - 204;

  menu.style.left = Math.round(left) + 'px';
  menu.style.top = Math.round(top) + 'px';
  menu.style.zIndex = '99999';
  menu.classList.add('open');
  setTimeout(() => document.addEventListener('click', closeAllFileMenus, { once: true }), 10);
}
function closeAllFileMenus() {
  document.querySelectorAll('.file-action-menu.open').forEach(m => m.classList.remove('open'));
}

function renameFile(e, fileId, currentName, folderId, subId) {
  openFileModal(e, fileId, currentName, folderId, subId);
}

// ── EXTRAIRE UN SOUS-DOSSIER VERS LA RACINE ──────────────────────────────────
async function extractSubfolder(parentId, subId) {
  if (!await customConfirm('Extraire ce dossier vers la racine ?')) return;
  try {
    await api('POST', '/folders/' + parentId + '/subfolders/' + subId + '/extract');
    toast('Dossier extrait vers la racine ✅');
    await loadFolders();
  } catch(e) { toast(e.message, 'error'); }
}

// ── DÉPLACER UN DOSSIER ──────────────────────────────────────────────────────
let _moveFolderId = null;

async function openMoveFolderModal(folderId, folderName) {
  _moveFolderId = folderId;
  document.getElementById('move-folder-title').textContent = '📁 Déplacer "' + folderName + '"';
  const modal = document.getElementById('move-folder-modal');
  modal.style.display = 'flex';
  // Load destinations
  const container = document.getElementById('move-folder-destinations');
  container.innerHTML = '<div style="color:var(--text3);font-size:13px">Chargement...</div>';
  try {
    const folders = await api('GET', '/folders');
    container.innerHTML = '';
    folders.filter(f => f.id !== folderId).forEach(function(f) {
      const btn = document.createElement('button');
      btn.style.cssText = 'display:flex;align-items:center;gap:10px;width:100%;padding:12px 16px;border-radius:10px;border:1.5px solid var(--border);background:var(--bg);cursor:pointer;font-size:14px;font-family:Inter,sans-serif;color:var(--text);margin-bottom:6px';
      btn.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" style="width:18px;height:18px;color:var(--teal-dark);flex-shrink:0"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>' + f.name;
      var fId = f.id;
      btn.onmouseover = function() { this.style.background = 'rgba(0,151,167,0.06)'; this.style.borderColor = 'var(--teal)'; };
      btn.onmouseout = function() { this.style.background = 'var(--bg)'; this.style.borderColor = 'var(--border)'; };
      btn.onclick = function() { doMoveFolder(fId); };
      container.appendChild(btn);
    });
    if (!container.children.length) {
      container.innerHTML = '<div style="color:var(--text3);font-size:13px;padding:12px 0">Aucun autre dossier disponible.</div>';
    }
  } catch(e) { container.innerHTML = '<div style="color:var(--danger)">Erreur: ' + e.message + '</div>'; }
}

function closeMoveFolder() {
  document.getElementById('move-folder-modal').style.display = 'none';
  _moveFolderId = null;
}

async function doMoveFolder(targetFolderId) {
  if (!_moveFolderId) return;
  try {
    await api('POST', '/folders/' + _moveFolderId + '/move', { toFolderId: targetFolderId });
    closeMoveFolder();
    toast('Dossier déplacé ✅');
    await loadFolders();
  } catch(e) { toast(e.message, 'error'); }
}

// ── DRAG & DROP DOSSIERS ──────────────────────────────────────────────────────
let _dragFolderId = null;

function dragFolderStart(e, folderId) {
  _dragFolderId = folderId;
  e.dataTransfer.effectAllowed = 'move';
  e.currentTarget.style.opacity = '0.5';
}

function dragFolderOver(e) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  e.currentTarget.style.outline = '2px dashed var(--teal)';
  e.currentTarget.style.outlineOffset = '2px';
}

function dragFolderDrop(e, targetFolderId) {
  e.preventDefault();
  e.currentTarget.style.outline = '';
  if (!_dragFolderId || _dragFolderId === targetFolderId) return;

  // Get current order from DOM
  const cards = document.querySelectorAll('.folder-card[data-folder-id]');
  const order = [...cards].map(c => c.getAttribute('data-folder-id'));

  // Swap positions
  const fromIdx = order.indexOf(String(_dragFolderId));
  const toIdx = order.indexOf(String(targetFolderId));
  if (fromIdx === -1 || toIdx === -1) return;
  order.splice(fromIdx, 1);
  order.splice(toIdx, 0, String(_dragFolderId));

  api('PATCH', '/folders/reorder', { order })
    .then(() => loadFolders())
    .catch(e => toast(e.message, 'error'));
}

function dragFolderEnd(e) {
  e.currentTarget.style.opacity = '';
  e.currentTarget.style.outline = '';
  _dragFolderId = null;
  // Remove all outlines
  document.querySelectorAll('.folder-card').forEach(c => { c.style.outline = ''; });
}

// ── DISCUSSION ───────────────────────────────────────────────────────────────
let _discussionFileId = null;
let _replyTo = null;

function setReply(commentId, userName, msgPreview) {
  try { userName = decodeURIComponent(userName); } catch(e) {}
  try { msgPreview = decodeURIComponent(msgPreview); } catch(e) {}
  _replyTo = { id: commentId, userName: userName, msgPreview: msgPreview };
  // Support both main discussion and sidebar discussion
  var replyBar = document.getElementById('reply-bar') || document.getElementById('reply-bar2');
  var replyName = document.getElementById('reply-name') || document.getElementById('reply-name2');
  var replyPreview = document.getElementById('reply-preview') || document.getElementById('reply-preview2');
  var isInline = document.getElementById('disc-inline-view')?.style.display !== 'none' && (document.getElementById('disc-inline-view')?.offsetWidth || 0) > 0;
  var replyBar = isInline ? document.getElementById('reply-bar2') : document.getElementById('reply-bar');
  var replyName = isInline ? document.getElementById('reply-name2') : document.getElementById('reply-name');
  var replyPreview = isInline ? document.getElementById('reply-preview2') : document.getElementById('reply-preview');
  var input = isInline ? document.getElementById('reply-input2') : document.getElementById('reply-input');
  if (replyBar) {
    replyBar.style.display = 'flex';
    if (replyName) replyName.textContent = userName;
    if (replyPreview) replyPreview.textContent = msgPreview.substring(0, 60);
    if (input) input.focus();
  }
}

function cancelReply() {
  _replyTo = null;
  var replyBar = document.getElementById('reply-bar');
  if (replyBar) replyBar.style.display = 'none';
  var replyBar2 = document.getElementById('reply-bar2');
  if (replyBar2) replyBar2.style.display = 'none';
}

function handleReply(btn) {
  var id = parseInt(btn.getAttribute('data-reply-id'));
  var user = btn.getAttribute('data-reply-user');
  var msg = btn.getAttribute('data-reply-msg');
  setReply(id, user, msg);
}

let _lastSeenComments = {}; // fileId -> ISO timestamp

function getLastSeenKey() {
  return currentUser ? 'mp_disc_seen_' + currentUser.id : null;
}
function loadLastSeen() {
  const key = getLastSeenKey();
  if (!key) return {};
  try { return JSON.parse(localStorage.getItem(key) || '{}'); }
  catch { return {}; }
}
function saveLastSeen(fileId) {
  const key = getLastSeenKey();
  if (!key) return;
  _lastSeenComments[fileId] = new Date().toISOString();
  localStorage.setItem(key, JSON.stringify(_lastSeenComments));
}

async function updateDiscussionBadges(fileIds) {
  if (!fileIds || !fileIds.length) return;
  _lastSeenComments = loadLastSeen();
  try {
    const validIds = Array.from(fileIds).filter(id => id && id !== 'undefined' && id !== 'null' && !isNaN(parseInt(id)));
    if (!validIds.length) return;
    const fileLevelSeen = {};
    Object.entries(_lastSeenComments || {}).forEach(([k,v]) => { if (!k.startsWith('thread_')) fileLevelSeen[k] = v; });
    const unread = await api('POST', '/threads/unread', { fileIds: validIds, lastSeen: fileLevelSeen });
    fileIds.forEach(id => {
      const badge = document.getElementById('disc-badge-' + id);
      if (!badge) return;
      const count = unread[id] || 0;
      if (count > 0) {
        badge.textContent = count > 9 ? '9+' : count;
        badge.style.display = 'inline-block';
      } else {
        badge.style.display = 'none';
      }
    });
  } catch(e) {}
}
let _discussionFileName = null;

let _discussionRefreshTimer = null;

// ── SYSTÈME DE FILS DE DISCUSSION ───────────────────────────────────────────
function startDiscussionRefresh() {
  stopDiscussionRefresh();
  _discussionRefreshTimer = setInterval(async function() {
    var isInline = document.getElementById('disc-inline-view')?.style.display !== 'none' && (document.getElementById('disc-inline-view')?.offsetWidth || 0) > 0;
    if (_currentThreadId) {
      if (isInline) await loadThreadRepliesInline(true);
      else await loadThreadReplies(true);
    } else if (_discussionFileId) {
      if (isInline) await loadThreadsInline(true);
      else await loadThreads(true);
    }
  }, 8000);
}

function stopDiscussionRefresh() {
  if (_discussionRefreshTimer) { clearInterval(_discussionRefreshTimer); _discussionRefreshTimer = null; }
}

async function openDiscussion(fileId, fileName) {
  const filesList = document.getElementById('files-list-body');
  if (filesList) saveNavState('lastFileScroll', { folderId: currentFolder?.id, top: filesList.scrollTop });
  saveNavState('lastDiscussion', { fileId, fileName });
  _discussionFileId = fileId;
  _discussionFileName = fileName;
  _currentThreadId = null;
  const viewFiles = document.getElementById('view-files');
  const panel = document.getElementById('discussion-panel');
  if (viewFiles) viewFiles.style.display = 'none';
  panel.setAttribute('style', 'display:block');
  const bc = document.getElementById('breadcrumb'); if(bc) bc.innerHTML = `<span style="font-size:13px;color:var(--teal);font-weight:600">💬 ${fileName}</span>`;
  const topbar = document.querySelector('.topbar'); if(topbar) topbar.style.display='none';
  const sb = document.getElementById('topbar-search'); if(sb) sb.style.display='none';
  const hdr = document.getElementById('threads-list-header'); if(hdr) hdr.style.top='0'; const hdr2 = document.getElementById('thread-detail-header'); if(hdr2) hdr2.style.top='0';
  document.getElementById('discussion-filename').textContent = '💬 ' + fileName;
  // Mark as seen
  saveLastSeen(fileId);
  const badge = document.getElementById('disc-badge-' + fileId);
  if (badge) badge.style.display = 'none';
  showView('threads-list-view');
  await loadThreads(false);
  startDiscussionRefresh();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function closeDiscussion() {
  stopDiscussionRefresh();
  const panel = document.getElementById('discussion-panel');
  panel.setAttribute('style', 'display:none');
  const bc = document.getElementById('breadcrumb'); if(bc) { updateBreadcrumb && updateBreadcrumb(); }
  const topbar = document.querySelector('.topbar'); if(topbar) topbar.style.display='flex';
  const sb = document.getElementById('topbar-search'); if(sb) sb.style.display='block';
  const hdr = document.getElementById('threads-list-header'); if(hdr) hdr.style.top='88px'; const hdr2 = document.getElementById('thread-detail-header'); if(hdr2) hdr2.style.top='88px';
  const viewFiles = document.getElementById('view-files');
  if (viewFiles) viewFiles.style.display = 'block';
  _discussionFileId = null;
  _currentThreadId = null;
  const savedScroll = loadNavState('lastFileScroll');
  if (savedScroll) {
    setTimeout(() => { const el = document.getElementById('files-list-body'); if (el) el.scrollTop = savedScroll.top; }, 50);
  }
}

function showView(viewId) {
  document.getElementById('threads-list-view').style.display = viewId === 'threads-list-view' ? 'block' : 'none';
  document.getElementById('thread-detail-view').style.display = viewId === 'thread-detail-view' ? 'block' : 'none';
}

function showNewThreadForm() {
  document.getElementById('new-thread-form').style.display = 'block';
  document.getElementById('new-thread-title').focus();
}

function hideNewThreadForm() {
  document.getElementById('new-thread-form').style.display = 'none';
  document.getElementById('new-thread-title').value = '';
}

async function createThread() {
  // Use correct input based on context
  const inputEl = document.getElementById('new-thread-title2') && document.getElementById('new-thread-form2').style.display !== 'none'
    ? document.getElementById('new-thread-title2')
    : document.getElementById('new-thread-title');
  const title = inputEl ? inputEl.value.trim() : '';
  if (!title) { toast('Formule ta question d&#39;abord', 'error'); return; }
  try {
    await api('POST', '/threads/' + _discussionFileId, { title });
    if (inputEl.id === 'new-thread-title2') { hideNewThreadForm2(); await loadThreadsInline(false); }
    else { hideNewThreadForm(); await loadThreads(); }
  } catch(e) { toast(e.message, 'error'); }
}

async function loadThreads(silent) {
  const list = document.getElementById('threads-list');
  const countEl = document.getElementById('threads-count');
  if (!silent) list.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3)">Chargement...</div>';
  try {
    const threads = await api('GET', '/threads/' + _discussionFileId);
    countEl.textContent = threads.length + ' fil' + (threads.length > 1 ? 's' : '');
    if (!threads.length) {
      list.innerHTML = '<div style="text-align:center;padding:48px;color:var(--text3)"><div style="font-size:40px;margin-bottom:12px">💬</div><div style="font-size:15px;font-weight:600;margin-bottom:6px">Aucune question pour l&#39;instant</div><div style="font-size:13px">Clique sur "Poser une question" pour démarrer un fil.</div></div>';
      return;
    }
    // Sort: unresolved first, then by lastReplyAt desc
    threads.sort(function(a,b) {
      if (a.resolved !== b.resolved) return a.resolved ? 1 : -1;
      return new Date(b.lastReplyAt) - new Date(a.lastReplyAt);
    });
    list.innerHTML = threads.map(function(t) {
      var date = new Date(t.lastReplyAt).toLocaleString('fr-FR', { day:'numeric', month:'short', hour:'2-digit', minute:'2-digit' });
      var isAdmin = currentUser?.role === 'admin';
      var canDelete = t.createdBy === currentUser?.id || isAdmin;
      return '<div data-thread-id="' + t.id + '" style="display:flex;align-items:center;gap:10px;padding:16px 20px;background:var(--surface,white);border-radius:14px;border:1.5px solid ' + (t.resolved ? 'rgba(46,125,50,0.3)' : 'var(--border)') + ';margin-bottom:10px;cursor:pointer;transition:box-shadow 0.15s" class="thread-card-sb">' +
        '<input type="checkbox" class="thread-select-cb-sb" data-tid="' + t.id + '" onclick="event.stopPropagation()" onchange="onThreadCheckboxChangeSb()" style="display:none;width:18px;height:18px;cursor:pointer;accent-color:var(--teal);flex-shrink:0">' +
        '<div style="display:flex;align-items:flex-start;gap:14px;flex:1;min-width:0">' +
        '<div style="width:40px;height:40px;border-radius:50%;background:linear-gradient(135deg,var(--teal),var(--teal-dark));display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:white;flex-shrink:0;overflow:hidden">' +
          (t.creatorAvatar ? '<img src="' + t.creatorAvatar + '" style="width:100%;height:100%;object-fit:cover">' : (t.creatorName||'?')[0].toUpperCase()) +
        '</div>' +
        '<div style="flex:1;min-width:0">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px">' +
            (t.resolved ? '<span style="background:#2E7D32;color:white;border-radius:8px;padding:4px 10px;font-size:11px;font-weight:700;display:inline-flex;align-items:center;gap:4px">✓ Résolu</span>' : '<span style="background:rgba(0,151,167,0.1);color:var(--teal-dark);border-radius:8px;padding:4px 10px;font-size:11px;font-weight:700">💬 Ouvert</span>') +
            '<span style="font-weight:700;font-size:15px;font-weight:700;color:var(--text)">' + t.title + '</span>' +
          '</div>' +
          '<div style="font-size:12px;color:var(--text3)">' +
            '<span style="color:' + (t.creatorRole==='admin'?'var(--teal-dark)':'var(--text2)') + ';font-weight:600">' + (t.creatorName||'') + '</span>' +
            ' · ' + date + ' · ' + t.replyCount + ' réponse' + (t.replyCount > 1 ? 's' : '') +
          '</div>' +
        '</div>' +
        '<div style="display:flex;align-items:center;gap:8px;flex-shrink:0">' +
          '<svg viewBox="0 0 24 24" fill="currentColor" style="width:16px;height:16px;color:var(--text3)"><path d="M8.59 16.59L13.17 12 8.59 7.41 10 6l6 6-6 6z"/></svg>' +
          (canDelete ? '<button onclick="event.stopPropagation();deleteThread(' + t.id + ')" style="width:28px;height:28px;border-radius:8px;border:none;background:rgba(229,115,115,0.1);color:var(--danger);cursor:pointer;display:flex;align-items:center;justify-content:center"><svg viewBox="0 0 24 24" fill="currentColor" style="width:13px;height:13px"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg></button>' : '') +
        '</div>' +
        '</div>' +
      '</div>';
    }).join('');
    document.querySelectorAll('#threads-list .thread-card-sb').forEach(function(card) {
      var tid = parseInt(card.getAttribute('data-thread-id'));
      var timer = null; var startX = 0; var startY = 0; var longPressed = false;
      card.addEventListener('touchstart', function(e) {
        startX = e.touches[0].clientX; startY = e.touches[0].clientY; longPressed = false;
        timer = setTimeout(function() { longPressed = true; if (navigator.vibrate) navigator.vibrate(50); enterThreadSelectionModeSb(tid); }, 500);
      }, { passive: true });
      card.addEventListener('touchmove', function(e) {
        if (Math.abs(e.touches[0].clientX-startX) > 10 || Math.abs(e.touches[0].clientY-startY) > 10) clearTimeout(timer);
      }, { passive: true });
      card.addEventListener('touchend', function(e) { clearTimeout(timer); if (longPressed) { longPressed = false; e.preventDefault(); e.stopPropagation(); return; } if (!_threadSelectionModeSb) openThread(tid); else { var cb = card.querySelector('.thread-select-cb-sb'); if (cb) { cb.checked = !cb.checked; onThreadCheckboxChangeSb(); } } });
      card.addEventListener('mousedown', function() { longPressed = false; timer = setTimeout(function() { longPressed = true; enterThreadSelectionModeSb(tid); }, 600); });
      card.addEventListener('mouseup', function() { clearTimeout(timer); });
      card.addEventListener('mouseleave', function() { clearTimeout(timer); });
      card.addEventListener('click', function(e) { if (longPressed) { e.stopPropagation(); return; } if (!_threadSelectionModeSb) openThread(tid); else { var cb = card.querySelector('.thread-select-cb-sb'); if (cb) { cb.checked = !cb.checked; onThreadCheckboxChangeSb(); } } });
    });
  } catch(e) {
    list.innerHTML = '<div style="color:var(--danger);padding:20px">Erreur: ' + e.message + '</div>';
  }
}

async function openThread(threadId) {
  const threadsList = document.getElementById('threads-list');
  if (threadsList) saveNavState('lastThreadScroll', { fileId: _discussionFileId, top: threadsList.scrollTop });
  saveNavState('lastThread', { threadId, fileId: _discussionFileId });
  _currentThreadId = threadId;
  showView('thread-detail-view');
  await loadThreadReplies(false);
  const _cm = document.getElementById('thread-replies');
  if (_cm) {
    _cm.scrollTop = _cm.scrollHeight;
    setTimeout(() => { _cm.scrollTop = _cm.scrollHeight; }, 200);
    setTimeout(() => { _cm.scrollTop = _cm.scrollHeight; }, 600);
  }
  const resolveBtn = document.getElementById('resolve-btn');
  if (resolveBtn) resolveBtn.style.display = currentUser?.role === 'admin' ? 'inline-block' : 'none';
  updateMuteBtn();
}
function updateMuteBtn() {
  const btn = document.getElementById('mute-btn');
  if (!btn) return;
  const muted = (currentUser?.mutedThreads || []).includes(_currentThreadId);
  btn.textContent = muted ? '🔕 En sourdine' : '🔔 Notifier';
  btn.style.color = muted ? 'var(--danger)' : 'var(--text2)';
  btn.style.borderColor = muted ? 'var(--danger)' : 'var(--border)';
}
async function toggleMuteThread() {
  try {
    const res = await api('POST', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/mute');
    if (!currentUser.mutedThreads) currentUser.mutedThreads = [];
    const idx = currentUser.mutedThreads.indexOf(_currentThreadId);
    if (res.muted && idx === -1) currentUser.mutedThreads.push(_currentThreadId);
    else if (!res.muted && idx !== -1) currentUser.mutedThreads.splice(idx, 1);
    updateMuteBtn();
    toast(res.muted ? 'Discussion mise en sourdine' : 'Notifications réactivées', 'success');
  } catch(e) {
    toast('Erreur', 'error');
  }
}

function backToThreads() {
  _currentThreadId = null;
  showView('threads-list-view');
  loadThreads(true).then(() => {
    const savedScroll = loadNavState('lastThreadScroll');
    if (savedScroll) {
      setTimeout(() => { const el = document.getElementById('threads-list'); if (el) el.scrollTop = savedScroll.top; }, 100);
    }
    clearNavState('lastThreadScroll');
  });
}

let _currentThreadResolved = false;
async function loadThreadReplies(silent) {
  if (!currentUser) {
    try { currentUser = await api('GET', '/me'); } catch(e) {}
  }
  if (!currentUser) {
    try { currentUser = await api('GET', '/me'); } catch(e) {}
  }
  const container = document.getElementById('thread-replies');
  if (!silent) container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3)">Chargement...</div>';
  try {
    const data = await api('GET', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/replies');
    _currentThreadResolved = data.thread.resolved;
    _mentionables = (data.mentionables || []).filter(u => u.id !== currentUser?.id);
    document.getElementById('thread-title-display').textContent = data.thread.title;
    const resolveBtn = document.getElementById('resolve-btn');
    if (resolveBtn) {
      resolveBtn.textContent = data.thread.resolved ? '✓ Résolu' : '○ Marquer résolu';
      resolveBtn.style.color = data.thread.resolved ? '#2E7D32' : 'var(--text2)';
      resolveBtn.style.borderColor = data.thread.resolved ? 'rgba(46,125,50,0.4)' : 'var(--border)';
    }
    if (!data.replies.length) {
      container.innerHTML = '<div style="padding:32px;text-align:center;color:var(--text3)">Aucune réponse — sois le premier à répondre !</div>';
      return;
    }
    var wasAtBottom = container.scrollHeight - container.clientHeight - container.scrollTop < 80;
    // Ne pas reconstruire le HTML si un audio est en cours de lecture
    var audioPlaying = Array.from(container.querySelectorAll('audio')).some(function(a) { return !a.paused; });
    if (audioPlaying) return;
    _repliesCache = data.replies;
    container.innerHTML = data.replies.map(function(r) {
      var isAdmin = r.userRole === 'admin';
      var isOwn = currentUser != null && String(r.userId) === String(currentUser.id);
      var isMine = isOwn;
      var date = new Date(r.createdAt).toLocaleString('fr-FR', { day:'numeric', month:'short', hour:'2-digit', minute:'2-digit' });
      var initials = r.userName.split(' ').map(function(w){return w[0];}).join('').substring(0,2).toUpperCase();
      var avatarHtml = r.userAvatar ? '<img src="' + r.userAvatar + '" style="width:100%;height:100%;object-fit:cover">' : initials;
      var bubbleBg = isMine ? 'linear-gradient(135deg,var(--teal),var(--teal-dark))' : 'var(--bg)';
      var bubbleColor = isMine ? 'white' : 'var(--text)';
      var bubbleBorder = isMine ? 'none' : '1px solid var(--border)';
      var avatarBg = isAdmin ? 'linear-gradient(135deg,#004D61,#003340)' : 'linear-gradient(135deg,var(--teal),var(--teal-dark))';
      // Audio
      var msgHtml = r.audio
        ? (function(){
            var aId='audio-'+r.id, bId='abtn-'+r.id, barId='abar-'+r.id, tId='atime-'+r.id;
            var dur=r.audioDuration||0;
            var durStr=Math.floor(dur/60)+':'+(dur%60<10?'0':'')+dur%60;
            return '<audio id="'+aId+'" src="'+r.audio+'" style="display:none"></audio>'+
              '<div style="display:flex;align-items:center;gap:10px;padding:4px 0;min-width:160px">'+
                '<button id="'+bId+'" onclick="toggleInlineAudio(\''+aId+'\',\''+bId+'\',\''+barId+'\',\''+tId+'\',event)" style="width:32px;height:32px;border-radius:50%;background:'+(isMine?'rgba(255,255,255,0.25)':'var(--teal-dark)')+';color:white;border:none;cursor:pointer;font-size:14px;flex-shrink:0">▶</button>'+
                '<canvas id="'+barId+'" data-mine="'+isMine+'" height="28" style="width:120px;height:28px;border-radius:3px;display:block"></canvas>'+
                '<div style="display:flex;justify-content:space-between;font-size:10px;color:'+(isMine?'rgba(255,255,255,0.7)':'var(--text3)')+'"><span id="'+tId+'">0:00</span><span>🎤 '+durStr+'</span></div>'+
              '</div>';
          })()
        : r.message.split('\n').join('<br>')
            .replace(/@\[([^\]]+)\]/g, function(m, name) { return renderMention(name, isMine); })
            .replace(/(?<!\])\B@([\w\-éèêëàâùûüôîïçÀ-ÿ][^\s@<]*(?:\s+[\w\-éèêëàâùûüôîïçÀ-ÿ][^\s@<]*)?)/g, function(m, name) { return renderMention(name, isMine); });
      var canDelete = currentUser?.role === 'admin' || isOwn;
      var reactHtml = '';
      if (r.reactions && Object.keys(r.reactions).length) {
        reactHtml += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:4px">';
        Object.entries(r.reactions).forEach(function(e) {
          var em=e[0], users=e[1];
          if (!users.length) return;
          var iReacted = users.indexOf(currentUser?currentUser.id:-1) !== -1;
          reactHtml += '<button onclick="reactMsg('+JSON.stringify(em)+','+r.id+')" style="display:flex;align-items:center;gap:3px;padding:2px 8px;border-radius:20px;border:1.5px solid '+(iReacted?'var(--teal)':'var(--border)')+';background:'+(iReacted?'rgba(0,151,167,0.1)':'var(--surface,white)')+';cursor:pointer;font-size:12px">'+em+' '+users.length+'</button>';
        });
        reactHtml += '</div>';
      }
      var row = '<div style="width:100%;display:flex;flex-direction:column;align-items:'+(isMine?'flex-end':'flex-start')+';margin-bottom:10px">';
      if (!isMine) {
        row += '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;padding-left:40px">' +
          '<span style="font-size:11px;font-weight:700;color:'+(isAdmin?'var(--teal-dark)':'var(--text2)')+'">'+r.userName+(isAdmin?' 👨‍🏫':'')+'</span>' +
          '<span style="font-size:10px;color:var(--text3)">'+date+'</span>' +
        '</div>';
      }
      row += '<div style="display:flex;align-items:flex-end;gap:8px;max-width:78%;margin:' + (isMine?'0 8px 0 auto':'0 auto 0 8px') + '">';
      if (!isMine) row += '<div style="width:32px;height:32px;border-radius:50%;background:'+avatarBg+';display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:white;flex-shrink:0;overflow:hidden;margin-bottom:2px">'+avatarHtml+'</div>';
      row += '<div>';
      row += '<div data-cid="'+r.id+'" class="msg-bubble" style="background:'+bubbleBg+';color:'+bubbleColor+';border-radius:'+(isMine?'18px 18px 4px 18px':'18px 18px 18px 4px')+';padding:10px 14px;font-size:14px;line-height:1.5;border:'+bubbleBorder+';border-left:'+(isAdmin&&!isMine?'3px solid var(--teal)':bubbleBorder)+'">';
      if (r.imageUrl) {
        msgHtml += '<div style="margin-top:6px"><img src="' + r.imageUrl + '" style="max-width:220px;max-height:200px;border-radius:10px;display:block;cursor:pointer" onclick=\"openImageLightbox(this.src)\"></div>';
      }
      row += msgHtml + '</div></div></div>';
      if (isMine) row += '<div style="font-size:10px;color:var(--text3);margin-top:3px;text-align:right">'+date+'</div>';
      row += reactHtml;
      row += '</div>';
      return row;
    }).join('');
    // Init audio — géré par toggleInlineAudio via onclick dans le HTML
    if (!silent || wasAtBottom) { container.scrollTop = container.scrollHeight; if (!silent) window.scrollTo({top: document.body.scrollHeight, behavior: 'smooth'}); }
    setTimeout(function() {
      container.querySelectorAll('canvas[data-mine]').forEach(function(canvas) {
        canvas.width = canvas.offsetWidth || 120;
        canvas.height = 28;
        redrawWaveformProgress(canvas, 0);
      });
    }, 300);
    // Init long press context menu for replies
    // Update comment map (keep inline entries)
    data.replies.forEach(function(r) {
      _commentDataMap[r.id] = {
        id: r.id, userId: r.userId, userName: r.userName,
        message: r.message || '', isOwn: String(r.userId) === String(currentUser?.id),
canDelete: (currentUser?.role === 'admin') || String(r.userId) === String(currentUser?.id)
      };
    });
    initBubbleEvents();
  } catch(e) {
    container.innerHTML = '<div style="color:var(--danger);padding:20px">Erreur: ' + e.message + '</div>';
  }
}

// ===== SYSTÈME @MENTION =====
function renderMention(name, isMine) {
  var isMe = currentUser && name.trim().toLowerCase() === currentUser.name.toLowerCase();
  if (isMine) {
    return '<span style="background:rgba(255,255,255,0.25);color:white;font-weight:700;border-radius:4px;padding:0 4px">@' + name + '</span>';
  }
  if (isMe) {
    return '<span style="background:rgba(0,196,212,0.2);color:var(--teal);font-weight:700;border-radius:4px;padding:0 4px">@' + name + '</span>';
  }
  return '<span style="color:var(--text3);font-weight:600">@' + name + '</span>';
}
let _mentionables = [];
let _mentionOpen = false;
let _mentionIdx = 0;
let _mentionMenu = null;

function handleMentionInput(textarea) {
  const val = textarea.value;
  const pos = textarea.selectionStart;
  const before = val.substring(0, pos);
  const match = before.match(/@(\[?[\w\s\-éèêëàâùûüôîïç]*)$/);
  if (!match) { closeMentionMenu(); return; }
  const query = match[1].toLowerCase();
  const filtered = query
    ? _mentionables.filter(u => u.name.toLowerCase().startsWith(query))
    : _mentionables;
  if (!filtered.length) { closeMentionMenu(); return; }
  showMentionMenu(textarea, filtered);
}

function showMentionMenu(textarea, users) {
  closeMentionMenu();
  _mentionOpen = true;
  _mentionIdx = 0;
  _mentionMenu = document.createElement('div');
  _mentionMenu.className = 'mention-menu';
  _mentionMenu.id = 'mention-menu';
  users.forEach(function(u, i) {
    var item = document.createElement('div');
    item.className = 'mention-item' + (i === 0 ? ' active' : '');
    item.innerHTML = '<span>' + u.name + '</span>' + ((u.role === 'admin' || u.role === 'subadmin') ? '<span class="mention-role">👨‍🏫</span>' : '');
    item.dataset.name = u.name;
    item.addEventListener('mousedown', function(e) { e.preventDefault(); insertMention(textarea, u.name); });
    _mentionMenu.appendChild(item);
  });
  var rect = textarea.getBoundingClientRect();
  var menuH = Math.min(users.length * 38, 180);
  var top = rect.top + window.scrollY - menuH - 6;
  var left = rect.left + window.scrollX;
  _mentionMenu.style.position = 'absolute';
  _mentionMenu.style.left = left + 'px';
  _mentionMenu.style.top = top + 'px';
  _mentionMenu.style.width = '220px';
  document.body.appendChild(_mentionMenu);
}

function closeMentionMenu() {
  _mentionOpen = false;
  var m = document.getElementById('mention-menu');
  if (m) m.remove();
  _mentionMenu = null;
}

function handleMentionKeydown(e, textarea) {
  if (!_mentionOpen || !_mentionMenu) return;
  var items = _mentionMenu.querySelectorAll('.mention-item');
  if (e.key === 'ArrowDown') { e.preventDefault(); _mentionIdx = Math.min(_mentionIdx+1, items.length-1); items.forEach(function(el,i){el.classList.toggle('active',i===_mentionIdx);}); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); _mentionIdx = Math.max(_mentionIdx-1, 0); items.forEach(function(el,i){el.classList.toggle('active',i===_mentionIdx);}); }
  else if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); var active = items[_mentionIdx]; if (active) insertMention(textarea, active.dataset.name); }
  else if (e.key === 'Escape') { closeMentionMenu(); }
}

function insertMention(textarea, name) {
  var val = textarea.value;
  var pos = textarea.selectionStart;
  var before = val.substring(0, pos);
  var newBefore = before.replace(/@[\w\s\-éèêëàâùûüôîïç]*$/, '@[' + name + '] ');
  textarea.value = newBefore + val.substring(pos);
  textarea.selectionStart = textarea.selectionEnd = newBefore.length;
  textarea.focus();
  closeMentionMenu();
}
// ============================

let _replyImageUrl = null;
let _replyImageUrl2 = null;
let _replyR2Key = null;
let _replyR2Key2 = null;
let _replyImageUploadPromise = null;
let _replyImageUploadPromise2 = null;
let _replyImageLocalUrl = null;
let _replyImageLocalUrl2 = null;

function cancelReplyImage(suffix) {
  const isInline = suffix === '2';
  if (isInline) { _replyImageUrl2 = null; _replyImageLocalUrl2 = null; }
  else { _replyImageUrl = null; _replyImageLocalUrl = null; }
  const preview = document.getElementById('reply-input' + suffix + '-preview');
  if (preview) { preview.style.display = 'none'; preview.innerHTML = '<img id="reply-img' + (isInline?'2':'') + '-preview" style="max-height:120px;border-radius:8px;max-width:100%">'; }
  const input = document.getElementById('reply-image-input' + (isInline?'2':''));
  if (input) input.value = '';
}

async function uploadReplyImage(input, previewId) {
  const file = input.files[0];
  if (!file) return;
  const isInline = previewId === 'reply-input2-preview';
  const btn = document.querySelector(isInline ? 'button[onclick="postReply2()"]' : '#thread-detail-view button[onclick="postReply()"]');
  if (file.size > 10 * 1024 * 1024) { toast('Image trop lourde (max 10 Mo)', 'error'); input.value = ''; return; }
  // Afficher preview immédiatement depuis le fichier local
  const localUrl = URL.createObjectURL(file);
  if (isInline) { _replyImageLocalUrl2 = localUrl; } else { _replyImageLocalUrl = localUrl; }
  const preview = document.getElementById(previewId);
  if (preview) {
    preview.innerHTML = '<div style="position:relative;display:inline-block"><img src="' + localUrl + '" style="max-height:120px;border-radius:8px;max-width:100%;opacity:0.5"><button onclick="cancelReplyImage(\'' + (isInline?'2':'') + '\')" style="position:absolute;top:-6px;right:-6px;background:#ef5350;color:white;border:none;border-radius:50%;width:20px;height:20px;cursor:pointer;font-size:12px;line-height:1;padding:0">×</button></div>';
    preview.style.display = 'block';
  }
  input.value = '';
  const uploadPromise = (async () => {
    try {
      const resizedBlob = await new Promise((resolve) => {
        const img = new Image();
        img.onload = () => {
          const MAX = 1200;
          let w = img.width, h = img.height;
          if (w > MAX || h > MAX) { if (w > h) { h = Math.round(h * MAX / w); w = MAX; } else { w = Math.round(w * MAX / h); h = MAX; } }
          const canvas = document.createElement('canvas');
          canvas.width = w; canvas.height = h;
          canvas.getContext('2d').drawImage(img, 0, 0, w, h);
          canvas.toBlob(resolve, 'image/jpeg', 0.85);
        };
        img.src = localUrl;
      });
      const fd = new FormData();
      fd.append('image', resizedBlob, file.name.replace(/\.[^.]+$/, '.jpg'));
      const data = await api('POST', '/threads/upload-image', fd);
      if (data.error) { toast(data.error, 'error'); cancelReplyImage(isInline?'2':''); return; }
      if (data.url) {
        console.log('IMAGE URL SET:', data.url, 'isInline:', isInline);
        if (isInline) { _replyImageUrl2 = data.url; _replyR2Key2 = data.r2Key || null; }
        else { _replyImageUrl = data.url; _replyR2Key = data.r2Key || null; }
        const img = preview?.querySelector('img');
        if (img) { img.src = data.url; img.style.opacity = '1'; }
      }
    } catch(e) { toast(e.message || 'Erreur upload image', 'error'); cancelReplyImage(isInline?'2':''); }
  })();
  if (isInline) { _replyImageUploadPromise2 = uploadPromise; } else { _replyImageUploadPromise = uploadPromise; }
}

let _sendingReply = false;
async function postReply() {
  if (_sendingReply) return;
  _sendingReply = true;
  const input = document.getElementById('reply-input');
  const message = input.value.trim();
  if ((!message && !_replyImageUrl && !_voiceBlob) || !_discussionFileId) { _sendingReply = false; return; }
  const btn = document.querySelector('#thread-detail-view button[onclick="postReply()"]');
  // Optimistic UI — immédiat
  const tempId = 'temp-' + Date.now();
  const container = document.getElementById('thread-replies');
  const _tempImgHtml = _replyImageLocalUrl ? '<div style="margin-top:6px"><img src="' + _replyImageLocalUrl + '" style="max-width:200px;max-height:180px;border-radius:8px;display:block"></div>' : '';
  const tempHtml = '<div id="' + tempId + '" style="display:flex;justify-content:flex-end;margin:4px 0;padding:0 12px"><div style="max-width:75%;background:var(--teal-dark);color:white;border-radius:16px 16px 4px 16px;padding:10px 14px;opacity:0.6;font-size:14px">' + (message || (_voiceBlob ? '🎤 Vocal...' : '')) + _tempImgHtml + '</div></div>';
  if (container) { container.insertAdjacentHTML('beforeend', tempHtml); container.scrollTop = container.scrollHeight; }
  input.value = ''; input.style.height = 'auto';
  if (_voiceBlob) cancelVoicePreview('main');
  cancelReply();
  if (btn) { btn.disabled = false; btn.textContent = 'Répondre'; }
  try {
    if (_replyImageUploadPromise) { await _replyImageUploadPromise; _replyImageUploadPromise = null; }
    cancelReplyImage('');
if (_replyImageUploadPromise) { await _replyImageUploadPromise; _replyImageUploadPromise = null; }
    const _pendingImageUrl = _replyImageUrl; const _pendingR2Key = _replyR2Key;
    cancelReplyImage('');
    if (!message && !_pendingImageUrl && !_pendingVoiceBlob) { const t = document.getElementById(tempId); if (t) t.remove(); _sendingReply = false; return; }
    const body = { message };
    if (_pendingVoiceBlob) { await new Promise(resolve => { const r = new FileReader(); r.onload = async () => { body.audio = r.result; body.audioDuration = _voiceSeconds; resolve(); }; r.readAsDataURL(_pendingVoiceBlob); }); }
    if (_pendingImageUrl) { body.imageUrl = _pendingImageUrl; body.r2Key = _pendingR2Key || null; }
    if (_replyTo) { body.replyToId = _replyTo.id; body.replyToName = _replyTo.userName; body.replyToPreview = _replyTo.msgPreview; }
    await loadThreadReplies(true);
    const tempEl = document.getElementById(tempId);
    if (tempEl) tempEl.remove();
    if (container) container.scrollTop = container.scrollHeight;
  } catch(e) {
    const tempEl = document.getElementById(tempId);
    if (tempEl) tempEl.innerHTML = '<div style="max-width:75%;background:#b71c1c;color:white;border-radius:16px 16px 4px 16px;padding:10px 14px;font-size:14px">' + (message || '🖼️') + '<div style="font-size:11px;margin-top:4px;opacity:0.85">⚠️ Non envoyé · <span style="text-decoration:underline;cursor:pointer" onclick="this.closest(\'[id^=temp-]\').remove();postReply()">Réessayer</span></div></div>';
  }
  finally { _sendingReply = false; }
}

async function deleteReply(replyId, skipConfirm) {
  if (!skipConfirm && !!await customConfirm('Supprimer cette réponse ?')) return;
  try {
    await api('DELETE', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/replies/' + replyId);
    await loadThreadReplies(true);
  } catch(e) { toast(e.message, 'error'); }
}

async function deleteThread(threadId) {
  if (!await customConfirm('Supprimer ce fil et toutes ses réponses ?')) return;
  try {
    await api('DELETE', '/threads/' + _discussionFileId + '/' + threadId);
    await loadThreads();
  } catch(e) { toast(e.message, 'error'); }
}

async function toggleResolve() {
  try {
    await api('PATCH', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/resolve');
    await loadThreadReplies(true);
  } catch(e) { toast(e.message, 'error'); }
}







function installPWA() {
  if (!_pwaInstallPrompt.prompt()) {
    // iOS - show manual instructions
    toast('Sur iPhone : bouton Partage \u2192 Sur l\u2019\u00e9cran d\u2019accueil', 'info');
    dismissPWA();
    return;
  }
  _pwaInstallPrompt.prompt();
  _pwaInstallPrompt.userChoice.then(function(result) {
    if (result.outcome === 'accepted') {
      document.getElementById('pwa-banner').style.display = 'none';
    }
    _pwaInstallPrompt = null;
  });
}

function dismissPWA() {
  document.getElementById('pwa-banner').style.display = 'none';
  localStorage.setItem('pwa-dismissed', '1');
}

// ── SIDEBAR MOBILE ───────────────────────────────────────────────────────────
function openSidebar() {
  var sidebar = document.getElementById('sidebar');
  var overlay = document.getElementById('sidebar-overlay');
  if (sidebar) sidebar.classList.add('open');
  if (overlay) overlay.style.display = 'block';
}
function closeSidebar() {
  var sidebar = document.getElementById('sidebar');
  var overlay = document.getElementById('sidebar-overlay');
  if (sidebar) sidebar.classList.remove('open');
  if (overlay) overlay.style.display = 'none';
}
function toggleSidebar() {
  var sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  if (window.innerWidth <= 768) {
    // Mobile : slide in/out
    if (sidebar.classList.contains('open')) {
      closeSidebar();
    } else {
      openSidebar();
    }
  } else {
    // Desktop : collapse/expand
    sidebar.classList.toggle('collapsed');
    localStorage.setItem('sidebar_collapsed', sidebar.classList.contains('collapsed') ? '1' : '0');
  }
}

// ── VOCAL RECORDING ──────────────────────────────────────────────────────────
let _voiceRecorder = null;
let _voiceChunks = [];
let _voiceTimer = null;
let _voiceSeconds = 0;
let _voiceLocked = false;
let _voiceContext = null;
let _voiceBlob = null;
let _previewAudio = null;
let _voiceTouchStartX = 0;
let _voiceTouchStartY = 0;
let _voiceJustCancelled = false;
let _voiceStarting = false;
let _voicePendingStop = false;

function getVoiceIds(ctx) {
  return {
    btn: ctx === 'main' ? 'record-btn' : 'record-btn2',
    label: ctx === 'main' ? 'record-label' : 'record-label2',
    timer: ctx === 'main' ? 'record-timer' : 'record-timer2',
    lock: ctx === 'main' ? 'record-lock-btn' : 'record-lock-btn2',
    preview: ctx === 'main' ? 'voice-preview-main' : 'voice-preview-side',
    playBtn: ctx === 'main' ? 'preview-play-btn-main' : 'preview-play-btn-side',
    canvas: ctx === 'main' ? 'preview-waveform-main' : 'preview-waveform-side',
    duration: ctx === 'main' ? 'preview-duration-main' : 'preview-duration-side',
  };
}

async function startRecording(ctx) {
  if (_voiceJustCancelled) return;
  if (_voiceRecorder && _voiceRecorder.state === 'recording') return;
  _voiceStarting = true;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    _voiceContext = ctx;
    _voiceChunks = [];
    _voiceBlob = null;
    _voiceSeconds = 0;
    const ids = getVoiceIds(ctx);

    _voiceRecorder = new MediaRecorder(stream);
    _voiceRecorder.ondataavailable = e => _voiceChunks.push(e.data);
    _voiceRecorder.onstop = () => {
      stream.getTracks().forEach(t => t.stop());
      _voiceBlob = new Blob(_voiceChunks, { type: 'audio/webm' });
      clearInterval(_voiceTimer);
      showVoicePreview(ctx);
    };
    _voiceRecorder.start();
    _voiceStarting = false;
    if (_voicePendingStop) { _voicePendingStop = false; stopRecordingHold(ctx); return; }

    const btn = document.getElementById(ids.btn);
    const lbl = document.getElementById(ids.label);
    const timer = document.getElementById(ids.timer);
    const lock = document.getElementById(ids.lock);
    if (btn) { btn.style.borderColor = '#ef5350'; btn.style.color = '#ef5350'; btn.style.background = 'rgba(239,83,80,0.08)'; }
    if (lbl) lbl.textContent = '⏺ Enregistrement...';
    if (timer) timer.style.display = 'inline';
    if (lock) { lock.style.display = 'flex'; lock.textContent = '🔓'; }

    _voiceTimer = setInterval(() => {
      _voiceSeconds++;
      const m = Math.floor(_voiceSeconds / 60);
      const s = _voiceSeconds % 60;
      if (timer) timer.textContent = m + ':' + (s < 10 ? '0' : '') + s;
      if (_voiceSeconds >= 120) stopRecording(ctx);
    }, 1000);
  } catch(e) {
    toast('Micro non disponible : ' + e.message, 'error');
  }
}

function handleVoiceTouchStart(e, ctx) {
  e.preventDefault();
  e.stopPropagation();
  _voiceTouchStartX = e.touches[0].clientX;
  _voiceTouchStartY = e.touches[0].clientY;
  startRecording(ctx);
}

function handleVoiceTouchMove(e, ctx) {
  if (_voiceLocked) return;
  e.preventDefault();
  const dx = e.touches[0].clientX - _voiceTouchStartX;
  const dy = e.touches[0].clientY - _voiceTouchStartY;
  // Slide UP vers le cadenas = mode mains libres
  if (dy < -40) {
    lockRecording(ctx);
    return;
  }
  // Slide LEFT = annuler
  if (dx < -60) {
    cancelRecording(ctx);
  }
}

function handleVoiceTouchEnd(e, ctx) {
  if (e && e.cancelable) { e.preventDefault(); e.stopPropagation(); }
  if (_voiceLocked) return;
  stopRecordingHold(ctx);
}

function stopRecordingHold(ctx) {
  if (_voiceLocked) return;
  if (_voiceStarting) { _voicePendingStop = true; return; }
  if (!_voiceRecorder || _voiceRecorder.state !== 'recording') return;
  _voiceRecorder.stop();
  resetVoiceUI(ctx);
}

function lockRecording(ctx) {
  _voiceLocked = true;
  const ids = getVoiceIds(ctx);
  const lock = document.getElementById(ids.lock);
  const lbl = document.getElementById(ids.label);
  const btn = document.getElementById(ids.btn);
  if (lock) {
    lock.textContent = '🔒';
    lock.style.display = 'flex';
    lock.style.background = 'var(--teal-dark)';
    lock.style.color = 'white';
    lock.onclick = () => { _voiceLocked = false; stopRecording(ctx); };
  }
  if (lbl) {
    lbl.textContent = '🔒 Mains libres – clique pour arrêter';
    lbl.style.cursor = 'pointer';
    lbl.style.color = 'var(--teal-dark)';
    lbl.style.fontWeight = '700';
    lbl.onclick = () => { _voiceLocked = false; stopRecording(ctx); };
  }
  if (btn) {
    btn.style.borderColor = 'var(--teal)';
    btn.style.color = 'var(--teal)';
    btn.style.background = 'rgba(0,151,167,0.08)';
  }
}

function cancelRecording(ctx) {
  _voiceLocked = false;
  if (_voiceRecorder && _voiceRecorder.state === 'recording') {
    _voiceRecorder.ondataavailable = null;
    _voiceRecorder.onstop = null;
    _voiceRecorder.stop();
  }
  clearInterval(_voiceTimer);
  _voiceBlob = null;
  resetVoiceUI(ctx);
  toast('Enregistrement annulé');
}

function stopRecording(ctx) {
  if (!_voiceRecorder || _voiceRecorder.state !== 'recording') return;
  if (_voiceLocked) return;
  _voiceRecorder.stop();
  resetVoiceUI(ctx);
}
function resetVoiceUI(ctx) {
  const ids = getVoiceIds(ctx);
  const btn = document.getElementById(ids.btn);
  const lbl = document.getElementById(ids.label);
  const timer = document.getElementById(ids.timer);
  const lock = document.getElementById(ids.lock);
  if (btn) { btn.style.borderColor = 'var(--border)'; btn.style.color = 'var(--text2)'; btn.style.background = 'transparent'; }
  if (lbl) {
    lbl.textContent = '🎤 Rester appuyé';
    lbl.style.cursor = '';
    lbl.style.color = '';
    lbl.style.fontWeight = '';
    lbl.onclick = null;
  }
  if (timer) { timer.style.display = 'none'; timer.textContent = '0:00'; }
  if (lock) { lock.style.display = 'none'; lock.textContent = '🔓'; lock.style.background = 'transparent'; lock.style.color = ''; lock.onclick = () => lockRecording(ctx); }
}

async function showVoicePreview(ctx) {
  if (!_voiceBlob) return;
  const ids = getVoiceIds(ctx);
  const preview = document.getElementById(ids.preview);
  if (!preview) return;
  preview.style.display = 'flex';
  const durEl = document.getElementById(ids.duration);
  const m = Math.floor(_voiceSeconds / 60);
  const s = _voiceSeconds % 60;
  if (durEl) durEl.textContent = m + ':' + (s < 10 ? '0' : '') + s;
  const canvas = document.getElementById(ids.canvas);
  if (canvas && _voiceBlob) drawWaveform(canvas, _voiceBlob);
}

async function drawWaveform(canvas, blob) {
  try {
    const arrayBuffer = await blob.arrayBuffer();
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const audioBuffer = await audioCtx.decodeAudioData(arrayBuffer);
    const data = audioBuffer.getChannelData(0);
    const ctx2d = canvas.getContext('2d');
    const W = canvas.width = canvas.offsetWidth || 160;
    const H = canvas.height = 32;
    ctx2d.clearRect(0, 0, W, H);
    const bars = Math.floor(W / 4);
    const step = Math.floor(data.length / bars);
    ctx2d.fillStyle = '#006064';
    for (let i = 0; i < bars; i++) {
      let max = 0;
      for (let j = 0; j < step; j++) max = Math.max(max, Math.abs(data[i * step + j] || 0));
      const h = Math.max(3, Math.round(max * H * 0.9));
      ctx2d.beginPath();
      ctx2d.rect(i * 4, (H - h) / 2, 3, h);
      ctx2d.fill();
    }
  } catch(e) {
    // Fallback bars
    const ctx2d = canvas.getContext('2d');
    const W = canvas.width = canvas.offsetWidth || 160;
    const H = canvas.height = 32;
    ctx2d.fillStyle = '#006064';
    const bars = Math.floor(W / 4);
    for (let i = 0; i < bars; i++) {
      const h = Math.max(3, Math.round(Math.abs(Math.sin(i * 0.8)) * H * 0.7 + 4));
      ctx2d.beginPath();
      ctx2d.rect(i * 4, (H - h) / 2, 3, h);
      ctx2d.fill();
    }
  }
}

function playVoicePreview(ctx) {
  if (!_voiceBlob) return;
  const ids = getVoiceIds(ctx);
  const playBtn = document.getElementById(ids.playBtn);
  if (_previewAudio && !_previewAudio.paused) {
    _previewAudio.pause();
    _previewAudio.currentTime = 0;
    if (playBtn) playBtn.textContent = '▶';
    return;
  }
  const url = URL.createObjectURL(_voiceBlob);
  _previewAudio = new Audio(url);
  _previewAudio.play();
  if (playBtn) playBtn.textContent = '⏸';
  _previewAudio.onended = () => { if (playBtn) playBtn.textContent = '▶'; };
}

function cancelVoicePreview(ctx) {
  if (_previewAudio) { _previewAudio.pause(); _previewAudio = null; }
  _voiceBlob = null;
  _voiceSeconds = 0;
  const ids = getVoiceIds(ctx);
  const preview = document.getElementById(ids.preview);
  if (preview) preview.style.display = 'none';
  // Empêche le touchend de la croix de relancer l'enregistrement
  _voiceJustCancelled = true;
  setTimeout(() => { _voiceJustCancelled = false; }, 400);
}

async function sendVoiceMessage(ctx) {
  if (!_voiceBlob) return;
  const dur = _voiceSeconds;
  const reader = new FileReader();
  reader.onload = async () => {
    try {
      await api('POST', '/threads/' + _discussionFileId + '/' + _currentThreadId + '/replies', {
        message: '', audio: reader.result, audioDuration: dur
      });
      cancelVoicePreview(ctx);
      if (ctx === 'main') await loadThreadReplies(false);
      else await loadThreadRepliesInline(true);
    } catch(e) { toast(e.message, 'error'); }
  };
  reader.readAsDataURL(_voiceBlob);
}

function toggleRecording() {}
function toggleRecording2() {}

function handleLockBtnClick(ctx) {
  if (_voiceLocked) {
    _voiceLocked = false;
    stopRecording(ctx);
  } else {
    lockRecording(ctx);
  }
}

// ── Gestion souris (desktop) ──────────────────────────────────────────────────
let _voiceMouseCtx = null;
let _voiceMouseStartX = 0;
let _voiceMouseStartY = 0;

function handleVoiceMouseDown(e, ctx) {
  if (_voiceJustCancelled) return;
  _voiceMouseCtx = ctx;
  _voiceMouseStartX = e.clientX;
  _voiceMouseStartY = e.clientY;
  startRecording(ctx);
  document.addEventListener('mousemove', _onVoiceMouseMove);
  document.addEventListener('mouseup', _onVoiceMouseUp);
}

function _onVoiceMouseMove(e) {
  const ctx = _voiceMouseCtx;
  if (!ctx) return;
  if (_voiceLocked) return;
  const dx = e.clientX - _voiceMouseStartX;
  const dy = e.clientY - _voiceMouseStartY;
if (dy < -40) {
    lockRecording(ctx);
    _cleanVoiceMouseListeners();
    return;
  }
  if (dx < -60) {
    cancelRecording(ctx);
    _cleanVoiceMouseListeners();
  }
}

function _onVoiceMouseUp() {
  const ctx = _voiceMouseCtx;
  _cleanVoiceMouseListeners();
  if (_voiceLocked) return;
  if (ctx) stopRecordingHold(ctx);
}

function _cleanVoiceMouseListeners() {
  document.removeEventListener('mousemove', _onVoiceMouseMove);
  document.removeEventListener('mouseup', _onVoiceMouseUp);
  _voiceMouseCtx = null;
}
async function loadSecurityPanel() {
  const db = await api('GET', '/settings');
  const input = document.getElementById('global-expires-input');
  const status = document.getElementById('global-expiry-status');
  if (input && db.defaultExpiresAt) {
    input.value = db.defaultExpiresAt.substring(0, 10);
    if (status) status.textContent = 'Date actuelle : ' + new Date(db.defaultExpiresAt).toLocaleDateString('fr-FR');
  } else if (status) {
    status.textContent = 'Aucune date globale définie.';
  }
  const users = await api('GET', '/users');
  const students = users.filter(u => u.role === 'student');
  const list = document.getElementById('security-students-list');
  if (!list) return;
  if (!students.length) { list.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3)">Aucun étudiant.</div>'; return; }
  const globalExpiry = db.defaultExpiresAt;
list.innerHTML = students.map(u => {
    const hasCustomExpiry = !!u.expiresAt;
const expiry = hasCustomExpiry ? new Date(u.expiresAt).toLocaleDateString('fr-FR') : (globalExpiry ? new Date(globalExpiry).toLocaleDateString('fr-FR') : null);
    const effectiveExpiry = u.expiresAt || globalExpiry;
const isExpired = effectiveExpiry && new Date() >= new Date(effectiveExpiry);
    return `<div style="display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--border)">
      <div style="flex:1">
        <div style="font-weight:600;font-size:13px;color:var(--text)">${u.name}</div>
        <div style="font-size:11px;color:var(--text3)">${u.login}</div>
      </div>
      <div style="font-size:12px;color:${isExpired ? '#ef5350' : 'var(--text3)'}">
        ${isExpired ? `<span style="color:#ef5350;font-weight:700">🔴 Expiré le ${expiry}</span>` : `<span style="color:var(--teal-dark)">${hasCustomExpiry ? '🔒 Perso : ' : '🌐 Global : '}${expiry || '—'}</span>`}
      </div>
      ${isExpired ? `<button onclick="unlockUser(${u.id})" style="padding:6px 12px;background:#ef5350;color:white;border:none;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer;margin-right:6px">🔓 Débloquer</button>` : ''} <button onclick="setUserExpiry(${u.id})" style="padding:6px 12px;background:linear-gradient(135deg,var(--teal),var(--teal-dark));color:white;border:none;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer">📅 Date perso</button>
    </div>`;
  }).join('');
}

async function saveGlobalExpiry() {
  const input = document.getElementById('global-expires-input');
  if (!input || !input.value) return toast('Choisis une date', 'error');
  await api('PATCH', '/settings', { defaultExpiresAt: new Date(input.value).toISOString() });
  toast('Date globale enregistrée');
  loadSecurityPanel();
}

async function removeGlobalExpiry() {
  await api('PATCH', '/settings', { defaultExpiresAt: null });
  const input = document.getElementById('global-expires-input');
  if (input) input.value = '';
  toast('Date globale supprimée');
  loadSecurityPanel();
}

async function setUserExpiry(userId) {
  const date = await customPrompt('Définir une date personnalisée (JJ/MM/AAAA) :', '');
  if (!date) return;
  const parts = date.split('/');
  if (parts.length !== 3) return toast('Format invalide, utilise JJ/MM/AAAA', 'error');
  const iso = new Date(`${parts[2]}-${parts[1]}-${parts[0]}`).toISOString();
  await api('PATCH', `/users/${userId}/expires`, { expiresAt: iso });
  toast('Date mise à jour');
  loadSecurityPanel();
}
function filterSecurityStudents(query) {
  const rows = document.querySelectorAll('#security-students-list > div');
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(query.toLowerCase()) ? 'flex' : 'none';
  });
}
async function unlockUser(userId) {
  const date = await customPrompt('Débloquer jusqu\'au (JJ/MM/AAAA) :', '');
  if (!date) return;
  const parts = date.split('/');
  if (parts.length !== 3) return toast('Format invalide, utilise JJ/MM/AAAA', 'error');
  const iso = new Date(`${parts[2]}-${parts[1]}-${parts[0]}`).toISOString();
  await api('PATCH', `/users/${userId}/expires`, { expiresAt: iso });
  toast('Compte débloqué');
  loadSecurityPanel();
}
async function unlockAllUsers() {
  const date = await customPrompt('Nouvelle date de blocage globale (JJ/MM/AAAA) :', '');
  if (!date) return;
  const parts = date.split('/');
  if (parts.length !== 3) return toast('Format invalide, utilise JJ/MM/AAAA', 'error');
  const iso = new Date(`${parts[2]}-${parts[1]}-${parts[0]}`).toISOString();
  await api('PATCH', '/settings', { defaultExpiresAt: iso });
  const users = await api('GET', '/users');
  const students = users.filter(u => u.role === 'student');
  await Promise.all(students.map(u => api('PATCH', `/users/${u.id}/expires`, { expiresAt: null })));
  toast('Date globale mise à jour — tous les comptes débloqués jusqu\'au ' + date);
  loadSecurityPanel();
}
