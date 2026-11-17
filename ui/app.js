'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const fmt = new Intl.NumberFormat();

const state = {
  status: null,
  datasets: null,
  recipes: null,
  jobs: [],
  selected: null,
  selectedDetail: null,
};

let searchRows = [];
let pollTimer = null;
let wasRunning = false;
let toastTimer = null;

const escaped = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await response.json().catch(() => ({ error: response.statusText }));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function toast(message, isError = false) {
  const node = $('#toast');
  node.textContent = message;
  node.classList.toggle('error', isError);
  node.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.add('hidden'), 5200);
}

function showTab(name) {
  $$('#tabs button').forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === name));
  $$('.tab').forEach((section) => section.classList.toggle('active', section.id === `tab-${name}`));
  if (name === 'playbook' && state.recipes) renderPlaybook();
}

function allRecipes() {
  if (!state.recipes) return [];
  return state.recipes.flatMap((phase) =>
    (phase.recipes || []).map((recipe) => ({ ...recipe, phase: phase.phase }))
  );
}

function findRecipe(id) {
  return allRecipes().find((recipe) => recipe.id === id);
}

/* ------------------------------------------------------------------ */
/* status                                                             */
/* ------------------------------------------------------------------ */

async function loadStatus() {
  try {
    state.status = await api('/api/status');
  } catch (error) {
    toast(error.message, true);
    return;
  }
  renderStatus();
  if (state.datasets) renderDatasets();
}

function renderStatus() {
  const s = state.status;
  if (!s) return;

  const reachable = s.splunk?.reachable;
  $('#pulse').className = `pulse ${reachable ? 'ok' : 'bad'}`;
  const pill = $('#lab-pill');
  pill.className = `pill ${reachable ? 'ok' : 'bad'}`;
  pill.textContent = reachable ? `Splunk ${s.splunk.version || 'online'}` : 'Splunk offline';
  $('#splunk-link').href = s.web_url || 'http://127.0.0.1:8000';

  const fieldsOk = s.fields?.installed && s.fields?.verified !== false;
  const cards = [
    {
      label: 'Splunk API',
      value: reachable ? (s.splunk.version || 'online') : 'offline',
      sub: reachable
        ? `${s.splunk.name || 'local'} · container ${s.docker?.running ? 'up' : 'down'}`
        : (s.docker?.running ? 'container is up, API starting' : 'start the container below'),
      cls: reachable ? 'good' : 'bad',
    },
    {
      label: 'Telemetry',
      value: fmt.format(s.data?.events || 0),
      sub: `${fmt.format(s.data?.hosts || 0)} hosts · ${s.data?.sourcetypes?.length || 0} sourcetypes`,
      cls: (s.data?.events || 0) > 0 ? '' : 'warn',
    },
    {
      label: 'Field extraction',
      value: fieldsOk ? 'active' : (s.fields?.installed ? 'inactive' : 'missing'),
      sub: fieldsOk ? 'EventCode, ProcessName, CommandLine…' : 'Windows hunts need this',
      cls: fieldsOk ? 'good' : 'warn',
    },
    {
      label: 'Replay path',
      value: s.hec?.ok ? 'HEC ready' : 'no HEC',
      sub: `${s.index_exists === false ? 'missing index' : 'index'} ${s.index}`,
      cls: s.hec?.ok ? 'good' : 'bad',
    },
  ];

  $('#status-cards').innerHTML = cards.map((card) => `
    <div class="card ${card.cls}">
      <div class="card-label">${escaped(card.label)}</div>
      <div class="card-value">${escaped(card.value)}</div>
      <div class="card-sub">${escaped(card.sub)}</div>
    </div>`).join('');

  renderBanner();
  renderChecklist();
  renderLoaded();
  renderRecentJobs();
}

function renderBanner() {
  const banner = $('#banner');
  const s = state.status;
  if (!s) return;
  let html = '';
  if (!s.repo?.ready) {
    html = `<div><strong>attack_data is not downloaded.</strong>
      Clone the repository metadata (small), then download only the technique folders you want.
      Nothing is fetched until you press Download on a dataset.</div>
      <div class="banner-actions">
        <button class="btn primary tiny" data-action="clone-repo">Clone attack_data</button>
        <a class="btn ghost tiny" href="${escaped(s.repo?.url || 'https://github.com/splunk/attack_data')}" target="_blank" rel="noreferrer">Repo ↗</a>
      </div>`;
  } else if (!s.splunk?.reachable) {
    html = `<div><strong>Splunk is offline.</strong> Start the container, then refresh this page.</div>
      <div class="banner-actions">
        <button class="btn primary tiny" data-action="start-lab">Start Splunk</button>
        <a class="btn ghost tiny" href="${escaped(s.web_url)}" target="_blank" rel="noreferrer">Open Splunk</a>
      </div>`;
  } else if (!s.fields?.installed) {
    html = `<div><strong>Windows fields are not extracted.</strong>
      The replayed XML has no <code>EventCode</code>, <code>ProcessName</code> or <code>CommandLine</code>,
      so most hunts would return nothing. Install the lab extraction (no restart, ~2s).</div>
      <div class="banner-actions">
        <button class="btn primary tiny" data-action="install-fields">Install field extraction</button>
      </div>`;
  } else if (s.fields?.verified === false) {
    html = `<div><strong>Field extraction is installed but not active yet.</strong>
      Reload the Splunk configs or restart the container if this persists.</div>
      <div class="banner-actions">
        <button class="btn tiny" data-action="install-fields">Reload / reinstall</button>
      </div>`;
  }
  banner.innerHTML = html;
  banner.classList.toggle('hidden', !html);
}

function renderChecklist() {
  const s = state.status;
  const loaded = s?.loaded || [];
  const steps = [
    {
      done: !!s?.repo?.ready,
      title: 'attack_data repository is available',
      detail: s?.repo?.ready
        ? s.repo.path
        : 'Clone metadata only; each dataset downloads its own LFS files on demand.',
      action: !s?.repo?.ready
        ? '<button class="btn tiny primary" data-action="clone-repo">Clone attack_data</button>'
        : '',
    },
    {
      done: !!s?.splunk?.reachable,
      title: 'Splunk is running',
      detail: s?.splunk?.reachable
        ? `${s.splunk.name} · ${s.splunk.license}`
        : 'Start the container and wait for the API.',
      action: !s?.splunk?.reachable
        ? '<button class="btn tiny primary" data-action="start-lab">Start Splunk</button>'
        : `<a class="btn tiny ghost" href="${escaped(s.web_url)}" target="_blank" rel="noreferrer">Open Splunk ↗</a>`,
    },
    {
      done: !!(s?.fields?.installed && s?.fields?.verified !== false),
      title: 'Windows fields are extracted',
      detail: 'Makes EventCode, Image, CommandLine, GrantedAccess and friends searchable.',
      action: !s?.fields?.installed
        ? '<button class="btn tiny" data-action="install-fields">Install</button>'
        : '',
    },
    {
      done: (s?.data?.events || 0) > 0,
      title: 'Attack data is in the index',
      detail: (s?.data?.events || 0) > 0
        ? `${fmt.format(s.data.events)} events across ${fmt.format(s.data.hosts)} hosts`
        : 'Replay a dataset from the Datasets tab.',
      action: (s?.data?.events || 0) > 0 ? '' : '<button class="btn tiny" data-goto="datasets">Browse datasets</button>',
    },
    {
      done: loaded.length > 0,
      title: 'Pick a technique and replay it',
      detail: loaded.length
        ? `${loaded.length} host${loaded.length === 1 ? '' : 's'} already replayed`
        : 'The T1003.001 folder is a good first credential-dumping scenario.',
      action: '<button class="btn tiny ghost" data-goto="datasets">Datasets</button>',
    },
    {
      done: false,
      title: 'Hunt, triage, and write it down',
      detail: 'Work through the Phases in the Playbook; then recreate one hit in Splunk Web.',
      action: '<button class="btn tiny ghost" data-goto="playbook">Playbook</button>',
    },
  ];

  $('#checklist').innerHTML = steps.map((step, index) => `
    <li class="${step.done ? 'done' : ''}">
      <span class="step-num">${step.done ? '✓' : index + 1}</span>
      <div class="step-body">
        <div class="step-title">${escaped(step.title)}</div>
        <div class="step-detail">${escaped(step.detail)}</div>
        ${step.action ? `<div class="step-action">${step.action}</div>` : ''}
      </div>
    </li>`).join('');
}

function renderLoaded() {
  const container = $('#loaded-table');
  const loaded = state.status?.loaded || [];
  if (!loaded.length) {
    container.innerHTML = `<div class="empty">
      <div class="empty-icon">∅</div>
      <h2>No attack data yet</h2>
      <p class="muted">Open Datasets, choose a technique, and press Replay.</p>
      <div class="detail-actions" style="justify-content:center;margin-top:14px">
        <button class="btn primary" data-goto="datasets">Browse datasets</button>
      </div>
    </div>`;
    return;
  }

  const rows = loaded.map((item) => `
    <tr>
      <td>
        <div><strong>${escaped(item.label)}</strong></div>
        <div class="muted small mono">${escaped(item.host)}</div>
      </td>
      <td><span class="chips">${(item.techniques || []).slice(0, 3).map((tech) => `<span class="badge purple">${escaped(tech)}</span>`).join('') || '<span class="muted">—</span>'}</span></td>
      <td class="mono">${fmt.format(item.count)}</td>
      <td class="right">
        <button class="btn tiny" data-action="search-host" data-host="${escaped(item.host)}">Search</button>
        ${item.path ? `<button class="btn tiny ghost" data-action="open-dataset" data-path="${escaped(item.path)}">Dataset</button>` : ''}
      </td>
    </tr>`).join('');

  container.innerHTML = `<div class="table-wrap">
    <table><thead><tr><th>Dataset / host</th><th>Technique</th><th>Events</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

/* ------------------------------------------------------------------ */
/* datasets                                                           */
/* ------------------------------------------------------------------ */

async function loadDatasets(force = false) {
  try {
    state.datasets = await api(`/api/datasets${force ? '?refresh=1' : ''}`);
  } catch (error) {
    toast(error.message, true);
    return;
  }
  const category = $('#ds-category');
  if (category.options.length <= 1) {
    category.innerHTML = '<option value="">All categories</option>' +
      state.datasets.categories.map((cat) => `<option value="${escaped(cat)}">${escaped(cat)}</option>`).join('');
  }
  renderDatasets();
}

function loadedPaths() {
  const paths = new Set();
  (state.status?.loaded || []).forEach((item) => {
    (item.paths || [item.path]).filter(Boolean).forEach((path) => paths.add(path));
  });
  return paths;
}

function stateBadge(dataset) {
  const map = {
    ready: ['green', 'downloaded'],
    partial: ['amber', 'partial'],
    missing: ['red', 'needs download'],
    legacy: ['blue', 'legacy YAML'],
    unknown: ['blue', 'unknown'],
  };
  const [color, text] = map[dataset.state] || ['', dataset.state];
  return `<span class="badge ${color}">${escaped(text)}</span>`;
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

function renderDatasets() {
  if (!state.datasets) return;
  if (!state.datasets.datasets.length) {
    $('#ds-count').textContent = '0 folders';
    $('#ds-list').innerHTML = !state.status?.repo?.ready
      ? `<div class="empty">
          <div class="empty-icon">↓</div>
          <h2>attack_data is not downloaded</h2>
          <p class="muted">Clone the repository metadata first. Logs stay out until you download a specific technique folder.</p>
          <div class="detail-actions" style="justify-content:center;margin-top:14px">
            <button class="btn primary" data-action="clone-repo">Clone attack_data</button>
          </div>
        </div>`
      : '<div class="empty"><h2>No datasets found</h2><p class="muted">The checkout has no dataset YAML files.</p></div>';
    return;
  }
  const query = $('#ds-search').value.trim().toLowerCase();
  const category = $('#ds-category').value;
  const statusFilter = $('#ds-state').value;
  const replayed = loadedPaths();

  let rows = state.datasets.datasets.filter((dataset) => {
    if (category && dataset.category !== category) return false;
    if (statusFilter === 'ready' && dataset.state !== 'ready') return false;
    if (statusFilter === 'missing' && !['missing', 'partial'].includes(dataset.state)) return false;
    if (statusFilter === 'loaded' && !replayed.has(dataset.path)) return false;
    if (query) {
      const haystack = [
        dataset.path, dataset.label, dataset.techniques.join(' '), dataset.description,
      ].join(' ').toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });

  const total = rows.length;
  const limit = 250;
  rows = rows.slice(0, limit);

  $('#ds-count').textContent = `${fmt.format(total)} folder${total === 1 ? '' : 's'} match` +
    (total > limit ? ` · showing first ${limit}` : '');

  if (!rows.length) {
    $('#ds-list').innerHTML = '<div class="empty"><h2>No matches</h2><p class="muted">Try a technique ID like T1003 or clear the filters.</p></div>';
    return;
  }

  $('#ds-list').innerHTML = rows.map((dataset) => `
    <button class="ds-row ${dataset.path === state.selected ? 'active' : ''}" data-path="${escaped(dataset.path)}">
      <div class="ds-info">
        <div class="ds-title"><span class="dot ${escaped(dataset.state)}"></span>${escaped(dataset.label)}</div>
        <div class="ds-sub">
          ${(dataset.techniques || []).slice(0, 3).map((tech) => `<span class="badge purple">${escaped(tech)}</span>`).join('')}
          <span class="path">${escaped(dataset.path)}</span>
        </div>
      </div>
      <div class="ds-side">
        ${replayed.has(dataset.path) ? '<span class="badge green">replayed</span>' : ''}
        ${stateBadge(dataset)}
        <span class="muted small">${formatBytes(dataset.bytes)}</span>
      </div>
    </button>`).join('');
}

async function openDataset(path, silent = false) {
  state.selected = path;
  $$('.ds-row').forEach((row) => row.classList.toggle('active', row.dataset.path === path));
  try {
    state.selectedDetail = await api(`/api/dataset?path=${encodeURIComponent(path)}`);
    renderDetail();
  } catch (error) {
    if (!silent) toast(error.message, true);
  }
}

function renderDetail() {
  const detail = state.selectedDetail;
  if (!detail) return;
  const loaded = (state.status?.loaded || []).find(
    (item) => (item.paths || []).includes(detail.path) ||
      (item.host && (detail.hosts || []).includes(item.host))
  );
  const fieldsOk = state.status?.fields?.installed && state.status?.fields?.verified !== false;
  const isLegacy = detail.state === 'legacy' || detail.legacy;
  const needsDownload = ['missing', 'partial'].includes(detail.state);
  const canReplay = !needsDownload || isLegacy;

  const fileRows = (detail.files || []).map((file) => {
    let status;
    if (!file.exists) status = '<span class="badge red">missing</span>';
    else if (file.pointer) status = '<span class="badge amber">LFS pointer</span>';
    else status = '<span class="badge green">local</span>';
    return `<tr>
      <td class="mono">${escaped(file.file)}</td>
      <td class="mono">${escaped(file.sourcetype || '—')}</td>
      <td class="mono">${formatBytes(file.bytes)}</td>
      <td>${status}</td>
    </tr>`;
  }).join('');

  const techniques = detail.techniques || [];
  const matchingHunts = allRecipes()
    .filter((recipe) => recipeMatches(recipe, techniques))
    .sort((a, b) => (a.techniques?.length ? 0 : 1) - (b.techniques?.length ? 0 : 1))
    .slice(0, 8);
  const huntHost = loaded?.host || '';

  const hunts = matchingHunts.length ? matchingHunts.map((recipe) => `
    <div class="hunt">
      <div class="hunt-head">
        <span class="hunt-title">${escaped(recipe.title)}</span>
        <button class="btn tiny" data-action="run-recipe" data-recipe="${escaped(recipe.id)}" data-host="${escaped(huntHost)}">Run</button>
      </div>
      <div class="hunt-why">${escaped(recipe.why)}</div>
    </div>`).join('') : '<p class="muted">No technique-specific hunts yet. Use the Playbook for generic ones.</p>';

  $('#ds-detail').innerHTML = `
    <div class="section-head" style="padding:0 0 8px">
      <div>
        <h1>${escaped(detail.label)}</h1>
        <div class="detail-path">${escaped(detail.path)}</div>
      </div>
      <div class="chips">${stateBadge(detail)}${loaded ? '<span class="badge green">replayed</span>' : ''}</div>
    </div>

    <p class="description">${escaped(detail.description || 'No description in the dataset YAML.')}</p>

    <dl class="meta-grid">
      <dt>Technique</dt><dd class="chips">${techniques.map((tech) => `<span class="badge purple">${escaped(tech)}</span>`).join('') || '<span class="muted">—</span>'}</dd>
      <dt>Host / UUID</dt><dd class="mono">${(detail.hosts || []).map(escaped).join('<br>') || '<span class="muted">not declared</span>'}</dd>
      <dt>Environment</dt><dd>${escaped(detail.environment || '—')}</dd>
      <dt>Files</dt><dd>${detail.ready_files}/${detail.file_count} local · ${formatBytes(detail.bytes)}</dd>
      <dt>Loaded</dt><dd>${loaded ? `${fmt.format(loaded.count)} events in <code>${escaped(state.status?.index || 'attack_data')}</code>` : '<span class="muted">not replayed</span>'}</dd>
    </dl>

    <div class="detail-actions">
      ${needsDownload || isLegacy ? '<button class="btn primary" data-action="download" data-path="' + escaped(detail.path) + '">Download dataset</button>' : ''}
      <button class="btn ${needsDownload || isLegacy ? '' : 'primary'}" data-action="replay" data-path="${escaped(detail.path)}" ${canReplay ? '' : 'disabled title="Download the dataset first"'}>Replay into Splunk</button>
      ${loaded ? `<button class="btn" data-action="search-host" data-host="${escaped(loaded.host)}">Search this host</button>` : ''}
    </div>
    <div class="note">Replay sends the YAML-declared files to index <code>${escaped(state.status?.index || 'attack_data')}</code> using the dataset's <code>id</code> as <code>host</code>. Replaying twice duplicates events.</div>
    ${isLegacy ? '<div class="note">Legacy YAML format: this dataset lists GitHub URLs instead of local paths. The app maps those URLs to files already in the folder and uses the YAML <code>sourcetypes</code> hints.</div>' : ''}
    ${!fieldsOk ? '<div class="note warn">Windows fields are not active yet. Install the field extraction from the dashboard banner first.</div>' : ''}

    <h2 style="font-size:14px;margin:18px 0 8px">Dataset files</h2>
    ${fileRows ? `<div class="table-wrap" style="max-height:220px"><table class="file-table">
      <thead><tr><th>File</th><th>Sourcetype</th><th>Size</th><th>Status</th></tr></thead>
      <tbody>${fileRows}</tbody></table></div>` : '<p class="muted">No file list in this YAML (legacy format). Replay uses the data files present in the folder.</p>'}

    <h2 style="font-size:14px;margin:20px 0 2px">Suggested hunts${loaded ? ' · scoped to this host' : ''}</h2>
    <div class="hunt-list">${hunts}</div>`;
}

function recipeMatches(recipe, techniques) {
  if (!recipe.techniques || !recipe.techniques.length) return true;
  return (techniques || []).some((technique) =>
    recipe.techniques.some((candidate) =>
      technique === candidate || technique.startsWith(`${candidate}.`) || candidate.startsWith(`${technique}.`)
    )
  );
}

/* ------------------------------------------------------------------ */
/* search                                                             */
/* ------------------------------------------------------------------ */

async function runSearch() {
  const query = $('#spl').value.trim();
  if (!query) {
    toast('Enter a search first.', true);
    return;
  }
  const meta = $('#search-meta');
  meta.innerHTML = '<span class="spinner"></span> running…';
  $('#row-json').classList.add('hidden');
  try {
    const result = await api('/api/search', {
      method: 'POST',
      body: JSON.stringify({
        q: query,
        range: $('#search-range').value,
        limit: 200,
      }),
    });
    renderResults(result);
    meta.textContent = `${fmt.format(result.rows.length)} rows · ${result.elapsed}s`;
  } catch (error) {
    meta.textContent = '';
    $('#result-count').textContent = '';
    $('#search-results').innerHTML = `<div class="note warn"><strong>Search failed.</strong><br>${escaped(error.message)}</div>`;
  }
}

function renderResults(result) {
  searchRows = result.rows || [];
  const fields = (result.fields || []).filter((field) => field !== '_raw').slice(0, 18);
  $('#result-count').textContent = searchRows.length
    ? `${fmt.format(searchRows.length)}${result.truncated ? '+' : ''} events`
    : '';

  if (!searchRows.length) {
    $('#search-results').innerHTML = '<div class="empty"><h2>No events</h2><p class="muted">Try a wider time range or another index.</p></div>';
    return;
  }

  const header = fields.map((field) => `<th class="mono">${escaped(field)}</th>`).join('');
  const body = searchRows.map((row, index) => {
    const cells = fields.map((field) => {
      const value = row[field];
      const text = Array.isArray(value) ? value.join(', ') : (value ?? '');
      return `<td class="mono cell-truncate" title="${escaped(text)}">${escaped(text)}</td>`;
    }).join('');
    return `<tr class="result-row" data-index="${index}">${cells}</tr>`;
  }).join('');

  $('#search-results').innerHTML = `<div class="table-wrap" style="max-height:480px">
    <table><thead><tr>${header}</tr></thead><tbody>${body}</tbody></table></div>`;

  $$('.result-row').forEach((row) => {
    row.addEventListener('click', () => {
      $$('.result-row').forEach((other) => other.classList.remove('selected'));
      row.classList.add('selected');
      const payload = searchRows[Number(row.dataset.index)];
      const text = JSON.stringify(payload, null, 2);
      const box = $('#row-json');
      box.textContent = text.length > 25000 ? `${text.slice(0, 25000)}\n… truncated` : text;
      box.classList.remove('hidden');
    });
  });
}

function openInSplunk(spl, range) {
  const base = state.status?.web_url || 'http://127.0.0.1:8000';
  const ranges = { all: ['0', ''], '15m': ['-15m', 'now'], '1h': ['-1h', 'now'], '24h': ['-24h', 'now'], '7d': ['-7d', 'now'], '30d': ['-30d', 'now'] };
  const [earliest, latest] = ranges[range || $('#search-range').value] || ranges.all;
  let query = spl.trim();
  if (!query.startsWith('|')) query = `search ${query}`;
  const url = `${base}/en-US/app/search/search?q=${encodeURIComponent(query)}&earliest=${encodeURIComponent(earliest)}&latest=${encodeURIComponent(latest)}`;
  window.open(url, '_blank', 'noopener');
}

function loadRecipeIntoSearch(recipe, host) {
  let spl = recipe.spl;
  if (host) {
    const safeHost = String(host).replace(/[^A-Za-z0-9._:-]/g, '');
    if (safeHost) spl = spl.replace(/index=(\S+)/, `index=$1 host="${safeHost}"`);
  }
  showTab('search');
  $('#spl').value = spl;
  runSearch();
}

/* ------------------------------------------------------------------ */
/* playbook                                                           */
/* ------------------------------------------------------------------ */

async function loadRecipes() {
  try {
    state.recipes = await api('/api/recipes');
  } catch (error) {
    toast(error.message, true);
    return;
  }
  renderPlaybook();
  renderQuickSearches();
  if (state.selectedDetail) renderDetail();
}

function renderPlaybook() {
  const container = $('#playbook');
  if (!state.recipes) {
    container.innerHTML = '<p class="muted">Loading…</p>';
    return;
  }
  container.innerHTML = state.recipes.map((phase) => `
    <section class="phase">
      <div class="phase-head">
        <h2>${escaped(phase.phase)}</h2>
        <p>${escaped(phase.intro || '')}</p>
      </div>
      <div class="recipe-grid">
        ${(phase.recipes || []).map((recipe) => `
          <article class="recipe">
            <div class="recipe-top"><h3>${escaped(recipe.title)}</h3></div>
            <p class="why">${escaped(recipe.why)}</p>
            <pre>${escaped(recipe.spl)}</pre>
            <div class="recipe-actions">
              <button class="btn tiny primary" data-action="run-recipe" data-recipe="${escaped(recipe.id)}">Run</button>
              <button class="btn tiny" data-action="open-recipe" data-recipe="${escaped(recipe.id)}">Open in Splunk ↗</button>
              <button class="btn tiny ghost" data-action="copy-recipe">Copy</button>
            </div>
          </article>`).join('')}
      </div>
    </section>`).join('');
}

function renderQuickSearches() {
  const ids = ['inventory', 'event-mix', 'process-timeline', 'lsass-access'];
  if (!state.recipes) return;
  const chips = ids.map((id) => findRecipe(id)).filter(Boolean);
  $('#quick-searches').innerHTML = chips.map((recipe) =>
    `<button class="chip" data-action="quick-recipe" data-recipe="${escaped(recipe.id)}">${escaped(recipe.title)}</button>`
  ).join('');
}

/* ------------------------------------------------------------------ */
/* jobs                                                               */
/* ------------------------------------------------------------------ */

async function startJob(action, path) {
  try {
    const options = { method: 'POST', body: JSON.stringify(path ? { path } : {}) };
    await api(`/api/${action}`, options);
    wasRunning = true;
    openDrawer();
    pollJobs();
  } catch (error) {
    toast(error.message, true);
  }
}

function openDrawer() {
  $('#drawer').classList.add('open');
  $('#drawer-toggle').classList.add('hidden');
}

function closeDrawer() {
  $('#drawer').classList.remove('open');
  $('#drawer-toggle').classList.toggle('hidden', !state.jobs.length);
}

function jobMarkup(job) {
  const color = job.status === 'done' ? 'green' : job.status === 'failed' ? 'red' : 'blue';
  return `<details class="job" ${job.status === 'running' ? 'open' : ''}>
    <summary>
      <span class="job-title"><span class="dot ${color}"></span><span>${escaped(job.title)}</span></span>
      <span class="badge ${color}">${escaped(job.status)}</span>
    </summary>
    <pre>${escaped(job.output || '(no output yet)')}</pre>
  </details>`;
}

function renderJobUIs() {
  const jobs = state.jobs || [];
  const running = jobs.filter((job) => job.status === 'running').length;

  $('#drawer-body').innerHTML = jobs.length
    ? `<div class="job-list">${jobs.map(jobMarkup).join('')}</div>`
    : '<p class="muted">No jobs yet.</p>';
  $('#recent-jobs').innerHTML = jobs.length
    ? `<div class="job-list">${jobs.slice(0, 4).map(jobMarkup).join('')}</div>`
    : '<p class="muted">No jobs yet. Downloads and replays show their output here.</p>';

  $('#job-badge').textContent = running || jobs.length;
  $('#drawer-toggle').classList.toggle('hidden', !jobs.length || $('#drawer').classList.contains('open'));

  $$('.job pre').forEach((pre) => { pre.scrollTop = pre.scrollHeight; });
}

async function pollJobs() {
  clearTimeout(pollTimer);
  try {
    state.jobs = await api('/api/jobs');
  } catch (error) {
    pollTimer = setTimeout(pollJobs, 2500);
    return;
  }
  const running = state.jobs.some((job) => job.status === 'running');
  renderJobUIs();
  if (wasRunning && !running) await refreshAfterJobs();
  wasRunning = running;
  if (running) pollTimer = setTimeout(pollJobs, 1200);
}

async function refreshAfterJobs() {
  await loadStatus();
  await loadDatasets(true);
  if (state.selected) await openDataset(state.selected, true);
}

function renderRecentJobs() {
  // Recent jobs also render in the drawer; keep the dashboard copy in sync.
  const jobs = state.jobs || [];
  const container = $('#recent-jobs');
  if (!container) return;
  container.innerHTML = jobs.length
    ? `<div class="job-list">${jobs.slice(0, 4).map(jobMarkup).join('')}</div>`
    : '<p class="muted">No jobs yet.</p>';
}

/* ------------------------------------------------------------------ */
/* actions                                                            */
/* ------------------------------------------------------------------ */

async function installFields() {
  openDrawer();
  await startJob('install-fields');
}

async function downloadDataset(path) {
  openDrawer();
  await startJob('download', path);
}

async function replayDataset(path) {
  const label = state.selectedDetail?.label || path;
  const ok = confirm(
    `Replay "${label}" into Splunk index ${state.status?.index || 'attack_data'}?\n\n` +
    'Replaying the same dataset twice duplicates events.'
  );
  if (!ok) return;
  openDrawer();
  await startJob('replay', path);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied to clipboard.');
  } catch {
    toast('Clipboard unavailable in this browser.', true);
  }
}

function handleAction(action, element) {
  switch (action) {
    case 'refresh-status': loadStatus(); break;
    case 'clone-repo': openDrawer(); startJob('repo/clone'); break;
    case 'refresh-datasets': loadDatasets(true); break;
    case 'install-fields': installFields(); break;
    case 'start-lab': openDrawer(); startJob('lab/start'); break;
    case 'run-search': runSearch(); break;
    case 'open-splunk': openInSplunk($('#spl').value); break;
    case 'copy-search': copyText($('#spl').value); break;
    case 'open-drawer': openDrawer(); break;
    case 'close-drawer': closeDrawer(); break;
    case 'search-host': {
      showTab('search');
      $('#spl').value = `index=${state.status?.index || 'attack_data'} host="${element.dataset.host}"\n| stats count by sourcetype source\n| sort -count`;
      $('#search-range').value = 'all';
      runSearch();
      break;
    }
    case 'open-dataset': {
      showTab('datasets');
      openDataset(element.dataset.path);
      break;
    }
    case 'download': downloadDataset(element.dataset.path); break;
    case 'replay': replayDataset(element.dataset.path); break;
    case 'quick-recipe': {
      const recipe = findRecipe(element.dataset.recipe);
      if (recipe) loadRecipeIntoSearch(recipe);
      break;
    }
    case 'run-recipe': {
      const recipe = findRecipe(element.dataset.recipe);
      if (recipe) loadRecipeIntoSearch(recipe, element.dataset.host);
      break;
    }
    case 'open-recipe': {
      const recipe = findRecipe(element.dataset.recipe);
      if (recipe) openInSplunk(recipe.spl, 'all');
      break;
    }
    case 'copy-recipe': {
      const pre = element.closest('.recipe')?.querySelector('pre');
      if (pre) copyText(pre.textContent);
      break;
    }
    default:
      break;
  }
}

/* ------------------------------------------------------------------ */
/* init                                                               */
/* ------------------------------------------------------------------ */

function bindEvents() {
  document.addEventListener('click', (event) => {
    const action = event.target.closest('[data-action]');
    if (action) {
      handleAction(action.dataset.action, action);
      return;
    }
    const goto = event.target.closest('[data-goto]');
    if (goto) {
      showTab(goto.dataset.goto);
      return;
    }
    const row = event.target.closest('.ds-row');
    if (row) openDataset(row.dataset.path);
  });

  $$('#tabs button').forEach((button) => {
    button.addEventListener('click', () => showTab(button.dataset.tab));
  });

  ['#ds-search', '#ds-category', '#ds-state'].forEach((selector) => {
    $(selector).addEventListener('input', renderDatasets);
    $(selector).addEventListener('change', renderDatasets);
  });

  $('#spl').addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      runSearch();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeDrawer();
  });
}

async function init() {
  bindEvents();
  await loadStatus();
  await Promise.all([loadDatasets(), loadRecipes()]);
  pollJobs();
}

document.addEventListener('DOMContentLoaded', init);
