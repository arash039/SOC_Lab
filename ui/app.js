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
  scenarios: null,
  scenarioId: null,
  scenarioDoc: null,
  scenarioPreflight: null,
  stageIndex: 0,
  lastCheck: null,
  hintCount: {},
};

let searchRows = [];
let pollTimer = null;
let wasRunning = false;
let toastTimer = null;

const escaped = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));

function techniqueBadge(tech) {
  const match = /^(T\d{4})(?:\.(\d{3}))?$/.exec(String(tech ?? '').trim());
  const label = `<span class="badge purple">${escaped(tech)}</span>`;
  if (!match) return label;
  const url = `https://attack.mitre.org/techniques/${match[1]}/${match[2] ? `${match[2]}/` : ''}`;
  return `<a class="badge purple" href="${url}" target="_blank" rel="noopener" title="Open ${escaped(tech)} on MITRE ATT&CK">${escaped(tech)}</a>`;
}

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
  if (name === 'scenarios' && !state.scenarios) loadScenarios();
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
  renderDangerZone();
}

function renderDangerZone() {
  const s = state.status;
  const container = $('#danger-actions');
  if (!s || !container) return;
  const buttons = [];
  if ((s.data?.events || 0) > 0) {
    buttons.push(
      `<button class="btn danger" data-action="delete-all-replay">Delete all replayed events (${fmt.format(s.data.events)})</button>`
    );
  }
  if (s.repo?.ready && !s.repo.using_parent_checkout) {
    buttons.push(
      '<button class="btn danger" data-action="remove-repo">Remove cloned attack_data</button>'
    );
  }
  if (s.fields?.installed) {
    buttons.push(
      '<button class="btn danger" data-action="uninstall-fields">Remove field extraction</button>'
    );
  }
  container.innerHTML = buttons.length
    ? buttons.join('')
    : '<p class="muted small">Nothing the app added is left to remove.</p>';
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
    if (/not found/i.test(error.message)) {
      state.selected = null;
      state.selectedDetail = null;
      renderDetailEmpty();
    }
  }
}

function renderDetailEmpty() {
  $('#ds-detail').innerHTML = `<div class="empty">
    <div class="empty-icon">⌁</div>
    <h2>Pick a dataset</h2>
    <p class="muted">Choose a technique folder to read the scenario, replay it, and run focused hunts.</p>
  </div>`;
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
        <span class="chips">
          ${recipe.techniques?.length ? techniqueBadge(recipe.techniques[0]) : ''}
          <button class="btn tiny" data-action="run-recipe" data-recipe="${escaped(recipe.id)}" data-host="${escaped(huntHost)}">Run</button>
        </span>
      </div>
      <div class="hunt-why">${escaped(recipe.why)}</div>
    </div>`).join('') : '<p class="muted">No technique-specific hunts yet. Use the Playbook for generic ones.</p>';

  const localCount = (detail.local_files || []).length;
  const deleteButtons = [
    loaded
      ? `<button class="btn danger" data-action="delete-replay" data-path="${escaped(detail.path)}">Delete replayed events</button>`
      : '',
    localCount
      ? `<button class="btn danger" data-action="delete-download" data-path="${escaped(detail.path)}">Delete downloaded files (${localCount})</button>`
      : '',
  ].filter(Boolean).join('');

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
      <dt>Technique</dt><dd class="chips">${techniques.map(techniqueBadge).join('') || '<span class="muted">—</span>'}</dd>
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
    <div class="hunt-list">${hunts}</div>
    ${deleteButtons ? `
      <h2 style="font-size:14px;margin:22px 0 2px">Data management</h2>
      <div class="detail-actions">${deleteButtons}</div>
      <div class="note warn">
        Deleting replayed events removes them from searches (disk is reclaimed when Splunk
        rolls buckets). Deleting downloaded files keeps the YAML metadata and frees the
        local logs; use Download to restore them.
      </div>` : ''}`;
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
/* scenarios                                                          */
/* ------------------------------------------------------------------ */

async function loadScenarios() {
  try {
    state.scenarios = await api('/api/scenarios');
  } catch (error) {
    toast(error.message, true);
    return;
  }
  renderScenarioList();
}

function scenarioBadges(scenario) {
  return [
    ...(scenario.techniques || []).map((tech) => `<span class="badge purple">${escaped(tech)}</span>`),
    scenario.difficulty ? `<span class="badge blue">${escaped(scenario.difficulty)}</span>` : '',
    scenario.estimated_minutes ? `<span class="badge">${escaped(scenario.estimated_minutes)} min</span>` : '',
  ].join('');
}

function renderScenarioList() {
  const list = $('#scenario-list');
  if (!list) return;
  const scenarios = state.scenarios?.scenarios || [];
  $('#scenario-count').textContent = `${scenarios.length} scenario${scenarios.length === 1 ? '' : 's'}`;
  if (!scenarios.length) {
    list.innerHTML = `<div class="empty">
      <div class="empty-icon">◎</div>
      <h2>No scenarios found</h2>
      <p class="muted">Add a JSON file under <code>soc_lab/scenarios/</code>, or pull the latest app version.</p>
    </div>`;
    return;
  }
  list.innerHTML = scenarios.map((scenario) => {
    const percent = scenario.stage_count
      ? Math.round((scenario.completed / scenario.stage_count) * 100)
      : 0;
    return `<button class="ds-row ${scenario.id === state.scenarioId ? 'active' : ''}" data-action="scenario-open" data-id="${escaped(scenario.id)}">
      <div class="ds-info">
        <div class="ds-title">
          ${scenario.done ? '<span class="dot green"></span>' : ''}${escaped(scenario.title)}
          ${scenario.done ? '<span class="badge green">complete</span>' : ''}
        </div>
        <div class="scenario-summary">${escaped(scenario.summary)}</div>
        <div class="progress" aria-hidden="true"><span style="width:${percent}%"></span></div>
      </div>
      <div class="ds-side">
        <span class="chips">${scenarioBadges(scenario)}</span>
        <span class="muted small">${scenario.completed}/${scenario.stage_count} stages</span>
      </div>
    </button>`;
  }).join('');
}

async function openScenario(id, keepStage = false) {
  state.scenarioId = id;
  try {
    const data = await api(`/api/scenario?id=${encodeURIComponent(id)}`);
    state.scenarioDoc = data.scenario;
    state.scenarioPreflight = data.preflight;
  } catch (error) {
    toast(error.message, true);
    return;
  }
  if (!keepStage) {
    const completed = state.scenarioDoc.progress.completed || [];
    const next = state.scenarioDoc.stages.findIndex((stage) => !completed.includes(stage.id));
    state.stageIndex = next === -1 ? 0 : next;
    state.lastCheck = null;
    state.hintCount = {};
  }
  renderScenarioList();
  renderScenarioDetail();
}

function preflightMarkup(preflight) {
  if (!preflight) return '<p class="muted">Checking lab readiness…</p>';
  const steps = (preflight.steps || []).map((step) => `
    <li class="${step.ok ? 'done' : ''}">
      <span class="step-num">${step.ok ? '✓' : '!'}</span>
      <div class="step-body">
        <div class="step-title">${escaped(step.label)}</div>
        <div class="step-detail">${escaped(step.detail)}</div>
      </div>
    </li>`).join('');
  return `<div class="note warn">
      <strong>This scenario needs setup.</strong> One click clones the dataset repository if needed,
      downloads this scenario's files, installs field extraction, and replays the data.
      <div class="setup-actions">
        <button class="btn primary" data-action="scenario-setup">Set up scenario</button>
      </div>
    </div>
    <ol class="checklist">${steps}</ol>`;
}

function renderScenarioDetail() {
  const container = $('#scenario-detail');
  const scenario = state.scenarioDoc;
  if (!container || !scenario) return;

  const header = `
    <div class="section-head" style="padding:0 0 8px">
      <div>
        <h1>${escaped(scenario.title)}</h1>
        <div class="detail-path">${escaped(scenario.dataset.path)}</div>
      </div>
      <div class="chips">${scenarioBadges(scenario)}</div>
    </div>
    <p class="description">${escaped(scenario.summary)}</p>`;

  if (!state.scenarioPreflight?.ready) {
    container.innerHTML = header + preflightMarkup(state.scenarioPreflight);
    return;
  }

  const stage = scenario.stages[state.stageIndex];
  if (!stage) return;
  const completed = scenario.progress.completed || [];
  const hints = stage.hints || [];
  const shown = state.hintCount[stage.id] || 0;

  container.innerHTML = `
    ${header}
    <div class="note"><strong>Briefing.</strong> ${escaped(scenario.briefing)}</div>
    ${scenario.debrief ? `<div class="note"><strong>Debrief.</strong> ${escaped(scenario.debrief)}</div>` : ''}
    <nav class="stage-rail" aria-label="Scenario stages">
      ${scenario.stages.map((item, index) => `
        <button class="${index === state.stageIndex ? 'active' : ''} ${completed.includes(item.id) ? 'done' : ''}"
          data-action="scenario-stage" data-index="${index}"
          aria-current="${index === state.stageIndex ? 'step' : 'false'}">
          <span class="stage-num">${completed.includes(item.id) ? '✓' : index + 1}</span>
          ${escaped(item.title)}
        </button>`).join('')}
    </nav>
    <article class="stage-card">
      <div class="stage-kicker">Stage ${state.stageIndex + 1} of ${scenario.stages.length}</div>
      <h2 id="stage-title" tabindex="-1">${escaped(stage.title)}</h2>
      <p class="narrative">${escaped(stage.narrative)}</p>
      <p class="question">${escaped(stage.question)}</p>

      ${scenarioTools()}

      <div class="hints">
        ${hints.slice(0, shown).map((hint) => `<div class="hint">${escaped(hint)}</div>`).join('')}
        ${shown < hints.length
          ? `<button class="btn tiny ghost" data-action="scenario-hint">Show a hint (${shown}/${hints.length})</button>`
          : ''}
      </div>

      <form id="scenario-form">
        ${stageInputs(stage)}
        <div class="stage-actions">
          <button class="btn primary" type="submit">Submit answer</button>
          ${completed.includes(stage.id) ? '<span class="muted small">Already completed — resubmitting is practice.</span>' : ''}
        </div>
      </form>

      ${feedbackMarkup()}
    </article>

    <div class="detail-actions">
      <button class="btn ghost" data-action="refresh-scenarios">Refresh readiness</button>
      <button class="btn danger" data-action="scenario-reset">Reset progress</button>
    </div>`;
}

function scenarioTools() {
  return `<div class="scenario-tools">
    <div>
      <strong>Write your own query.</strong>
      <span class="muted small">Start from the lab index and this host, or investigate in Splunk Web.</span>
    </div>
    <span class="chips">
      <button class="btn tiny primary" data-action="scenario-new-search">New search</button>
      <button class="btn tiny ghost" data-action="scenario-open-splunk">Open Splunk ↗</button>
    </span>
  </div>`;
}

function stageInputs(stage) {
  const inputs = stage.inputs || [];
  let html = '';
  if (stage.answer?.type === 'choice') {
    html += `<fieldset class="choices">
      <legend>Choose one</legend>
      ${stage.answer.options.map((option, index) => `
        <label class="choice">
          <input type="radio" name="answer" value="${index}" required>
          <span>${escaped(option)}</span>
        </label>`).join('')}
    </fieldset>`;
  } else if (stage.answer?.type === 'answer') {
    html += `<label class="field">
      <span>Your answer</span>
      <input name="answer" type="text" autocomplete="off" spellcheck="false" required>
    </label>`;
  }
  if (inputs.includes('spl')) {
    html += `<label class="field">
      <span>Your SPL (run against the lab index)</span>
      <textarea name="spl" rows="5" spellcheck="false" required placeholder="index=attack_data host=&quot;...&quot; | stats count"></textarea>
    </label>`;
  }
  if (inputs.includes('review')) {
    html += `<label class="field">
      <span>Your reasoning (saved for the debrief, not auto-graded)</span>
      <textarea name="review" rows="4"></textarea>
    </label>`;
  }
  return html || '<p class="muted">This stage has no input.</p>';
}

function feedbackMarkup() {
  const result = state.lastCheck;
  if (!result) return '';
  const results = (result.results || []).map((item) => `
    <li class="${item.passed ? 'ok' : 'bad'}">
      <span>${item.passed ? '✓' : '✗'}</span>${escaped(item.message)}
    </li>`).join('');
  return `<div class="feedback ${result.passed ? 'ok' : 'bad'}" tabindex="-1" aria-live="polite">
    <div class="feedback-head">${result.passed ? 'Stage passed' : 'Not yet'}</div>
    <ul>${results}</ul>
    ${result.passed && result.debrief ? `<div class="stage-debrief"><strong>Debrief.</strong> ${escaped(result.debrief)}</div>` : ''}
    ${result.passed && result.scenario_debrief ? `<div class="stage-debrief scenario-debrief"><strong>Scenario complete.</strong> ${escaped(result.scenario_debrief)}</div>` : ''}
    ${result.passed && result.next ? '<button class="btn primary" data-action="scenario-next">Next stage</button>' : ''}
    ${result.passed && !result.next && !result.scenario_debrief ? '<button class="btn" data-action="refresh-scenarios">Finish remaining stages, then reload</button>' : ''}
  </div>`;
}

async function submitScenarioStage() {
  const scenario = state.scenarioDoc;
  const stage = scenario?.stages[state.stageIndex];
  if (!stage) return;
  const form = $('#scenario-form');
  const payload = { scenario_id: scenario.id, stage_id: stage.id };
  const answerInput = form?.querySelector('input[name="answer"]');
  if (answerInput?.type === 'radio') {
    const checked = form.querySelector('input[name="answer"]:checked');
    if (checked) payload.answer = checked.value;
  } else if (answerInput) {
    payload.answer = answerInput.value;
  }
  const spl = form?.querySelector('[name="spl"]');
  if (spl) payload.spl = spl.value;
  const review = form?.querySelector('[name="review"]');
  if (review) payload.review = review.value;
  if (!payload.answer && !payload.spl && !payload.review) {
    toast('Answer the question first.', true);
    return;
  }
  const button = form?.querySelector('button[type="submit"]');
  if (button) {
    button.disabled = true;
    button.textContent = 'Checking…';
  }
  try {
    state.lastCheck = await api('/api/scenario/check', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    if (state.lastCheck.passed) {
      const completed = new Set(scenario.progress.completed || []);
      completed.add(stage.id);
      scenario.progress.completed = Array.from(completed);
      loadScenarios();
    }
  } catch (error) {
    state.lastCheck = null;
    toast(error.message, true);
  }
  renderScenarioDetail();
  const feedback = $('.feedback');
  if (feedback) feedback.focus();
}

function moveScenarioStage(index) {
  const stages = state.scenarioDoc?.stages || [];
  state.stageIndex = Math.max(0, Math.min(index, stages.length - 1));
  state.lastCheck = null;
  renderScenarioDetail();
  $('#stage-title')?.focus();
}

async function loadScenarioFile(event) {
  const input = event.target;
  const file = input.files && input.files[0];
  input.value = '';
  if (!file) return;
  if (!/\.json$/i.test(file.name)) {
    toast('Choose a .json scenario file.', true);
    return;
  }
  let scenario;
  try {
    scenario = JSON.parse(await file.text());
  } catch {
    toast('That file is not valid JSON.', true);
    return;
  }
  try {
    const result = await api('/api/scenario/load', {
      method: 'POST',
      body: JSON.stringify({ filename: file.name, scenario }),
    });
    toast(`Loaded ${result.filename}.`);
    await loadScenarios();
    await openScenario(result.id);
  } catch (error) {
    toast(error.message, true);
  }
}

async function startScenarioSetup() {
  if (!state.scenarioId) return;
  const button = document.querySelector('[data-action="scenario-setup"]');
  if (button) {
    button.disabled = true;
    button.textContent = 'Setting up…';
  }
  try {
    await api('/api/scenario/setup', {
      method: 'POST',
      body: JSON.stringify({ scenario_id: state.scenarioId }),
    });
    wasRunning = true;
    openDrawer();
    pollJobs();
  } catch (error) {
    if (button) {
      button.disabled = false;
      button.textContent = 'Set up scenario';
    }
    toast(error.message, true);
  }
}

async function resetScenario() {
  if (!state.scenarioId) return;
  const ok = confirm('Reset progress for this scenario?\n\nCompleted stages and saved explanations will be deleted.');
  if (!ok) return;
  try {
    await api('/api/scenario/reset', {
      method: 'POST',
      body: JSON.stringify({ scenario_id: state.scenarioId }),
    });
  } catch (error) {
    toast(error.message, true);
    return;
  }
  state.lastCheck = null;
  state.hintCount = {};
  await openScenario(state.scenarioId);
  await loadScenarios();
}

async function refreshScenario() {
  await loadScenarios();
  if (state.scenarioId) await openScenario(state.scenarioId, true);
}

function currentScenarioStage() {
  return state.scenarioDoc?.stages[state.stageIndex] || null;
}

function scenarioBaseQuery() {
  const index = state.status?.index || 'attack_data';
  const host = state.scenarioPreflight?.host || '';
  return host ? `index=${index} host="${host}"\n` : `index=${index}\n`;
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
  showSearchContext(recipe);
  runSearch();
}

function showSearchContext(recipe) {
  const box = $('#search-context');
  if (!recipe) {
    box.classList.add('hidden');
    box.innerHTML = '';
    return;
  }
  const techniques = (recipe.techniques || [])
    .map(techniqueBadge)
    .join('');
  box.innerHTML = `
    <div class="search-context-head">
      <div>
        <strong>${escaped(recipe.title)}</strong>
        ${techniques}
        ${recipe.phase ? `<span class="badge blue">${escaped(recipe.phase)}</span>` : ''}
      </div>
      <button class="icon-btn" data-action="close-search-context" aria-label="Close description">×</button>
    </div>
    <p>${escaped(recipe.why || 'Suggested hunt.')}</p>`;
  box.classList.remove('hidden');
}

function hideSearchContext() {
  $('#search-context').classList.add('hidden');
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
  await loadScenarios();
  if (state.scenarioId) await openScenario(state.scenarioId, true);
  if (!state.status?.repo?.ready) {
    state.selected = null;
    state.selectedDetail = null;
    renderDetailEmpty();
    return;
  }
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
  const label = state.selectedDetail?.path === path
    ? state.selectedDetail.label
    : (state.scenarioDoc?.dataset.path === path ? state.scenarioDoc.title : path);
  const ok = confirm(
    `Replay "${label}" into Splunk index ${state.status?.index || 'attack_data'}?\n\n` +
    'Replaying the same dataset twice duplicates events.'
  );
  if (!ok) return;
  openDrawer();
  await startJob('replay', path);
}

function confirmTypedDelete(message) {
  const answer = prompt(`${message}\n\nType DELETE to confirm.`);
  return (answer || '').trim().toUpperCase() === 'DELETE';
}

async function deleteReplayDataset(path) {
  const label = state.selectedDetail?.label || path;
  const ok = confirm(
    `Delete all replayed events for "${label}" from index ${state.status?.index || 'attack_data'}?\n\n` +
    'This removes them from searches and cannot be undone.'
  );
  if (!ok) return;
  openDrawer();
  await startJob('dataset/delete-replay', path);
}

async function deleteDownloadedFiles(path) {
  const label = state.selectedDetail?.label || path;
  const count = (state.selectedDetail?.local_files || []).length;
  const ok = confirm(
    `Delete ${count} downloaded data file${count === 1 ? '' : 's'} in "${label}"?\n\n` +
    'The YAML metadata stays. You can download the folder again.'
  );
  if (!ok) return;
  openDrawer();
  await startJob('dataset/delete-download', path);
}

async function deleteAllReplayedEvents() {
  const events = fmt.format(state.status?.data?.events || 0);
  if (!confirmTypedDelete(`Delete ALL ${events} replayed events from index ${state.status?.index || 'attack_data'}?`)) return;
  openDrawer();
  await startJob('lab/delete-replay');
}

async function removeAttackData() {
  if (!confirmTypedDelete('Remove the local attack_data checkout, including every downloaded dataset?')) return;
  openDrawer();
  await startJob('repo/remove');
}

async function uninstallFields() {
  if (!confirmTypedDelete('Remove the SOC Lab Windows field extraction from Splunk?')) return;
  openDrawer();
  await startJob('uninstall-fields');
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
    case 'close-search-context': hideSearchContext(); break;
    case 'open-drawer': openDrawer(); break;
    case 'close-drawer': closeDrawer(); break;
    case 'search-host': {
      hideSearchContext();
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
    case 'delete-replay': deleteReplayDataset(element.dataset.path); break;
    case 'delete-download': deleteDownloadedFiles(element.dataset.path); break;
    case 'delete-all-replay': deleteAllReplayedEvents(); break;
    case 'remove-repo': removeAttackData(); break;
    case 'uninstall-fields': uninstallFields(); break;
    case 'quick-recipe': {
      const recipe = findRecipe(element.dataset.recipe);
      if (recipe) loadRecipeIntoSearch(recipe);
      break;
    }
    case 'scenario-open': openScenario(element.dataset.id); break;
    case 'scenario-load': $('#scenario-file').click(); break;
    case 'scenario-setup': startScenarioSetup(); break;
    case 'scenario-stage': moveScenarioStage(Number(element.dataset.index)); break;
    case 'scenario-next': moveScenarioStage(state.stageIndex + 1); break;
    case 'scenario-hint': {
      const stage = currentScenarioStage();
      if (stage) {
        state.hintCount[stage.id] = (state.hintCount[stage.id] || 0) + 1;
        renderScenarioDetail();
      }
      break;
    }
    case 'scenario-new-search': {
      showTab('search');
      hideSearchContext();
      $('#spl').value = scenarioBaseQuery();
      $('#search-range').value = 'all';
      $('#spl').focus();
      break;
    }
    case 'scenario-open-splunk': openInSplunk(scenarioBaseQuery(), 'all'); break;
    case 'scenario-reset': resetScenario(); break;
    case 'refresh-scenarios': refreshScenario(); break;
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

  $('#scenario-file').addEventListener('change', loadScenarioFile);

  document.addEventListener('submit', (event) => {
    if (event.target.id === 'scenario-form') {
      event.preventDefault();
      submitScenarioStage();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeDrawer();
  });
}

async function init() {
  bindEvents();
  await loadStatus();
  await Promise.all([loadDatasets(), loadRecipes(), loadScenarios()]);
  pollJobs();
}

document.addEventListener('DOMContentLoaded', init);
