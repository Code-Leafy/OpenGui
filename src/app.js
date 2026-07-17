    // --- Tauri Bridge ---
    // The frontend always talks to the real backend via the Tauri IPC bridge.
    // (The previous mock backend has been removed; the app requires the
    // OpenConnect GUI shell to run.)
    const backend = {
      invoke: (cmd, args) => window.__TAURI__.core.invoke(cmd, args),
      listen: (channel, handler) => window.__TAURI__.event.listen(channel, handler),
    };

    // --- App State ---
    let profiles = [];
    let activeProfileId = null;
    let currentState = 'Disconnected';
    let timerInterval = null;
    let pingInterval = null;
    let connectionStartTime = null;
    let settings = null; // global settings from backend
    let userRequestedDisconnect = false;
    let pendingCertProfileId = null;
    let totalDl = 0;
    let totalUl = 0;
    let retryAttempts = 0;
    const MAX_RETRY_ATTEMPTS = 6;
    let pendingRetryTimeout = null;
    let statsInterval = null;

    const POLL_MS = 1000;

    function formatBytes(mb) {
      return mb > 1024 ? (mb / 1024).toFixed(2) + ' GB' : Math.floor(mb) + ' MB';
    }

    function formatSpeed(mbPerSec) {
      return mbPerSec.toFixed(2) + ' MB/s';
    }

    // --- DOM Elements ---
    const profileList = document.getElementById('profile-list');
    const largeFlag = document.getElementById('large-flag');
    const currentServerTitle = document.getElementById('current-server-title');
    const currentServerSubtitle = document.getElementById('current-server-subtitle');
    const connectTarget = document.getElementById('connect-target');
    const pulseCore = document.getElementById('pulse-core');

    const statStatus = document.getElementById('stat-status');
    const statusIndicator = document.getElementById('status-indicator');
    const statIp = document.getElementById('stat-ip');
    const statTimer = document.getElementById('stat-timer');
    const statPing = document.getElementById('stat-ping');

    const navProfiles = document.getElementById('nav-profiles');
    const navLogs = document.getElementById('nav-logs');
    const navStats = document.getElementById('nav-stats');
    const logsContainer = document.getElementById('logs-container');
    const sidebarLogsEl = document.getElementById('sidebar-logs');
    const sidebarStatsEl = document.getElementById('sidebar-stats');

    const modal = document.getElementById('add-profile-modal');
    const btnAddProfile = document.getElementById('btn-add-profile');

    // Set when the profile modal is opened for editing an existing profile;
    // null means the modal is in "add" mode. Assigned inside the modal setup.
    let editingProfileId = null;
    let editProfile = () => {};

    const mfaModal = document.getElementById('mfa-modal');
    const certModal = document.getElementById('cert-modal');
    const settingsModal = document.getElementById('settings-modal');

    const UNKNOWN_FLAG = 'xx';

    function flagCode(p) {
      const cc = (p && p.country_code ? String(p.country_code) : '').trim().toLowerCase();
      if (cc.length === 2 && /^[a-z]{2}$/.test(cc)) return cc;
      return UNKNOWN_FLAG;
    }

    function flagUrl(code, ratio) {
      const r = ratio === '1x1' ? '1x1' : '4x3';
      return `flags/${r}/${(code || UNKNOWN_FLAG)}.svg`;
    }

    function flagForProfile(p) {
      return flagUrl(flagCode(p), '4x3');
    }

    function attachFlagFallback(img) {
      if (!img) return;
      img.addEventListener('error', function onFlagError() {
        img.removeEventListener('error', onFlagError);
        img.src = flagUrl(UNKNOWN_FLAG, '4x3');
      });
    }

    function setFlagSrc(img, src) {
      if (!img) return;
      attachFlagFallback(img);
      img.src = src;
    }

    const PROTOCOL_LABELS = {
      anyconnect: 'AnyConnect',
      nc: 'Juniper Network Connect',
      gp: 'GlobalProtect',
      pulse: 'Pulse Connect Secure',
      f5: 'F5 BIG-IP',
      fortinet: 'FortiGate',
      array: 'Array Networks',
    };

    function protocolLabel(p) {
      const key = (p && p.protocol ? String(p.protocol) : '').trim().toLowerCase();
      return PROTOCOL_LABELS[key] || 'AnyConnect';
    }

    // --- Initialization ---
    async function init() {
      setupEvents();

      await backend.listen('openconnect://state', (event) => {
        const previousState = getSimpleState();
        currentState = event.payload;
        const newState = getSimpleState();
        renderState();

        if (newState === 'Connected') {
          retryAttempts = 0;
          if (pendingRetryTimeout) {
            clearTimeout(pendingRetryTimeout);
            pendingRetryTimeout = null;
          }
        }

        if (!userRequestedDisconnect &&
            (newState === 'Failed' || (newState === 'Disconnected' && previousState !== 'Disconnected'))) {
          if (settings && settings.auto_retry_enabled && activeProfileId) {
            if (pendingRetryTimeout) {
              clearTimeout(pendingRetryTimeout);
              pendingRetryTimeout = null;
            }
            if (retryAttempts < MAX_RETRY_ATTEMPTS) {
              retryAttempts++;
              const base = 3000 * Math.pow(2, retryAttempts - 1);
              const delay = Math.min(base, 60000);
              const jitter = Math.floor(Math.random() * 1000);
              const wait = delay + jitter;
              addLog(Date.now(), 'INFO', `Connection dropped. Auto-retry ${retryAttempts}/${MAX_RETRY_ATTEMPTS} in ${Math.round(wait / 1000)}s...`);
              pendingRetryTimeout = setTimeout(async () => {
                pendingRetryTimeout = null;
                if (getSimpleState() !== 'Connected' && getSimpleState() !== 'Connecting') {
                  userRequestedDisconnect = false;
                  try {
                    await backend.invoke('connect', { profileId: activeProfileId });
                  } catch (err) {
                    addLog(Date.now(), 'ERROR', 'Auto-retry connect failed: ' + String(err));
                  }
                }
              }, wait);
            } else {
              addLog(Date.now(), 'ERROR', `Auto-retry giving up after ${MAX_RETRY_ATTEMPTS} attempts.`);
            }
          }
        }
      });

      await backend.listen('openconnect://events', (event) => {
        for (const { timestamp, level, message } of event.payload) {
          addLog(timestamp, level, message);
        }
      });
      await backend.listen('openconnect://server-cert', (event) => {
        pendingCertProfileId = activeProfileId;
        document.getElementById('cert-pin').textContent = event.payload;
        certModal.classList.add('active');
        const f = certModal.querySelector('input, button, select, [tabindex]:not([tabindex="-1"])');
        if (f) f.focus();
      });
      await backend.listen('openconnect://mfa-required', (event) => {
        const p = profiles.find((x) => x.id === event.payload);
        document.getElementById('mfa-profile-name').textContent = p ? p.name : 'VPN';
        mfaModal.classList.add('active');
        document.getElementById('mfa-code-input').focus();
      });
      await backend.listen('openconnect://tunnel-info', (event) => {
        // Tunnel is up; reflect the assigned IP in the stats panel.
        if (event.payload && event.payload.ip) {
          statIp.textContent = event.payload.ip;
        }
      });

      try {
        await backend.invoke('bridge_version');
      } catch (err) {
        console.error('bridge_version failed', err);
      }

      try {
        settings = await backend.invoke('get_settings');
      } catch (err) {
        console.error('get_settings failed', err);
        settings = null;
      }
      applySettingsToUI();

      profiles = await backend.invoke('list_profiles') || [];
      if (profiles.length > 0) activeProfileId = profiles[0].id;

      try {
        currentState = await backend.invoke('get_connection_state');
      } catch (err) {
        console.error('get_connection_state failed', err);
      }

      renderProfiles();
      renderState();

      maybeAutoConnect();
    }

    // Auto-connect to the last-used profile on launch, if enabled in Settings
    // and we are not already connected/connecting.
    function maybeAutoConnect() {
      if (!settings || !settings.auto_connect) return;
      const targetId = settings.last_profile_id || activeProfileId;
      if (!targetId) return;
      const prof = profiles.find((p) => p.id === targetId);
      if (!prof) return;
      const s = getSimpleState();
      if (s !== 'Disconnected' && s !== 'Failed') return;
      activeProfileId = targetId;
      renderProfiles();
      renderState();
      userRequestedDisconnect = false;
      addLog(Date.now(), 'INFO', 'Auto-connecting to ' + prof.name + '...');
      backend.invoke('connect', { profileId: targetId })
        .catch((err) => addLog(Date.now(), 'ERROR', 'Auto-connect failed: ' + String(err)));
    }

    function getSimpleState() {
      if (typeof currentState === 'string') return currentState;
      if (currentState && typeof currentState === 'object') {
        if (currentState.Failed) return 'Failed';
        const keys = Object.keys(currentState);
        if (keys.length > 0) return keys[0];
      }
      return 'Unknown';
    }

    function renderTimer() {
      if (connectionStartTime === null) {
        statTimer.textContent = '00:00:00';
        return;
      }
      const diff = Math.floor((Date.now() - connectionStartTime) / 1000);
      const h = String(Math.floor(diff / 3600)).padStart(2, '0');
      const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
      const s = String(diff % 60).padStart(2, '0');
      statTimer.textContent = `${h}:${m}:${s}`;
    }

    function startTimer() {
      if (timerInterval) return;
      connectionStartTime = Date.now();
      renderTimer();
      timerInterval = setInterval(() => {
        if (sidebarStatsEl.classList.contains('active')) renderTimer();
      }, 1000);
    }

    function stopTimer() {
      if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
      }
      connectionStartTime = null;
      statTimer.textContent = '00:00:00';
      totalDl = 0;
      totalUl = 0;
    }

    function startPing() {
      if (pingInterval) return;
      statPing.textContent = (Math.floor(Math.random() * 20) + 15) + 'ms';
      pingInterval = setInterval(() => {
        if (sidebarStatsEl.classList.contains('active')) {
          statPing.textContent = (Math.floor(Math.random() * 30) + 15) + 'ms';
        }
      }, 2000);
    }

    function stopPing() {
      if (pingInterval) {
        clearInterval(pingInterval);
        pingInterval = null;
      }
      statPing.textContent = '0ms';
    }

    function deleteProfile(id) {
      backend.invoke('delete_profile', { id }).then(() => {
        profiles = profiles.filter((p) => p.id !== id);
        if (activeProfileId === id) {
          activeProfileId = profiles.length > 0 ? profiles[0].id : null;
        }
        renderProfiles();
        renderState();
      }).catch((err) => {
        console.error('delete_profile failed', err);
        addLog(Date.now(), 'ERROR', 'Failed to delete profile: ' + String(err));
      });
    }

    function renderState() {
      const stateStr = getSimpleState();

      statStatus.textContent = stateStr;
      connectTarget.className = 'connect-target';
      statusIndicator.className = 'status-indicator';

      if (stateStr === 'Connected') {
        pulseCore.textContent = 'Disconnect';
        connectTarget.classList.add('connected');
        statusIndicator.classList.add('connected');
        statStatus.textContent = 'Protected';
        startTimer();
        startPing();
        if (sidebarStatsEl.classList.contains('active')) startStatsLoop();
      } else if (stateStr === 'Connecting') {
        pulseCore.textContent = 'Cancel';
        connectTarget.classList.add('connecting');
        statIp.textContent = '---';
        stopTimer();
        stopPing();
        stopStatsLoop();
      } else if (stateStr === 'Disconnecting') {
        pulseCore.textContent = 'Cancel';
        connectTarget.classList.add('disconnecting');
        statIp.textContent = '---';
        stopTimer();
        stopPing();
        stopStatsLoop();
      } else {
        pulseCore.textContent = 'Connect';
        statIp.textContent = '---';
        stopTimer();
        stopPing();
        stopStatsLoop();
      }

      if (activeProfileId) {
        const p = profiles.find((x) => x.id === activeProfileId);
        if (p) {
          currentServerTitle.textContent = p.name;
          currentServerSubtitle.textContent = p.server;
          setFlagSrc(largeFlag, flagForProfile(p));
        }
      } else {
        currentServerTitle.textContent = 'Select a Profile';
        currentServerSubtitle.textContent = 'No profile selected';
        setFlagSrc(largeFlag, flagUrl(UNKNOWN_FLAG, '4x3'));
      }
    }

    function renderProfiles() {
      profileList.innerHTML = '';

      profiles.forEach((p, idx) => {
        const el = document.createElement('div');
        el.className = `profile-card ${p.id === activeProfileId ? 'active' : ''}`;
        el.style.animationDelay = `${idx * 0.05}s`;

        const flagSrc = flagForProfile(p);
        el.innerHTML = `
          <div class="profile-icon"><img class="flag" src="${escapeHtml(flagSrc)}" alt=""></div>
          <div class="profile-info">
            <div class="profile-name">${escapeHtml(p.name)}</div>
            <div class="profile-meta">
              <span class="profile-server">${escapeHtml(safeHostname(p.server))}</span>
            </div>
            <div class="profile-protocol">${escapeHtml(protocolLabel(p))}</div>
          </div>
          <div class="profile-actions">
            <button class="btn-icon btn-edit-profile" data-id="${escapeHtml(p.id)}" title="Edit Profile" aria-label="Edit profile ${escapeHtml(p.name)}"><svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg></button>
            <button class="btn-icon btn-delete-profile" data-id="${escapeHtml(p.id)}" title="Delete Profile" aria-label="Delete profile ${escapeHtml(p.name)}"><svg viewBox="0 0 24 24"><path d="M3 6h18"></path><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg></button>
          </div>
        `;
        el.setAttribute('role', 'button');
        el.setAttribute('tabindex', '0');
        el.setAttribute('aria-label', 'Select profile ' + p.name);
        el.onclick = (e) => {
          if (e.target.closest('.btn-delete-profile')) {
            e.stopPropagation();
            deleteProfile(p.id);
            return;
          }
          if (e.target.closest('.btn-edit-profile')) {
            e.stopPropagation();
            editProfile(p.id);
            return;
          }
          if (getSimpleState() !== 'Disconnected' && getSimpleState() !== 'Failed') return;
          activeProfileId = p.id;
          document.querySelectorAll('.profile-card').forEach((card) => card.classList.remove('active'));
          el.classList.add('active');
          renderState();
        };
        el.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            el.click();
          }
        });
        attachFlagFallback(el.querySelector('img.flag'));
        profileList.appendChild(el);
      });
    }

    function safeHostname(server) {
      try {
        return new URL(server).hostname;
      } catch (_) {
        return server;
      }
    }

    function escapeHtml(str) {
      return String(str == null ? '' : str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    const MAX_LOG_LINES = 1000;

    function addLog(ts, level, msg) {
      const time = new Date(ts).toLocaleTimeString([], { hour12: false });
      const el = document.createElement('div');
      el.className = 'log-line';
      const levelClass = level === 'ERROR' ? 'log-error' : 'log-info';
      el.innerHTML = `<span class="log-time">[${time}]</span><span class="${levelClass}">[${level}]</span> ${escapeHtml(msg)}`;
      logsContainer.appendChild(el);
      while (logsContainer.childElementCount > MAX_LOG_LINES) {
        logsContainer.removeChild(logsContainer.firstChild);
      }
      logsContainer.scrollTop = logsContainer.scrollHeight;
    }

    function applySettingsToUI() {
      if (!settings) return;
      setToolActive('btn-netshield', settings.netshield_enabled);
      setToolActive('btn-killswitch', settings.killswitch_enabled);
      setToolActive('btn-autoretry', settings.auto_retry_enabled);

      document.getElementById('ns-block-malware').checked = !!(settings.netshield && settings.netshield.block_malware);
      document.getElementById('ns-secure-connection').checked = !!(settings.netshield && settings.netshield.secure_connection);
      document.getElementById('ns-block-ads').checked = !!(settings.netshield && settings.netshield.block_ads);

      const nsState = (settings.netshield) || {};
      const nsFlyMap = {
        'ns-block-malware': !!nsState.block_malware,
        'ns-secure-connection': !!nsState.secure_connection,
        'ns-block-ads': !!nsState.block_ads,
      };
      document.querySelectorAll('.ns-fly-item').forEach((item) => {
        item.classList.toggle('on', !!nsFlyMap[item.dataset.target]);
      });

      document.getElementById('set-auto-connect').checked = !!settings.auto_connect;
      document.getElementById('set-default-protocol').value = settings.default_protocol || 'OpenConnect';
    }

    function setToolActive(id, active) {
      const el = document.getElementById(id);
      if (el) el.classList.toggle('active', !!active);
    }

    // --- Stats chart loop (visual only; real throughput not yet streamed) ---
    // Top-level scope so both renderState() and setupEvents() can use them.
    let dlHistory = Array(20).fill(0);
    let ulHistory = Array(20).fill(0);
    let pingHistory = Array(20).fill(0);

    const statsEl = {
      dlSpeed: document.getElementById('stats-dl-speed'),
      ulSpeed: document.getElementById('stats-ul-speed'),
      dlTotal: document.getElementById('stats-dl-total'),
      ulTotal: document.getElementById('stats-ul-total'),
      pingCurrent: document.getElementById('stats-ping-current'),
      chartDl: document.getElementById('chart-dl-line'),
      chartUl: document.getElementById('chart-ul-line'),
      chartPing: document.getElementById('chart-ping-line'),
    };

    function updateChart() {
      const maxVal = Math.max(...dlHistory, ...ulHistory, 1);
      const maxPingVal = Math.max(...pingHistory, 1) * 1.2;
      const w = 200, h = 80, pingH = 72;
      const getPoints = (data, max, customH) => {
        const height = customH || h;
        return data.map((val, i) => {
          const x = (i / (data.length - 1)) * w;
          const y = height - ((val / max) * height * 0.9);
          return `${x},${y}`;
        }).join(' ');
      };
      statsEl.chartDl.setAttribute('points', getPoints(dlHistory, maxVal));
      statsEl.chartUl.setAttribute('points', getPoints(ulHistory, maxVal));
      if (statsEl.chartPing) statsEl.chartPing.setAttribute('points', getPoints(pingHistory, maxPingVal, pingH));
    }

    function zeroStats() {
      statsEl.dlSpeed.textContent = '0.00 KB/s';
      statsEl.ulSpeed.textContent = '0.00 KB/s';
      statsEl.dlTotal.textContent = '0 MB';
      statsEl.ulTotal.textContent = '0 MB';
      if (statsEl.pingCurrent) statsEl.pingCurrent.textContent = '0';
    }

    function startStatsLoop() {
      if (statsInterval || getSimpleState() !== 'Connected') return;
      statsInterval = setInterval(() => {
        const dlSpeed = Math.random() * 5 + 0.5;
        const ulSpeed = Math.random() * 1.5 + 0.1;
        totalDl += dlSpeed;
        totalUl += ulSpeed;
        const pingVal = Math.floor(Math.random() * 30 + 20);

        statsEl.dlSpeed.textContent = formatSpeed(dlSpeed);
        statsEl.ulSpeed.textContent = formatSpeed(ulSpeed);
        statsEl.dlTotal.textContent = formatBytes(totalDl);
        statsEl.ulTotal.textContent = formatBytes(totalUl);
        if (statsEl.pingCurrent) statsEl.pingCurrent.textContent = pingVal;

        dlHistory.push(dlSpeed); ulHistory.push(ulSpeed); pingHistory.push(pingVal);
        dlHistory.shift(); ulHistory.shift(); pingHistory.shift();
        updateChart();
      }, POLL_MS);
    }

    function stopStatsLoop() {
      if (statsInterval) {
        clearInterval(statsInterval);
        statsInterval = null;
      }
      if (getSimpleState() !== 'Connected') zeroStats();
    }

    function setupEvents() {
      let connectInFlight = false;
      const handleConnectionToggle = async () => {
        if (connectInFlight) return;
        connectInFlight = true;
        try {
          const s = getSimpleState();
          if (s === 'Disconnected' || s === 'Failed') {
            if (!activeProfileId) return;
            userRequestedDisconnect = false;
            if (pendingRetryTimeout) {
              clearTimeout(pendingRetryTimeout);
              pendingRetryTimeout = null;
            }
            retryAttempts = 0;
            try {
              await backend.invoke('connect', { profileId: activeProfileId });
            } catch (err) {
              addLog(Date.now(), 'ERROR', 'Connect failed: ' + String(err));
            }
          } else if (s === 'Connected' || s === 'Connecting') {
            userRequestedDisconnect = true;
            if (pendingRetryTimeout) {
              clearTimeout(pendingRetryTimeout);
              pendingRetryTimeout = null;
            }
            retryAttempts = 0;
            try {
              await backend.invoke('disconnect');
            } catch (err) {
              addLog(Date.now(), 'ERROR', 'Disconnect failed: ' + String(err));
            }
          }
        } finally {
          connectInFlight = false;
        }
      };

      connectTarget.onclick = handleConnectionToggle;
      connectTarget.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleConnectionToggle();
        }
      });

      // --- Modal accessibility: focus first control on open, Escape closes ---
      const closeHandlers = {
        'add-profile-modal': () => modal.classList.remove('active'),
        'settings-modal': () => settingsModal.classList.remove('active'),
        'mfa-modal': () => mfaModal.classList.remove('active'),
        'cert-modal': () => certModal.classList.remove('active'),
      };

      function openModal(overlay) {
        overlay.classList.add('active');
        const focusable = overlay.querySelector('input, button, select, [tabindex]:not([tabindex="-1"])');
        if (focusable) focusable.focus();
      }

      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          const open = document.querySelector('.modal-overlay.active');
          if (open && closeHandlers[open.id]) {
            e.preventDefault();
            closeHandlers[open.id]();
          }
        }
      });

      const showProfiles = () => {
        navProfiles.classList.add('active');
        navLogs.classList.remove('active');
        navStats.classList.remove('active');
        profileList.classList.add('active');
        sidebarLogsEl.classList.remove('active');
        sidebarStatsEl.classList.remove('active');
        stopStatsLoop();
        btnAddProfile.style.display = 'flex';
      };
      const showLogs = () => {
        navLogs.classList.add('active');
        navProfiles.classList.remove('active');
        navStats.classList.remove('active');
        sidebarLogsEl.classList.add('active');
        profileList.classList.remove('active');
        sidebarStatsEl.classList.remove('active');
        stopStatsLoop();
        btnAddProfile.style.display = 'none';
      };
      const showStats = () => {
        navStats.classList.add('active');
        navProfiles.classList.remove('active');
        navLogs.classList.remove('active');
        sidebarStatsEl.classList.add('active');
        profileList.classList.remove('active');
        sidebarLogsEl.classList.remove('active');
        btnAddProfile.style.display = 'none';
        if (getSimpleState() === 'Connected') startStatsLoop();
        else zeroStats();
      };
      navProfiles.onclick = showProfiles;
      navLogs.onclick = showLogs;
      navStats.onclick = showStats;
      [navProfiles, navLogs, navStats].forEach((tab) => {
        tab.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            tab.click();
          }
        });
      });

      // --- Profile modal ---
      // Auto-detected ISO country for the profile being edited (null = unknown).
      let detectedCountry = null;
      let detectSeq = 0;
      const flagPreviewImg = document.getElementById('flag-preview-img');
      const flagPreviewName = document.getElementById('flag-preview-name');
      const advancedColumn = document.getElementById('advanced-column');
      const btnToggleAdvanced = document.getElementById('btn-toggle-advanced');
      const modalOuter = document.getElementById('add-profile-modal');

      const regionNames = (typeof Intl !== 'undefined' && Intl.DisplayNames)
        ? new Intl.DisplayNames(['en'], { type: 'region' })
        : null;
      const countryName = (cc) => {
        if (!cc) return 'Unknown';
        try { return (regionNames && regionNames.of(cc.toUpperCase())) || cc.toUpperCase(); }
        catch (_) { return cc.toUpperCase(); }
      };

      const setFlagPreview = (cc) => {
        const code = (cc && /^[a-z]{2}$/i.test(cc)) ? cc.toLowerCase() : UNKNOWN_FLAG;
        setFlagSrc(flagPreviewImg, flagUrl(code, '4x3'));
        flagPreviewName.textContent = code === UNKNOWN_FLAG ? 'Unknown' : countryName(code);
      };

      // Resolve the server's country via the backend GeoIP command.
      const detectServerCountry = async () => {
        let server = document.getElementById('input-server').value.trim();
        if (!server) { detectedCountry = null; setFlagPreview(null); return; }
        if (!server.startsWith('http')) server = 'https://' + server;
        const seq = ++detectSeq;
        try {
          const cc = await backend.invoke('detect_country', { server });
          if (seq !== detectSeq) return;
          if (cc && /^[a-z]{2}$/i.test(cc)) {
            detectedCountry = cc.toLowerCase();
            setFlagPreview(detectedCountry);
          } else {
            detectedCountry = null;
            setFlagPreview(null);
          }
        } catch (err) {
          if (seq !== detectSeq) return;
          detectedCountry = null;
          setFlagPreview(null);
        }
      };

      let advancedVisible = false;
      const setAdvancedVisible = (show) => {
        advancedVisible = show;
        advancedColumn.style.display = show ? 'flex' : 'none';
        modalOuter.classList.toggle('wide', show);
        btnToggleAdvanced.textContent = show ? 'Hide Advanced options ‹' : 'Show Advanced options ›';
      };
      btnToggleAdvanced.onclick = () => setAdvancedVisible(!advancedVisible);

      // --- Profile-form validation helpers ---
      const FIELD_IDS = ['name', 'server', 'username', 'password'];
      const setFieldError = (field, message) => {
        const wrap = document.getElementById('input-' + field).closest('.input-modern');
        const err = document.getElementById('err-' + field);
        if (message) {
          wrap.classList.add('invalid');
          err.textContent = message;
        } else {
          wrap.classList.remove('invalid');
          err.textContent = '';
        }
      };
      const clearAllFieldErrors = () => FIELD_IDS.forEach((f) => setFieldError(f, ''));

      const validateProfileForm = () => {
        clearAllFieldErrors();
        let ok = true;
        let firstBad = null;
        const name = document.getElementById('input-name').value.trim();
        const server = document.getElementById('input-server').value.trim();
        const username = document.getElementById('input-username').value.trim();

        if (!name) {
          setFieldError('name', 'Profile name is required.');
          ok = false; firstBad = firstBad || 'name';
        } else if (name.length > 64) {
          setFieldError('name', 'Name must be 64 characters or fewer.');
          ok = false; firstBad = firstBad || 'name';
        }

        if (!server) {
          setFieldError('server', 'Server address is required.');
          ok = false; firstBad = firstBad || 'server';
        } else {
          const normalized = server.startsWith('http') ? server : 'https://' + server;
          let host = '';
          try { host = new URL(normalized).hostname; } catch (_) { host = ''; }
          if (!host || !host.includes('.')) {
            setFieldError('server', 'Enter a valid server URL (e.g. https://vpn.example.com).');
            ok = false; firstBad = firstBad || 'server';
          }
        }

        if (!username) {
          setFieldError('username', 'Username is required.');
          ok = false; firstBad = firstBad || 'username';
        }

        if (firstBad) {
          const el = document.getElementById('input-' + firstBad);
          if (el) el.focus();
        }
        return ok;
      };

      // Clear a field's error as soon as the user starts fixing it.
      FIELD_IDS.forEach((f) => {
        const el = document.getElementById('input-' + f);
        if (el) el.addEventListener('input', () => setFieldError(f, ''));
      });

      // Advanced (OpenConnect) option field ids -> profile key + kind.
      // kind: 'str' (trimmed string), 'num' (integer), 'bool' (checkbox).
      const ADV_FIELDS = [
        ['adv-protocol', 'protocol', 'str'],
        ['adv-authgroup', 'authgroup', 'str'],
        ['adv-usergroup', 'usergroup', 'str'],
        ['adv-certificate', 'certificate', 'str'],
        ['adv-sslkey', 'sslkey', 'str'],
        ['adv-key-password', 'key_password', 'str'],
        ['adv-token-mode', 'token_mode', 'str'],
        ['adv-token-secret', 'token_secret', 'str'],
        ['adv-external-browser', 'external_browser', 'str'],
        ['adv-no-external-auth', 'no_external_auth', 'bool'],
        ['adv-proxy', 'proxy', 'str'],
        ['adv-proxy-auth', 'proxy_auth', 'str'],
        ['adv-no-proxy', 'no_proxy', 'bool'],
        ['adv-resolve', 'resolve', 'str'],
        ['adv-sni', 'sni', 'str'],
        ['adv-cafile', 'cafile', 'str'],
        ['adv-no-system-trust', 'no_system_trust', 'bool'],
        ['adv-allow-insecure-crypto', 'allow_insecure_crypto', 'bool'],
        ['adv-dtls-ciphers', 'dtls_ciphers', 'str'],
        ['adv-base-mtu', 'base_mtu', 'num'],
        ['adv-dtls-local-port', 'dtls_local_port', 'num'],
        ['adv-force-dpd', 'force_dpd', 'num'],
        ['adv-queue-len', 'queue_len', 'num'],
        ['adv-no-dtls', 'no_dtls', 'bool'],
        ['adv-pfs', 'pfs', 'bool'],
        ['adv-passtos', 'passtos', 'bool'],
        ['adv-disable-ipv6', 'disable_ipv6', 'bool'],
        ['adv-deflate', 'deflate', 'bool'],
        ['adv-os-override', 'os_override', 'str'],
        ['adv-useragent', 'useragent', 'str'],
        ['adv-version-string', 'version_string', 'str'],
        ['adv-local-hostname', 'local_hostname', 'str'],
      ];

      // Reset every advanced control to its empty/default state.
      const resetAdvancedFields = () => {
        ADV_FIELDS.forEach(([id, , kind]) => {
          const el = document.getElementById(id);
          if (!el) return;
          if (kind === 'bool') el.checked = false;
          else el.value = '';
        });
        const errEl = document.getElementById('err-advanced');
        if (errEl) errEl.textContent = '';
        setAdvancedVisible(false);
      };

      // Merge advanced controls into the given profile object. Only non-empty /
      // checked values are attached so the backend keeps them as None otherwise.
      const applyAdvancedFields = (profile) => {
        ADV_FIELDS.forEach(([id, key, kind]) => {
          const el = document.getElementById(id);
          if (!el) return;
          if (kind === 'bool') {
            if (el.checked) profile[key] = true;
          } else if (kind === 'num') {
            const v = el.value.trim();
            if (v !== '') {
              const n = parseInt(v, 10);
              if (!Number.isNaN(n)) profile[key] = n;
            }
          } else {
            const v = el.value.trim();
            if (v !== '') profile[key] = v;
          }
        });
      };

      // Populate the advanced controls from an existing profile (reverse of
      // applyAdvancedFields). Missing keys leave the control at its default.
      const fillAdvancedFields = (profile) => {
        let anySet = false;
        ADV_FIELDS.forEach(([id, key, kind]) => {
          const el = document.getElementById(id);
          if (!el) return;
          const v = profile[key];
          if (kind === 'bool') {
            el.checked = v === true;
            if (el.checked) anySet = true;
          } else if (v !== undefined && v !== null && v !== '') {
            el.value = String(v);
            anySet = true;
          }
        });
        return anySet;
      };

      const modalHeading = document.getElementById('modal-heading');
      const passwordInput = document.getElementById('input-password');

      btnAddProfile.onclick = () => {
        editingProfileId = null;
        modalHeading.textContent = 'New Connection Profile';
        btnSaveModal.textContent = 'Save Profile';
        passwordInput.placeholder = 'Password';
        document.getElementById('input-name').value = '';
        document.getElementById('input-server').value = '';
        document.getElementById('input-username').value = '';
        passwordInput.value = '';
        clearAllFieldErrors();
        resetAdvancedFields();
        detectedCountry = null;
        detectSeq++;
        setFlagPreview(null);
        openModal(modal);
      };

      // Open the profile modal pre-filled with an existing profile for editing.
      editProfile = (id) => {
        const prof = profiles.find((p) => p.id === id);
        if (!prof) return;
        editingProfileId = id;
        modalHeading.textContent = 'Edit Connection Profile';
        btnSaveModal.textContent = 'Update Profile';
        passwordInput.placeholder = 'Password (leave blank to keep current)';
        document.getElementById('input-name').value = prof.name || '';
        document.getElementById('input-server').value = prof.server || '';
        document.getElementById('input-username').value = prof.username || '';
        passwordInput.value = '';
        clearAllFieldErrors();
        resetAdvancedFields();
        const anyAdv = fillAdvancedFields(prof);
        if (anyAdv) setAdvancedVisible(true);
        detectedCountry = (prof.country_code && /^[a-z]{2}$/i.test(prof.country_code))
          ? prof.country_code.toLowerCase() : null;
        detectSeq++;
        setFlagPreview(detectedCountry);
        openModal(modal);
      };

      // Re-detect the country when the user finishes editing the server field,
      // and (debounced) while they type so the flag updates without needing blur.
      let detectDebounce = null;
      const serverInput = document.getElementById('input-server');
      serverInput.addEventListener('blur', () => {
        if (detectDebounce) { clearTimeout(detectDebounce); detectDebounce = null; }
        detectServerCountry();
      });
      serverInput.addEventListener('input', () => {
        if (detectDebounce) clearTimeout(detectDebounce);
        detectedCountry = null;
        detectDebounce = setTimeout(() => { detectDebounce = null; detectServerCountry(); }, 700);
      });

      document.getElementById('btn-cancel-modal').onclick = () => { editingProfileId = null; modal.classList.remove('active'); };

      const btnSaveModal = document.getElementById('btn-save-modal');
      btnSaveModal.onclick = async () => {
        if (btnSaveModal.disabled) return;
        if (!validateProfileForm()) return;

        const name = document.getElementById('input-name').value.trim();
        let server = document.getElementById('input-server').value.trim();
        const username = document.getElementById('input-username').value.trim();
        const password = document.getElementById('input-password').value;

        if (!server.startsWith('http')) server = 'https://' + server;

        // Always attempt a fresh country detection at save time so the stored
        // profile gets an accurate flag whenever the server actually resolves.
        if (detectDebounce) { clearTimeout(detectDebounce); detectDebounce = null; }
        await detectServerCountry();

        const isEdit = !!editingProfileId;
        const existing = isEdit ? profiles.find((p) => p.id === editingProfileId) : null;
        const id = isEdit
          ? editingProfileId
          : ((crypto.randomUUID && crypto.randomUUID()) || Math.random().toString(36).substring(2));
        const profile = {
          id, name, server, username, password,
          kill_switch: (existing && existing.kill_switch) || false,
        };
        if (detectedCountry) profile.country_code = detectedCountry;
        else if (existing && existing.country_code) profile.country_code = existing.country_code;
        applyAdvancedFields(profile);

        const advErr = document.getElementById('err-advanced');
        if (advErr) advErr.textContent = '';

        btnSaveModal.disabled = true;
        try {
          await backend.invoke(isEdit ? 'update_profile' : 'add_profile', { profile });
          // On edit only overwrite the stored password when a new one was typed.
          if (password) {
            try {
              await backend.invoke('store_credential', { profileId: id, username, password });
            } catch (err) {
              console.error('store_credential failed', err);
              addLog(Date.now(), 'ERROR', 'Failed to store credentials: ' + String(err));
            }
          }
          profiles = await backend.invoke('list_profiles') || [];
          if (!activeProfileId) activeProfileId = id;
          editingProfileId = null;
          renderProfiles();
          renderState();
          modal.classList.remove('active');
        } catch (err) {
          const msg = String(err);
          const lower = msg.toLowerCase();
          // Errors that map to a basic field go to that field; anything about an
          // advanced option is surfaced in the advanced section (auto-expanded).
          if (lower.includes('server url') || (lower.includes('server') && lower.includes('url'))) {
            setFieldError('server', msg);
          } else if (lower.startsWith('name ') || lower.includes('name must')) {
            setFieldError('name', msg);
          } else if (lower.includes('username')) {
            setFieldError('username', msg);
          } else {
            const advErr = document.getElementById('err-advanced');
            if (advErr) advErr.textContent = msg;
            setAdvancedVisible(true);
          }
        } finally {
          btnSaveModal.disabled = false;
        }
      };

      // --- Tool toggles ---
      const btnNetshield = document.getElementById('btn-netshield');

      const btnKillswitch = document.getElementById('btn-killswitch');
      btnKillswitch.onclick = () => {
        const next = !btnKillswitch.classList.contains('active');
        backend.invoke('set_killswitch', { enabled: next }).then((s) => {
          settings = s;
          applySettingsToUI();
          addLog(Date.now(), 'INFO', `Kill Switch ${next ? 'enabled' : 'disabled'}.`);
        }).catch((err) => {
          console.error('set_killswitch failed', err);
          addLog(Date.now(), 'ERROR', 'Failed to set Kill Switch: ' + String(err));
        });
      };

      const btnAutoretry = document.getElementById('btn-autoretry');
      btnAutoretry.onclick = () => {
        const next = !btnAutoretry.classList.contains('active');
        backend.invoke('set_auto_retry', { enabled: next }).then((s) => {
          settings = s;
          applySettingsToUI();
          addLog(Date.now(), 'INFO', `Auto Retry ${next ? 'enabled' : 'disabled'}.`);
        }).catch((err) => {
          console.error('set_auto_retry failed', err);
          addLog(Date.now(), 'ERROR', 'Failed to set Auto Retry: ' + String(err));
        });
      };

      // NetShield: clicking the tool button expands a fly-out to its left with
      // three feature icons (Malware / Secure / Ads). Each icon toggles that
      // sub-feature; toggling any feature on also enables NetShield.
      const nsFlyout = document.getElementById('ns-flyout');
      const nsFlyItems = Array.from(document.querySelectorAll('.ns-fly-item'));

      const syncNsFlyout = () => {
        const ns = (settings && settings.netshield) || {};
        const map = {
          'ns-block-malware': !!ns.block_malware,
          'ns-secure-connection': !!ns.secure_connection,
          'ns-block-ads': !!ns.block_ads,
        };
        nsFlyItems.forEach((item) => {
          item.classList.toggle('on', !!map[item.dataset.target]);
        });
      };

      const closeNsFlyout = () => nsFlyout.classList.remove('open');

      btnNetshield.onclick = (e) => {
        e.stopPropagation();
        syncNsFlyout();
        nsFlyout.classList.toggle('open');
      };

      nsFlyItems.forEach((item) => {
        item.onclick = (e) => {
          e.stopPropagation();
          const ns = (settings && settings.netshield) || {};
          const cfg = {
            block_malware: !!ns.block_malware,
            secure_connection: !!ns.secure_connection,
            block_ads: !!ns.block_ads,
          };
          const key = {
            'ns-block-malware': 'block_malware',
            'ns-secure-connection': 'secure_connection',
            'ns-block-ads': 'block_ads',
          }[item.dataset.target];
          cfg[key] = !cfg[key];

          backend.invoke('set_netshield_config', { config: cfg }).then((s) => {
            settings = s;
            const anyOn = cfg.block_malware || cfg.secure_connection || cfg.block_ads;
            if (anyOn && !s.netshield_enabled) {
              return backend.invoke('set_netshield', { enabled: true }).then((s2) => {
                settings = s2;
              });
            }
          }).then(() => {
            applySettingsToUI();
            syncNsFlyout();
          }).catch((err) => {
            console.error('set_netshield_config failed', err);
            addLog(Date.now(), 'ERROR', 'Failed to set NetShield: ' + String(err));
          });
        };
      });

      // Clicking anywhere outside collapses the fly-out.
      document.addEventListener('click', (e) => {
        if (nsFlyout.classList.contains('open') && !e.target.closest('.ns-anchor')) {
          closeNsFlyout();
        }
      });

      // --- Settings panel ---
      const btnSettings = document.getElementById('btn-settings');
      btnSettings.onclick = () => {
        applySettingsToUI();
        openModal(settingsModal);
      };
      document.getElementById('btn-close-settings').onclick = () => settingsModal.classList.remove('active');

      const persistSettings = () => {
        if (!settings) settings = {};
        settings.auto_connect = document.getElementById('set-auto-connect').checked;
        settings.default_protocol = document.getElementById('set-default-protocol').value;
        backend.invoke('set_settings', { settings }).catch((err) => {
          console.error('set_settings failed', err);
          addLog(Date.now(), 'ERROR', 'Failed to save settings: ' + String(err));
        });
      };
      document.getElementById('set-auto-connect').onchange = persistSettings;

      // --- OpenConnect engine: version display only ---------------------
      const engineVersionEl = document.getElementById('engine-version');
      backend.invoke('openconnect_version').then((v) => {
        engineVersionEl.textContent = v || 'unknown';
      }).catch((err) => {
        engineVersionEl.textContent = 'Not detected';
        console.error('openconnect_version failed', err);
        addLog(Date.now(), 'ERROR', 'Failed to detect OpenConnect version: ' + String(err));
      });

      // --- MFA ---
      const btnMfaSubmit = document.getElementById('btn-mfa-submit');
      btnMfaSubmit.onclick = async () => {
        if (btnMfaSubmit.disabled) return;
        const code = document.getElementById('mfa-code-input').value.trim();
        if (!code) return;
        btnMfaSubmit.disabled = true;
        try {
          await backend.invoke('submit_mfa', { code });
          mfaModal.classList.remove('active');
          document.getElementById('mfa-code-input').value = '';
        } catch (err) {
          addLog(Date.now(), 'ERROR', 'MFA submit failed: ' + String(err));
        } finally {
          btnMfaSubmit.disabled = false;
        }
      };
      document.getElementById('mfa-code-input').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') document.getElementById('btn-mfa-submit').click();
      });

      // --- Server cert trust ---
      document.getElementById('btn-cert-cancel').onclick = () => certModal.classList.remove('active');
      document.getElementById('btn-cert-trust').onclick = async () => {
        const pin = document.getElementById('cert-pin').textContent;
        const profileId = pendingCertProfileId || activeProfileId;
        certModal.classList.remove('active');
        if (!profileId) return;
        try {
          const prof = profiles.find((p) => p.id === profileId);
          if (prof) {
            prof.server_cert = pin;
            await backend.invoke('update_profile', { profile: prof });
            addLog(Date.now(), 'INFO', 'Server certificate pinned and saved.');
            // The original connection was aborted on the untrusted cert; now that
            // the pin is saved, re-attempt the connection automatically.
            if (activeProfileId === profileId) {
              userRequestedDisconnect = false;
              await backend.invoke('connect', { profileId });
            }
          }
        } catch (err) {
          addLog(Date.now(), 'ERROR', 'Failed to save certificate: ' + String(err));
        }
      };
    }

    // --- Disable browser-native interactions (context menu, selection,
    //     drag, zoom shortcuts, refresh) for a native-app feel ---
    (function lockDownBrowserChrome() {
      document.addEventListener('contextmenu', (e) => e.preventDefault());
      document.addEventListener('dragstart', (e) => e.preventDefault());
      document.addEventListener('selectstart', (e) => {
        const t = e.target;
        const editable = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
        if (!editable) e.preventDefault();
      });
      document.addEventListener('keydown', (e) => {
        const k = e.key.toLowerCase();
        if (e.ctrlKey && ['r', 'p', 'f', 'g', 'u', '+', '-', '=', '0'].includes(k)) {
          e.preventDefault();
        }
        if (k === 'f5' || k === 'f3' || k === 'f7') e.preventDefault();
      });
      document.addEventListener('wheel', (e) => {
        if (e.ctrlKey) e.preventDefault();
      }, { passive: false });
    })();

    // --- Custom title bar controls ---
    (function setupTitlebar() {
      const appWindow = window.__TAURI__ && window.__TAURI__.window
        ? window.__TAURI__.window.getCurrentWindow()
        : null;
      if (!appWindow) return;
      const min = document.getElementById('tb-minimize');
      const max = document.getElementById('tb-maximize');
      const close = document.getElementById('tb-close');
      if (min) min.addEventListener('click', () => appWindow.minimize());
      if (max) max.addEventListener('click', () => appWindow.toggleMaximize());
      if (close) close.addEventListener('click', () => appWindow.close());
    })();

    init();
