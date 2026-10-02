// Blackbox report: page switching, and the event pages' tables. The events
// are in data files next to report.html (data/<page>-<day>.js), loaded only
// when a page needs them. Each file calls BB.put with gzip-compressed JSON.
(function () {
  'use strict';
  var meta = JSON.parse(document.getElementById('bb-meta').textContent);
  var waiting = {}, store = {};

  // BB.put is called by each data file once it has loaded.
  window.BB = {
    put: function (key, b64) {
      store[key] = b64;
      if (waiting[key]) { waiting[key].forEach(function (f) { f(); }); delete waiting[key]; }
    }
  };

  function loadScript(key, file) {
    return new Promise(function (resolve, reject) {
      if (store[key] !== undefined) { resolve(); return; }
      (waiting[key] = waiting[key] || []).push(resolve);
      if (waiting[key].length > 1) return;
      var s = document.createElement('script');
      s.src = 'data/' + file;
      s.onerror = function () { reject(new Error('could not read data/' + file)); };
      document.head.appendChild(s);
    });
  }

  function unpack(key) {
    var bin = atob(store[key]), bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    var ds = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Response(ds).text().then(JSON.parse);
  }

  function getData(key, file) {
    return loadScript(key, file).then(function () { return unpack(key); });
  }

  // ---- Formatting ----
  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  // t is seconds (UTC); off the report's UTC offset that day.
  function when(t, off) {
    var d = new Date((t + off) * 1000);
    return pad(d.getUTCDate()) + ' ' + MONTHS[d.getUTCMonth()] + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds());
  }
  function dayLabel(day) {
    var d = new Date(Date.UTC(+day.slice(0, 4), +day.slice(4, 6) - 1, +day.slice(6, 8)));
    return DAYS[d.getUTCDay()] + ' ' + d.getUTCDate() + ' ' + MONTHS[d.getUTCMonth()];
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; });
  }
  // Only High and Medium are flagged; other rows show a dash.
  var SEV = { high: 'High', medium: 'Medium' };
  function sevCell(s) { return SEV[s] ? '<span class="sv ' + s + '">' + SEV[s] + '</span>' : '<span class="mute">—</span>'; }

  // ---- Pages ----
  var views = document.querySelectorAll('.view');
  function show() {
    var id = (location.hash || '#overview').slice(1).split('/')[0];
    if (!document.querySelector('.view[data-view="' + id + '"]')) id = 'overview';
    views.forEach(function (v) { v.hidden = v.getAttribute('data-view') !== id; });
    document.querySelectorAll('[data-nav]').forEach(function (a) { a.classList.toggle('on', a.getAttribute('data-nav') === id); });
    var t = tables[id];
    if (t) t.open();
    if (id === 'detections') showDetection((location.hash.split('/')[1] || ''));
    window.scrollTo(0, 0);
  }

  // ---- Detections: one shown at a time, the newest unless one is named ----
  function showDetection(n) {
    var links = document.querySelectorAll('[data-det]');
    if (!links.length) return;
    if (!document.querySelector('[data-detail="' + n + '"]')) {
      var first = Array.prototype.find.call(links, function (a) { return !a.hidden; }) || links[0];
      n = first.getAttribute('data-det');
    }
    links.forEach(function (a) { a.classList.toggle('sel', a.getAttribute('data-det') === n); });
    document.querySelectorAll('[data-detail]').forEach(function (d) { d.hidden = d.getAttribute('data-detail') !== n; });
  }
  document.querySelectorAll('[data-detsev] span').forEach(function (chip) {
    chip.addEventListener('click', function () {
      var sev = chip.getAttribute('data-sev');
      chip.parentNode.querySelectorAll('span').forEach(function (c) { c.classList.toggle('on', c === chip); });
      var list = chip.closest('.dlist');
      list.querySelectorAll('[data-det]').forEach(function (a) { a.hidden = !!sev && !a.classList.contains(sev); });
      // Hide day headings with nothing left under them.
      list.querySelectorAll('.dayh').forEach(function (h) {
        var el = h.nextElementSibling, any = false;
        while (el && !el.classList.contains('dayh')) { if (!el.hidden) any = true; el = el.nextElementSibling; }
        h.hidden = !any;
      });
    });
  });

  // ---- Event tables ----
  // Rows are kept as compact arrays: [index, time, host, sev, action, user,
  // target, source, summary, eventID, log, process, command, outcome, flags,
  // day, offset], strings already looked up.
  var ROW_H = 38;
  var tables = {};
  (meta.pages || []).forEach(function (p) {
    var el = document.querySelector('[data-events="' + p.ID + '"]');
    if (el) tables[p.ID] = new Table(p, el);
  });

  function Table(page, el) {
    this.page = page; this.el = el; this.rows = null; this.shown = [];
    this.body = el.querySelector('.vt-body'); this.box = el.querySelector('.vt');
    this.count = el.querySelector('[data-count]');
    var self = this;
    el.querySelectorAll('[data-f]').forEach(function (f) {
      f.addEventListener('input', function () { self.filter(); });
    });
    this.box.addEventListener('scroll', function () { self.draw(); });
    this.body.addEventListener('click', function (e) {
      var r = e.target.closest('[data-i]');
      if (r) openEvent(self, +r.getAttribute('data-i'));
    });
    el.querySelector('[data-csv]').addEventListener('click', function () { self.csv(); });
  }

  Table.prototype.open = function () {
    if (this.loading) return;
    var self = this, p = this.page;
    if (!p.Days || !p.Days.length) { this.message('No events of this kind in this report.'); this.rows = []; this.count.textContent = ''; return; }
    if (typeof DecompressionStream === 'undefined') {
      this.message('This browser is too old to show the event list. Open events.csv in this report\'s folder instead, or use a current version of Edge, Chrome or Firefox.');
      return;
    }
    this.loading = true;
    var rows = [], done = 0;
    this.message('Loading events…');
    var jobs = p.Days.map(function (day) {
      return getData(p.ID + '/' + day, p.ID + '-' + day + '.js').then(function (c) {
        var d = c.dict;
        c.rows.forEach(function (r) {
          rows.push([r[0], c.base + r[1], d[r[2]], d[r[3]], d[r[4]], d[r[5]], r[6], d[r[7]], r[8], r[9], d[r[10]], d[r[11]], r[12], d[r[13]], r[14], day, c.off]);
        });
        done++;
        self.message('Loading events… ' + done + ' of ' + p.Days.length + ' days');
      });
    });
    Promise.all(jobs).then(function () {
      rows.sort(function (a, b) { return b[1] - a[1] || b[0] - a[0]; });
      self.rows = rows;
      self.options();
      self.filter();
    }).catch(function (err) {
      self.message('The events could not be read: ' + err.message + '. Open events.csv in this report\'s folder instead.');
    });
  };

  Table.prototype.message = function (text) {
    this.body.style.height = '';
    this.body.innerHTML = '<div class="vt-msg">' + esc(text) + '</div>';
  };

  Table.prototype.options = function () {
    var self = this;
    function fill(sel, col, label) {
      var seen = {};
      self.rows.forEach(function (r) { if (r[col]) seen[r[col]] = (seen[r[col]] || 0) + 1; });
      Object.keys(seen).sort(function (a, b) { return a.localeCompare(b); }).forEach(function (v) {
        var o = document.createElement('option'); o.value = v; o.textContent = (label ? label(v) : v) + ' (' + seen[v].toLocaleString() + ')';
        sel.appendChild(o);
      });
    }
    fill(this.el.querySelector('[data-f="host"]'), 2);
    fill(this.el.querySelector('[data-f="user"]'), 5);
    fill(this.el.querySelector('[data-f="day"]'), 15, dayLabel);
  };

  Table.prototype.filter = function () {
    if (!this.rows) return;
    var f = {};
    this.el.querySelectorAll('[data-f]').forEach(function (x) { f[x.getAttribute('data-f')] = x.value; });
    var text = (f.text || '').toLowerCase();
    this.shown = this.rows.filter(function (r) {
      if (f.sev && r[3] !== f.sev) return false;
      if (f.host && r[2] !== f.host) return false;
      if (f.user && r[5] !== f.user) return false;
      if (f.day && r[15] !== f.day) return false;
      if (text) {
        var hay = (r[8] + ' ' + r[2] + ' ' + r[5] + ' ' + r[6] + ' ' + r[7] + ' ' + r[9] + ' ' + r[11] + ' ' + r[12]).toLowerCase();
        if (hay.indexOf(text) < 0) return false;
      }
      return true;
    });
    var all = this.rows.length, n = this.shown.length;
    this.count.textContent = n === all ? all.toLocaleString() + ' events' : n.toLocaleString() + ' of ' + all.toLocaleString() + ' events';
    this.body.style.height = (n * ROW_H) + 'px';
    this.box.scrollTop = 0;
    this.last = null;
    if (!n) { this.message(all ? 'No events match these filters.' : 'No events of this kind in this report.'); return; }
    this.draw();
  };

  // draw renders only the rows in view (plus a margin), so a page with
  // hundreds of thousands of events scrolls smoothly.
  Table.prototype.draw = function () {
    if (!this.shown.length) return;
    var top = this.box.scrollTop, h = this.box.clientHeight || 600;
    var first = Math.max(0, Math.floor(top / ROW_H) - 10), last = Math.min(this.shown.length, Math.ceil((top + h) / ROW_H) + 10);
    if (this.last && this.last[0] === first && this.last[1] === last) return;
    this.last = [first, last];
    var html = '';
    for (var i = first; i < last; i++) {
      var r = this.shown[i];
      html += '<div class="vt-row" data-i="' + i + '" style="top:' + (i * ROW_H) + 'px"><span class="mono">' + when(r[1], r[16]) +
        '</span><span><b>' + esc(r[2]) + '</b></span><span>' + esc(r[5]) + '</span><span class="what" title="' + esc(r[8]) + '">' + esc(r[8]) +
        (r[14] ? ' <i class="flag">' + esc(r[14].split(',').join(' · ')) + '</i>' : '') + '</span><span>' + sevCell(r[3]) + '</span></div>';
    }
    this.body.innerHTML = html;
  };

  Table.prototype.csv = function () {
    if (!this.shown.length) return;
    var q = function (s) { s = String(s == null ? '' : s); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    var lines = ['time,system,person,target,source,what happened,severity,event id,log,process,command,outcome'];
    this.shown.forEach(function (r) {
      lines.push([when(r[1], r[16]), r[2], r[5], r[6], r[7], r[8], r[3], r[9], r[10], r[11], r[12], r[13]].map(q).join(','));
    });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv' }));
    a.download = this.page.ID + '-events.csv';
    a.click();
  };

  // ---- Event panel ----
  var ov = document.querySelector('.ov'), drawer = document.querySelector('.drawer');
  function closeEvent() { ov.hidden = true; drawer.hidden = true; }
  ov.addEventListener('click', closeEvent);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeEvent(); });

  function openEvent(table, i) {
    var r = table.shown[i], p = table.page;
    if (!r) return;
    var rows = [['Time', when(r[1], r[16]) + ' ' + meta.zone], ['System', r[2]], ['Person', r[5]], ['Target', r[6]], ['Source address', r[7]],
      ['Event ID', r[9]], ['Log', r[10]], ['Program', r[11]], ['Command', r[12]], ['Outcome', r[13]]];
    var kv = rows.filter(function (x) { return x[1]; }).map(function (x) { return '<span>' + esc(x[0]) + '</span><b>' + esc(x[1]) + '</b>'; }).join('');
    drawer.innerHTML = '<span class="x" tabindex="0">✕ Close</span><div class="pm" style="margin-bottom:4px">' + esc(p.Title) + (r[9] ? ' · event ' + esc(r[9]) : '') + '</div>' +
      '<h3>' + esc(r[8]) + '</h3><div style="margin-top:6px">' + sevCell(r[3]) + '</div><div class="kv3">' + kv + '</div><div class="raw">Loading the original event data…</div>';
    drawer.querySelector('.x').addEventListener('click', closeEvent);
    ov.hidden = false; drawer.hidden = false;
    getData('raw/' + p.ID + '/' + r[15], p.ID + '-' + r[15] + '-raw.js').then(function (raw) {
      // The raw file lists the day's events in the same order as its data file.
      return getData(p.ID + '/' + r[15], p.ID + '-' + r[15] + '.js').then(function (c) {
        for (var k = 0; k < c.rows.length; k++) if (c.rows[k][0] === r[0]) return raw[k];
      });
    }).then(function (x) {
      var box = drawer.querySelector('.raw');
      if (!box) return;
      if (!x) { box.textContent = 'No original event data.'; return; }
      var out = '';
      (x[0] || []).forEach(function (d) { out += '<span class="t">' + esc(d.label) + ':</span> <span class="v">' + esc(d.value) + '</span>\n'; });
      var f = x[1] || {};
      Object.keys(f).forEach(function (k) { out += '<span class="t">' + esc(k) + '</span> <span class="v">' + esc(f[k]) + '</span>\n'; });
      if (x[2]) out = '<span class="t">Recorded as:</span> <span class="v">' + esc(x[2]) + '</span>\n' + out;
      box.innerHTML = out || 'No original event data.';
    }).catch(function (err) {
      var box = drawer.querySelector('.raw');
      if (box) box.textContent = 'The original event data could not be read: ' + err.message;
    });
  }

  window.addEventListener('hashchange', show);
  show();
})();
