/* Protek help — guided tour + help mode (roadmap #4).
 *
 * Text comes from help/catalog.json via the #help-data JSON that base.html
 * embeds for the current page (app.help_payload). Nothing here is
 * page-specific: sections are found from the markup every page already uses —
 * .kpi tiles (label in .k), .panel blocks with an <h2>, and named form
 * controls — and matched to the catalog by heading prefix / label / name.
 *
 * Keyboard: ? opens the menu; in a tour → / Enter next, ← back, Esc closes.
 * All text goes in via textContent — never parsed as HTML.
 */
(function () {
  'use strict';
  var dataEl = document.getElementById('help-data');
  var main = document.querySelector('main.main');
  if (!dataEl || !main) return;
  var D;
  try { D = JSON.parse(dataEl.textContent); } catch (e) { return; }

  var store = {
    get: function (s, k) { try { return window[s].getItem(k); } catch (e) { return null; } },
    set: function (s, k, v) { try { window[s].setItem(k, v); } catch (e) { /* private mode */ } },
    del: function (s, k) { try { window[s].removeItem(k); } catch (e) { /* ignore */ } },
  };

  function norm(s) { return (s || '').replace(/\s+/g, ' ').trim().toLowerCase(); }

  // Longest catalog key that the text starts with (headings are matched by
  // their static leading text; "Address-List · crowdsec" ← "Address-List").
  function byPrefix(map, text) {
    var t = norm(text), best = null, len = -1;
    Object.keys(map || {}).forEach(function (k) {
      var nk = norm(k);
      if (nk && t.indexOf(nk) === 0 && nk.length > len) { best = map[k]; len = nk.length; }
    });
    return best;
  }

  function fieldHelp(name) {
    var f = D.fields || {};
    if (f[name]) return f[name];
    var hit = null;
    Object.keys(f).forEach(function (k) {
      if (hit || k.indexOf('*') < 0) return;
      var re = new RegExp('^' + k.split('*').map(function (p) {
        return p.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
      }).join('.*') + '$');
      if (re.test(name)) hit = f[k];
    });
    return hit;
  }

  function headingText(h) {
    var s = '';
    for (var n = h.firstChild; n; n = n.nextSibling) {
      if (n.nodeType === 3) s += n.textContent;
      else if (norm(s)) break;
    }
    return s.trim() || h.textContent.trim();
  }

  function visible(el) {
    if (!el || el.closest('[hidden]')) return false;
    var r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function fieldsIn(root) {
    return Array.prototype.filter.call(
      root.querySelectorAll('input[name], select[name], textarea[name]'),
      function (f) {
        var t = (f.getAttribute('type') || '').toLowerCase();
        return t !== 'hidden' && t !== 'submit' && f.name !== 'csrf_token' && visible(f);
      });
  }

  // ── tour steps for this page ─────────────────────────────────────────────
  function buildSteps() {
    var steps = [{ title: D.label, body: [D.intro || 'An overview of this page.'] }];
    var seenStrips = [];
    Array.prototype.forEach.call(main.querySelectorAll('.kpi'), function (k) {
      var strip = k.parentElement;
      if (seenStrips.indexOf(strip) >= 0 || !visible(strip)) return;
      seenStrips.push(strip);
      var lines = [];
      Array.prototype.forEach.call(strip.querySelectorAll('.kpi'), function (kk) {
        var lab = kk.querySelector('.k');
        if (!lab || !visible(kk)) return;
        var label = lab.textContent.trim();
        lines.push([label, byPrefix(D.kpis, label) || '']);
      });
      if (lines.length) steps.push({ target: strip, title: 'The numbers', list: lines });
    });
    var tabs = main.querySelector('.tabs');
    if (tabs && visible(tabs)) {
      steps.push({ target: tabs, title: 'Related pages',
        body: ['These tabs switch between pages that belong together. The highlighted one is where you are.'] });
    }
    Array.prototype.forEach.call(main.querySelectorAll('.panel'), function (p) {
      if (!visible(p) || (p.parentElement && p.parentElement.closest('.panel'))) return;
      var h = p.querySelector('h2');
      var fields = fieldsIn(p);
      var body = [];
      var title;
      if (h) {
        title = headingText(h);
        var txt = byPrefix(D.sections, title);
        if (txt) body.push(txt);
      } else if (fields.length) {
        title = 'Settings';
      } else {
        return;
      }
      if (fields.length) {
        body.push(fields.length === 1 ? 'There is 1 setting here.' :
          'There are ' + fields.length + ' settings here.');
        body.push('Turn on Help mode (Help menu, or press ?) to see what each one does.');
      }
      if (!body.length) body.push('');
      steps.push({ target: p, title: title, body: body });
    });
    return steps;
  }

  // ── tour UI ─────────────────────────────────────────────────────────────
  var spot = null, pop = null, steps = [], idx = 0, allMode = false, lastFocus = null;

  function endTour(markDone) {
    if (spot) spot.remove();
    if (pop) pop.remove();
    spot = pop = null;
    document.removeEventListener('keydown', onTourKey, true);
    window.removeEventListener('resize', place);
    if (allMode) store.del('sessionStorage', 'protek.tour');
    if (markDone) postDone();
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function postDone() {
    var meta = document.querySelector('meta[name=csrf-token]');
    var body = new URLSearchParams({ done: '1' });
    fetch(D.done_url, { method: 'POST', body: body, credentials: 'same-origin',
      headers: { 'X-CSRFToken': meta ? meta.content : '' } }).catch(function () {});
    D.offer = false;
  }

  function place() {
    if (!pop) return;
    var s = steps[idx];
    var narrow = window.innerWidth < 640;
    if (s.target && visible(s.target)) {
      var r = s.target.getBoundingClientRect();
      spot.style.display = 'block';
      spot.style.top = (r.top + window.scrollY - 6) + 'px';
      spot.style.left = (r.left + window.scrollX - 6) + 'px';
      spot.style.width = (r.width + 12) + 'px';
      spot.style.height = (r.height + 12) + 'px';
      if (!narrow) {
        var below = r.bottom + 12 + pop.offsetHeight < window.innerHeight;
        var top = below ? r.bottom + 12 : Math.max(12, r.top - pop.offsetHeight - 12);
        pop.style.top = top + 'px';
        pop.style.left = Math.min(Math.max(12, r.left), window.innerWidth - pop.offsetWidth - 12) + 'px';
      }
    } else {
      spot.style.display = 'none';
      if (!narrow) {
        pop.style.top = Math.max(12, (window.innerHeight - pop.offsetHeight) / 2) + 'px';
        pop.style.left = Math.max(12, (window.innerWidth - pop.offsetWidth) / 2) + 'px';
      }
    }
  }

  function show(i) {
    idx = Math.max(0, Math.min(steps.length - 1, i));
    var s = steps[idx];
    if (s.target) s.target.scrollIntoView({ block: 'center' });
    pop.textContent = '';
    var count = el('div', 'help-pop-count',
      (allMode ? D.label + ' · ' : '') + 'Step ' + (idx + 1) + ' of ' + steps.length);
    var title = el('h3', 'help-pop-title', s.title || '');
    title.id = 'help-pop-title';
    pop.appendChild(count);
    pop.appendChild(title);
    (s.body || []).forEach(function (t) { if (t) pop.appendChild(el('p', null, t)); });
    if (s.list) {
      var dl = el('dl', 'help-pop-list');
      s.list.forEach(function (pair) {
        dl.appendChild(el('dt', null, pair[0]));
        dl.appendChild(el('dd', null, pair[1] || '—'));
      });
      pop.appendChild(dl);
    }
    var bar = el('div', 'help-pop-bar');
    var skip = el('button', 'btn ghost', allMode ? 'End tour' : 'Close');
    skip.type = 'button';
    skip.addEventListener('click', function () { endTour(allMode); });
    var back = el('button', 'btn ghost', 'Back');
    back.type = 'button';
    back.disabled = idx === 0;
    back.addEventListener('click', function () { show(idx - 1); });
    var last = idx === steps.length - 1;
    var nextPage = allMode && last ? nextTourPage() : null;
    var next = el('button', 'btn', last ? (nextPage ? 'Next: ' + nextPage.label + ' →' : 'Done') : 'Next');
    next.type = 'button';
    next.addEventListener('click', advance);
    bar.appendChild(skip);
    bar.appendChild(el('span', 'help-pop-gap'));
    bar.appendChild(back);
    bar.appendChild(next);
    pop.appendChild(bar);
    place();
    next.focus();
  }

  function nextTourPage() {
    var pos = tourPos();
    return pos >= 0 && pos + 1 < D.tour.length ? D.tour[pos + 1] : null;
  }

  function tourPos() {
    for (var i = 0; i < D.tour.length; i++) if (D.tour[i].key === D.page) return i;
    return -1;
  }

  function advance() {
    if (idx < steps.length - 1) return show(idx + 1);
    if (allMode) {
      var np = nextTourPage();
      if (np) {
        store.set('sessionStorage', 'protek.tour', np.key);
        window.location.href = np.url;
        return;
      }
      endTour(true);                 // finished the whole tour
      return;
    }
    endTour(false);
  }

  function onTourKey(e) {
    if (!pop) return;
    if (e.key === 'Escape') { endTour(allMode); e.preventDefault(); }
    else if (e.key === 'ArrowRight') { advance(); e.preventDefault(); }
    else if (e.key === 'ArrowLeft') { show(idx - 1); e.preventDefault(); }
  }

  function startTour(all) {
    closeMenu();
    if (pop) endTour(false);
    allMode = !!all;
    if (allMode) {
      var pos = tourPos();
      if (pos < 0 && D.tour.length) {        // start from the first tour page
        store.set('sessionStorage', 'protek.tour', D.tour[0].key);
        window.location.href = D.tour[0].url;
        return;
      }
      store.set('sessionStorage', 'protek.tour', D.page);
    }
    lastFocus = document.activeElement;
    steps = buildSteps();
    spot = el('div', 'help-spot');
    spot.setAttribute('aria-hidden', 'true');
    pop = el('div', 'help-pop');
    pop.setAttribute('role', 'dialog');
    pop.setAttribute('aria-modal', 'false');
    pop.setAttribute('aria-labelledby', 'help-pop-title');
    pop.setAttribute('aria-live', 'polite');
    document.body.appendChild(spot);
    document.body.appendChild(pop);
    document.addEventListener('keydown', onTourKey, true);
    window.addEventListener('resize', place);
    show(0);
  }

  // ── help mode ───────────────────────────────────────────────────────────
  var tip = null;

  function closeTip() {
    if (!tip) return;
    var owner = tip._owner;
    tip.remove();
    tip = null;
    if (owner) owner.setAttribute('aria-expanded', 'false');
  }

  function openTip(btn, text) {
    var same = tip && tip._owner === btn;
    closeTip();
    if (same) return;
    tip = el('div', 'help-tip', text);
    tip.setAttribute('role', 'note');
    tip._owner = btn;
    tip.id = 'help-tip';
    btn.setAttribute('aria-expanded', 'true');
    btn.setAttribute('aria-describedby', 'help-tip');
    document.body.appendChild(tip);
    var r = btn.getBoundingClientRect();
    var left = Math.min(r.left + window.scrollX, window.scrollX + window.innerWidth - tip.offsetWidth - 12);
    tip.style.top = (r.bottom + window.scrollY + 6) + 'px';
    tip.style.left = Math.max(window.scrollX + 12, left) + 'px';
  }

  function mark(after, label, text, inside) {
    if (!text) return;
    var b = el('button', 'help-mark', '?');
    b.type = 'button';
    b.setAttribute('aria-label', 'What is ' + label + '?');
    b.setAttribute('aria-expanded', 'false');
    b.addEventListener('click', function (e) { e.preventDefault(); e.stopPropagation(); openTip(b, text); });
    if (inside) after.appendChild(b);
    else after.insertAdjacentElement('afterend', b);
  }

  function labelFor(f) {
    if (f.id) {
      var l = main.querySelector('label[for="' + f.id.replace(/"/g, '') + '"]');
      if (l) return l;
    }
    var wrap = f.closest('label');
    if (wrap) return wrap;
    var prev = f.previousElementSibling;
    return prev && prev.tagName === 'LABEL' ? prev : null;
  }

  function helpModeOn() {
    document.body.classList.add('help-mode');
    Array.prototype.forEach.call(main.querySelectorAll('.kpi .k'), function (k) {
      mark(k, k.textContent.trim(), byPrefix(D.kpis, k.textContent), true);
    });
    Array.prototype.forEach.call(main.querySelectorAll('.panel h2'), function (h) {
      var t = headingText(h);
      mark(h, t, byPrefix(D.sections, t), true);
    });
    fieldsIn(main).forEach(function (f) {
      var lab = labelFor(f);
      var name = lab ? lab.textContent.trim() : f.name;
      if (lab) mark(lab, name, fieldHelp(f.name), true);
      else mark(f, name, fieldHelp(f.name), false);
    });
  }

  function helpModeOff() {
    closeTip();
    document.body.classList.remove('help-mode');
    Array.prototype.forEach.call(document.querySelectorAll('.help-mark'), function (b) { b.remove(); });
  }

  function setHelpMode(on) {
    if (on) helpModeOn(); else helpModeOff();
    store.set('localStorage', 'protek.helpmode', on ? '1' : '0');
    var item = document.querySelector('[data-help="help-mode"]');
    if (item) {
      item.setAttribute('aria-pressed', on ? 'true' : 'false');
      item.querySelector('b').textContent = on ? 'on' : 'off';
    }
  }

  // ── menu ────────────────────────────────────────────────────────────────
  var btn = document.getElementById('help-btn');
  var menu = document.getElementById('help-menu');

  function openMenu() {
    if (!menu) return;
    menu.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    var first = menu.querySelector('[role=menuitem]');
    if (first) first.focus();
  }

  function closeMenu() {
    if (!menu || menu.hidden) return;
    menu.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
  }

  if (btn && menu) {
    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      if (menu.hidden) openMenu(); else closeMenu();
    });
    menu.addEventListener('click', function (e) {
      var item = e.target.closest('[data-help]');
      if (!item) return;
      var act = item.getAttribute('data-help');
      if (act === 'tour-page') startTour(false);
      else if (act === 'tour-all') startTour(true);
      else if (act === 'help-mode') { closeMenu(); setHelpMode(!document.body.classList.contains('help-mode')); }
    });
    menu.addEventListener('keydown', function (e) {
      var items = Array.prototype.slice.call(menu.querySelectorAll('[role=menuitem]'));
      var i = items.indexOf(document.activeElement);
      if (e.key === 'ArrowDown') { items[(i + 1) % items.length].focus(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { items[(i - 1 + items.length) % items.length].focus(); e.preventDefault(); }
      else if (e.key === 'Escape') { closeMenu(); btn.focus(); e.preventDefault(); }
    });
  }

  document.addEventListener('click', function (e) {
    if (menu && !menu.hidden && !e.target.closest('.help-wrap')) closeMenu();
    if (tip && !e.target.closest('.help-tip') && !e.target.closest('.help-mark')) closeTip();
  });

  document.addEventListener('keydown', function (e) {
    var t = document.activeElement && document.activeElement.tagName;
    if (e.key === 'Escape' && tip) { var o = tip._owner; closeTip(); if (o) o.focus(); return; }
    if (e.key !== '?' || pop || t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' ||
        (document.activeElement && document.activeElement.isContentEditable)) return;
    if (menu.hidden) openMenu(); else closeMenu();
    e.preventDefault();
  });

  // ── offer + resume ──────────────────────────────────────────────────────
  if (store.get('localStorage', 'protek.helpmode') === '1') setHelpMode(true);

  var resume = store.get('sessionStorage', 'protek.tour');
  if (resume && resume === D.page) {
    setTimeout(function () { startTour(true); }, 300);
  } else if (resume && tourPos() < 0) {
    store.del('sessionStorage', 'protek.tour');   // wandered off the tour
  }

  if (D.offer && !resume) {
    var card = el('div', 'panel help-offer');
    card.setAttribute('role', 'region');
    card.setAttribute('aria-label', 'Tour offer');
    card.appendChild(el('strong', null, 'New to Protek? Take the tour.'));
    card.appendChild(el('p', 'muted', 'A few minutes, page by page — what each part shows and what each setting does. You can restart it any time from Help.'));
    var row = el('div', 'help-offer-row');
    var go = el('button', 'btn', 'Start the tour');
    go.type = 'button';
    go.addEventListener('click', function () { card.remove(); startTour(true); });
    var later = el('button', 'btn ghost', 'Not now');
    later.type = 'button';
    later.addEventListener('click', function () { card.remove(); postDone(); });
    row.appendChild(go);
    row.appendChild(later);
    card.appendChild(row);
    var flashes = main.querySelectorAll('.flash');
    var anchor = flashes.length ? flashes[flashes.length - 1] : null;
    if (anchor) anchor.insertAdjacentElement('afterend', card);
    else main.insertBefore(card, main.firstChild);
  }
})();
