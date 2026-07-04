// === Docs config ===
var QUICKSTART_DOCS = [
  { slug: 'quickstart', title: 'Quickstart', sidebar: 'Quickstart' },
];

var SPEC_DOCS = [
  { slug: '01-storage-format',           title: '01 \u2014 Storage Format',           sidebar: '01 \u2014 Storage Format' },
  { slug: '02-signing-interface',         title: '02 \u2014 Signing Interface',         sidebar: '02 \u2014 Signing Interface' },
  { slug: '03-policy-engine',             title: '03 \u2014 Policy Engine',             sidebar: '03 \u2014 Policy Engine' },
  { slug: '04-agent-access-layer',        title: '04 \u2014 Agent Access Layer',        sidebar: '04 \u2014 Agent Access' },
  { slug: '05-key-isolation',             title: '05 \u2014 Key Isolation',             sidebar: '05 \u2014 Key Isolation' },
  { slug: '06-wallet-lifecycle',          title: '06 \u2014 Wallet Lifecycle',          sidebar: '06 \u2014 Wallet Lifecycle' },
  { slug: '07-supported-chains',          title: '07 \u2014 Supported Chains',          sidebar: '07 \u2014 Supported Chains' },
];

var SDK_DOCS = [
  { slug: 'sdk-cli',    title: 'CLI Reference',    sidebar: 'CLI' },
  { slug: 'sdk-node',   title: 'Node.js SDK',      sidebar: 'Node.js' },
  { slug: 'sdk-python', title: 'Python SDK',       sidebar: 'Python' },
];

var DOCS = QUICKSTART_DOCS.concat(SDK_DOCS).concat(SPEC_DOCS);

// Vercel build copies docs into website-docs/md/; local dev serves from repo root
var DOCS_PATHS = ['md', '../docs'];
var isFirstBlockquote = true;

// === Marked renderer (v15 token-object API) ===
marked.use({
  renderer: {
    blockquote: function (token) {
      var body = this.parser.parse(token.tokens);
      if (isFirstBlockquote) {
        isFirstBlockquote = false;
        var inner = body.replace(/^<p>/, '').replace(/<\/p>\n?$/, '');
        return '<p class="subtitle">' + inner + '</p>\n';
      }
      return '<blockquote>' + body + '</blockquote>\n';
    },

    heading: function (token) {
      var text = this.parser.parseInline(token.tokens);
      var id = token.text.toLowerCase()
        .replace(/<[^>]+>/g, '')
        .replace(/[^\w]+/g, '-')
        .replace(/(^-|-$)/g, '');
      return '<h' + token.depth + ' id="' + id + '">' + text + '</h' + token.depth + '>\n';
    },

    code: function (token) {
      var lang = (token.lang || '').trim();
      if (lang && hljs.getLanguage(lang)) {
        var highlighted = hljs.highlight(token.text, { language: lang }).value;
        return '<pre><code class="hljs language-' + lang + '">' + highlighted + '</code></pre>\n';
      }
      // No language or unknown — render plain (preserves directory trees, ASCII diagrams)
      var escaped = token.text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
      return '<pre><code>' + escaped + '</code></pre>\n';
    },
  },
});

// === Build sidebar ===
function buildSidebar(currentSlug) {
  var sidebar = document.getElementById('docs-sidebar');
  if (!sidebar) return;

  var html = '';

  // Brand
  html += '<div class="docs-sidebar-brand">';
  html += '<a href="./">OWS</a>';
  html += '<span class="version">v1.4</span>';
  html += '</div>';

  // Nav
  html += '<div class="docs-sidebar-nav">';
  html += '<a href="./">Overview</a>';
  QUICKSTART_DOCS.forEach(function (doc) {
    var active = doc.slug === currentSlug ? ' class="active"' : '';
    html += '<a href="doc.html?slug=' + doc.slug + '"' + active + '>' + doc.sidebar + '</a>';
  });

  html += '<div class="docs-sidebar-title" style="margin-top: 1rem;">SDK Reference</div>';
  SDK_DOCS.forEach(function (doc) {
    var active = doc.slug === currentSlug ? ' class="active"' : '';
    html += '<a href="doc.html?slug=' + doc.slug + '"' + active + '>' + doc.sidebar + '</a>';
  });

  html += '<div class="docs-sidebar-title" style="margin-top: 1rem;">Specification</div>';
  SPEC_DOCS.forEach(function (doc) {
    var active = doc.slug === currentSlug ? ' class="active"' : '';
    html += '<a href="doc.html?slug=' + doc.slug + '"' + active + '>' + doc.sidebar + '</a>';
  });
  html += '</div>';

  // Footer
  html += '<div class="docs-sidebar-footer">';
  html += '<a href="https://github.com/open-wallet-standard/core">';
  html += '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>';
  html += ' GitHub';
  html += '</a>';
  html += '</div>';

  sidebar.innerHTML = html;
}

// === Build prev / next nav ===
function buildNav(currentSlug) {
  var idx = DOCS.findIndex(function (d) { return d.slug === currentSlug; });
  if (idx === -1) return '';

  var html = '<div class="docs-nav">';

  if (idx === 0) {
    html += '<a href="./"><span class="label">Previous</span><span class="title">\u2190 Overview</span></a>';
  } else {
    var prev = DOCS[idx - 1];
    html += '<a href="doc.html?slug=' + prev.slug + '"><span class="label">Previous</span><span class="title">\u2190 ' + prev.title + '</span></a>';
  }

  if (idx < DOCS.length - 1) {
    var next = DOCS[idx + 1];
    html += '<a href="doc.html?slug=' + next.slug + '" class="next"><span class="label">Next</span><span class="title">' + next.title + ' \u2192</span></a>';
  } else {
    html += '<div></div>';
  }

  html += '</div>';
  return html;
}

// === Copy buttons on pre blocks ===
function addCopyButtons() {
  document.querySelectorAll('.docs-content pre').forEach(function (pre) {
    var wrapper = document.createElement('div');
    wrapper.style.position = 'relative';
    pre.parentNode.insertBefore(wrapper, pre);
    wrapper.appendChild(pre);

    var btn = document.createElement('button');
    btn.className = 'code-copy-btn';
    btn.textContent = 'Copy';
    btn.addEventListener('click', function () {
      navigator.clipboard.writeText(pre.textContent).then(function () {
        btn.textContent = 'Copied!';
        setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
      });
    });
    wrapper.appendChild(btn);
  });
}

// === Hash scroll ===
function scrollToHash() {
  if (window.location.hash) {
    var el = document.querySelector(window.location.hash);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

// === Main ===
async function loadDoc() {
  var params = new URLSearchParams(window.location.search);
  var slug = params.get('slug');
  if (!slug || !/^[a-zA-Z0-9_-]+$/.test(slug)) { window.location.href = './'; return; }

  var doc = DOCS.find(function (d) { return d.slug === slug; });
  if (!doc) { window.location.href = './'; return; }

  document.title = doc.title + ' - OWS Docs';
  buildSidebar(doc.slug);

  var content = document.getElementById('docs-content');

  try {
    var md;
    for (var i = 0; i < DOCS_PATHS.length; i++) {
      var res = await fetch(DOCS_PATHS[i] + '/' + doc.slug + '.md');
      if (res.ok) { md = await res.text(); break; }
    }
    if (!md) throw new Error('not found');

    isFirstBlockquote = true;
    // nosemgrep: javascript.browser.security.innerHTML-concatenation.innerHTML-concatenation
    content.innerHTML = marked.parse(md) + buildNav(doc.slug);
    addCopyButtons();
    scrollToHash();
  } catch (e) {
    content.innerHTML = '<h1>Not Found</h1><p>Could not load <code></code>.</p>';
    content.querySelector('code').textContent = slug + '.md';
  }
}

window.addEventListener('hashchange', scrollToHash);
loadDoc();
