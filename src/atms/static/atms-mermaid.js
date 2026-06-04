// ATMS — defensive Mermaid initialiser.
//
// Loaded by every report template (Markdown report uses GitHub's renderer; HTML
// report and the inline web report load mermaid.min.js + this script). The
// goal: never throw a "Syntax error in text" bomb just because the page was
// opened in a way that left the diagram source unrendered (e.g. someone opens
// the raw .j2 / template .html directly in a file browser, or the diagram is
// empty for a degenerate System).
//
// Strategy:
//   1. Find every <pre class="mermaid">.
//   2. Read its textContent. If it doesn't start with a known Mermaid keyword
//      (flowchart / graph / sequenceDiagram / classDiagram / stateDiagram / erDiagram /
//      gantt / pie / journey / mindmap), it's either an unrendered Jinja
//      placeholder ({{ mermaid_dfd }}) or empty — hide the <pre> and surface a
//      friendly message instead.
//   3. Otherwise initialise Mermaid in dark theme and call mermaid.run() on
//      the surviving blocks.
(function () {
  'use strict';

  function isLikelyMermaid(text) {
    if (!text) return false;
    var stripped = text.trim();
    if (!stripped) return false;
    return /^(flowchart|graph|sequenceDiagram|classDiagram|stateDiagram|erDiagram|gantt|pie|journey|mindmap|gitGraph|timeline)\b/i.test(stripped);
  }

  function decorateInvalid(block) {
    block.style.display = 'none';
    var note = document.createElement('p');
    note.style.color = '#8b949e';
    note.style.fontStyle = 'italic';
    note.style.padding = '12px 0';
    note.textContent =
      'Data flow diagram unavailable — render this report through ATMS ' +
      '(atms.exe analyze ... or via the web UI) to see the diagram.';
    block.parentNode.insertBefore(note, block);
  }

  function init() {
    if (!window.mermaid) {
      return;
    }

    var blocks = document.querySelectorAll('pre.mermaid, .mermaid');
    var validBlocks = [];
    for (var i = 0; i < blocks.length; i++) {
      var b = blocks[i];
      if (isLikelyMermaid(b.textContent)) {
        validBlocks.push(b);
      } else {
        decorateInvalid(b);
      }
    }

    if (validBlocks.length === 0) {
      return;
    }

    try {
      window.mermaid.initialize({
        startOnLoad: false,
        theme: 'dark',
        flowchart: { htmlLabels: true, curve: 'basis' },
        // v0.13: 'strict' disables Mermaid `click` directives + raw HTML.
        // Component names are user-controlled, so don't let them become
        // a stored-XSS vector via Mermaid script execution.
        securityLevel: 'strict'
      });
      // Render only the blocks we vetted as valid
      window.mermaid.run({ nodes: validBlocks }).catch(function (err) {
        // Last-ditch guard: if Mermaid itself throws on a "valid-looking" block,
        // replace each block with a tidy error message rather than the bomb icon.
        for (var i = 0; i < validBlocks.length; i++) {
          decorateInvalid(validBlocks[i]);
        }
        if (window.console && window.console.warn) {
          window.console.warn('ATMS: Mermaid render failed:', err);
        }
      });
    } catch (err) {
      for (var i = 0; i < validBlocks.length; i++) {
        decorateInvalid(validBlocks[i]);
      }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
