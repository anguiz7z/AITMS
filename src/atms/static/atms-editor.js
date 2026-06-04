/* ATMS — drag-and-drop system editor.
 *
 * Vanilla JS, no external libs. Renders nodes on an SVG canvas; nodes are
 * draggable, edges are created by shift-clicking source then target.
 * Output is a JSON structure compatible with the ATMS System schema.
 *
 * Bundled with the .exe — fully offline.
 */
(function () {
  "use strict";

  // v0.16.10: palette data is now generated from models.py at build
  // time (see scripts/gen_palette.py) and fetched at editor load. This
  // closes the 67% coverage gap where the hand-maintained JS array
  // only exposed 40 of 121 ComponentType values.
  let PALETTE_DATA = null;  // {version, total, groups: [{name, items: [...]}]}
  // Groups that start expanded — the rest start collapsed so the
  // 13-group / 121-item palette doesn't overwhelm a fresh user.
  const DEFAULT_EXPANDED_GROUPS = new Set([
    "AI / ML / agentic primitives",
    "Cloud compute + serverless + container",
  ]);

  const TRUST_ZONES = [
    "internet",
    "external_provider",
    "corp_net",
    "prod",
    "staging",
    "training_vpc",
    "ot_dmz",
    "ot_zone",
    "default",
  ];

  // ---- App state ------------------------------------------------------
  const state = {
    name: "Untitled system",
    description: "",
    components: [],   // {id, name, type, trust_zone, x, y}
    dataflows: [],    // {source, target, label}
    selectedNodeId: null,
    edgeMode: false,
    edgeSource: null,
    nextId: 1,
    // v0.14.4: drag state lives at the top level so a single
    // window-level mousemove handler can read it without per-node
    // closures that leak listeners across re-renders.
    draggingNodeId: null,
    dragOffsetX: 0,
    dragOffsetY: 0,
  };

  // ---- DOM lookups ----------------------------------------------------
  const palette = document.getElementById("palette");
  const canvas = document.getElementById("canvas");
  const propsPanel = document.getElementById("props");
  const yamlPreview = document.getElementById("yaml-preview");
  const sysName = document.getElementById("sys-name");
  const sysDesc = document.getElementById("sys-desc");
  const edgeBtn = document.getElementById("edge-btn");
  const clearBtn = document.getElementById("clear-btn");
  const analyzeBtn = document.getElementById("analyze-btn");
  const saveBtn = document.getElementById("save-btn");
  const status = document.getElementById("status");

  // ---- Initial palette population ------------------------------------
  //
  // v0.16.10: loadPalette() fetches palette-data.json (generated from
  // models.py + _SYNONYMS) and builds 13 collapsible groups containing
  // all 121 ComponentType values. The search box at the top filters
  // items live; matched groups auto-expand, others auto-hide.
  async function loadPalette() {
    try {
      const resp = await fetch("/static/palette-data.json", { cache: "no-cache" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      PALETTE_DATA = await resp.json();
    } catch (err) {
      console.error("Failed to load palette-data.json:", err);
      palette.innerHTML = `<div class="palette-error">Failed to load component palette: ${err.message}</div>`;
      return;
    }
    buildPalette();
    wireSearch();
  }

  function buildPalette() {
    palette.innerHTML = "";
    if (!PALETTE_DATA || !PALETTE_DATA.groups) return;

    PALETTE_DATA.groups.forEach((g) => {
      const wrapper = document.createElement("div");
      wrapper.className = "palette-group";
      wrapper.dataset.group = g.name;
      if (!DEFAULT_EXPANDED_GROUPS.has(g.name)) {
        wrapper.classList.add("collapsed");
      }

      const h = document.createElement("h4");
      h.className = "palette-group-header";
      h.innerHTML = `<span class="chevron">▾</span><span>${g.name}</span><span class="count">${g.items.length}</span>`;
      h.addEventListener("click", () => {
        wrapper.classList.toggle("collapsed");
      });
      wrapper.appendChild(h);

      g.items.forEach((c) => {
        const item = document.createElement("div");
        item.className = "palette-item";
        item.draggable = true;
        item.dataset.type = c.type;
        // Stash synonyms on the dataset so search can match without
        // re-walking PALETTE_DATA.
        item.dataset.synonyms = (c.synonyms || []).join(" ");
        item.title = c.type + (c.synonyms && c.synonyms.length
          ? "\nAliases: " + c.synonyms.join(", ") : "");
        item.innerHTML = `<span class="emoji">${c.emoji}</span><span>${c.type}</span>`;
        item.addEventListener("dragstart", (ev) => {
          ev.dataTransfer.setData("text/atms-type", c.type);
        });
        wrapper.appendChild(item);
      });
      palette.appendChild(wrapper);
    });
  }

  // ---- Palette search filter -----------------------------------------
  function wireSearch() {
    const input = document.getElementById("palette-search");
    const clearBtn = document.getElementById("palette-search-clear");
    if (!input) return;

    let timer = null;
    const applyFilter = (raw) => {
      const q = (raw || "").trim().toLowerCase();
      const groups = palette.querySelectorAll(".palette-group");

      if (!q) {
        // Empty query: restore default visibility / collapse state.
        groups.forEach((g) => {
          g.classList.remove("hidden");
          if (!DEFAULT_EXPANDED_GROUPS.has(g.dataset.group)) {
            g.classList.add("collapsed");
          } else {
            g.classList.remove("collapsed");
          }
          g.querySelectorAll(".palette-item").forEach((i) => {
            i.classList.remove("hidden");
          });
        });
        if (clearBtn) clearBtn.style.display = "none";
        return;
      }

      if (clearBtn) clearBtn.style.display = "";
      groups.forEach((g) => {
        let groupHasMatch = false;
        const groupNameMatches = g.dataset.group.toLowerCase().includes(q);
        g.querySelectorAll(".palette-item").forEach((i) => {
          const haystack = (
            i.dataset.type + " " + (i.dataset.synonyms || "")
          ).toLowerCase();
          const match = groupNameMatches || haystack.includes(q);
          i.classList.toggle("hidden", !match);
          if (match) groupHasMatch = true;
        });
        g.classList.toggle("hidden", !groupHasMatch);
        // Auto-expand groups with matches so the user sees them.
        if (groupHasMatch) g.classList.remove("collapsed");
      });
    };

    input.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(() => applyFilter(input.value), 150);
    });
    input.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") {
        input.value = "";
        applyFilter("");
      }
    });
    if (clearBtn) {
      clearBtn.style.display = "none";
      clearBtn.addEventListener("click", () => {
        input.value = "";
        applyFilter("");
        input.focus();
      });
    }
  }

  // ---- Canvas drag-drop -----------------------------------------------
  canvas.addEventListener("dragover", (ev) => {
    ev.preventDefault();
    ev.dataTransfer.dropEffect = "copy";
  });
  canvas.addEventListener("drop", (ev) => {
    ev.preventDefault();
    const type = ev.dataTransfer.getData("text/atms-type");
    if (!type) return;
    const rect = canvas.getBoundingClientRect();
    const x = ev.clientX - rect.left;
    const y = ev.clientY - rect.top;
    addNode(type, x, y);
  });

  function addNode(type, x, y) {
    const id = `c${state.nextId++}`;
    const node = {
      id,
      name: type.replace(/_/g, " "),
      type,
      trust_zone: "default",
      x,
      y,
    };
    state.components.push(node);
    renderCanvas();
    selectNode(id);
    setStatus(`Added ${type}.`);
  }

  function deleteNode(id) {
    state.components = state.components.filter((c) => c.id !== id);
    state.dataflows = state.dataflows.filter(
      (d) => d.source !== id && d.target !== id
    );
    if (state.selectedNodeId === id) state.selectedNodeId = null;
    renderCanvas();
    renderProps();
    setStatus(`Removed ${id}.`);
  }

  function selectNode(id) {
    state.selectedNodeId = id;
    renderCanvas();
    renderProps();
  }

  // ---- Canvas rendering (SVG) -----------------------------------------
  function renderCanvas() {
    canvas.innerHTML = "";
    const svgNS = "http://www.w3.org/2000/svg";

    // Edges (lines first, beneath nodes)
    state.dataflows.forEach((df) => {
      const s = state.components.find((c) => c.id === df.source);
      const t = state.components.find((c) => c.id === df.target);
      if (!s || !t) return;
      const line = document.createElementNS(svgNS, "line");
      line.setAttribute("x1", s.x + 60);
      line.setAttribute("y1", s.y + 30);
      line.setAttribute("x2", t.x + 60);
      line.setAttribute("y2", t.y + 30);
      line.setAttribute("stroke", "#58a6ff");
      line.setAttribute("stroke-width", "2");
      line.setAttribute("marker-end", "url(#arrow)");
      canvas.appendChild(line);
      if (df.label) {
        const txt = document.createElementNS(svgNS, "text");
        txt.setAttribute("x", (s.x + t.x) / 2 + 60);
        txt.setAttribute("y", (s.y + t.y) / 2 + 26);
        txt.setAttribute("fill", "#8b949e");
        txt.setAttribute("font-size", "11");
        txt.setAttribute("text-anchor", "middle");
        txt.textContent = df.label;
        canvas.appendChild(txt);
      }
    });

    // Nodes
    state.components.forEach((c) => {
      const g = document.createElementNS(svgNS, "g");
      g.setAttribute("transform", `translate(${c.x},${c.y})`);
      g.style.cursor = "move";
      g.dataset.nodeId = c.id;

      const rect = document.createElementNS(svgNS, "rect");
      rect.setAttribute("width", "120");
      rect.setAttribute("height", "60");
      rect.setAttribute("rx", "6");
      rect.setAttribute("fill", "#1f2630");
      rect.setAttribute(
        "stroke",
        c.id === state.selectedNodeId ? "#f78166" : "#30363d"
      );
      rect.setAttribute(
        "stroke-width",
        c.id === state.selectedNodeId ? "3" : "1.5"
      );
      g.appendChild(rect);

      const t1 = document.createElementNS(svgNS, "text");
      t1.setAttribute("x", "60");
      t1.setAttribute("y", "26");
      t1.setAttribute("fill", "#e6edf3");
      t1.setAttribute("font-size", "13");
      t1.setAttribute("font-weight", "600");
      t1.setAttribute("text-anchor", "middle");
      t1.textContent =
        c.name.length > 16 ? c.name.slice(0, 14) + "..." : c.name;
      g.appendChild(t1);

      const t2 = document.createElementNS(svgNS, "text");
      t2.setAttribute("x", "60");
      t2.setAttribute("y", "44");
      t2.setAttribute("fill", "#8b949e");
      t2.setAttribute("font-size", "10");
      t2.setAttribute("text-anchor", "middle");
      t2.textContent = c.type;
      g.appendChild(t2);

      // Click handler — select / participate in edge mode
      g.addEventListener("click", (ev) => {
        ev.stopPropagation();
        if (state.edgeMode) {
          if (!state.edgeSource) {
            state.edgeSource = c.id;
            setStatus(`Edge source: ${c.id}. Click target to connect.`);
            renderCanvas();
          } else if (state.edgeSource !== c.id) {
            // v0.14.4: capture the source ID BEFORE we clear it so the
            // status message reports the actual edge, not "?".
            const fromId = state.edgeSource;
            state.dataflows.push({
              source: fromId,
              target: c.id,
              label: "",
            });
            state.edgeMode = false;
            state.edgeSource = null;
            edgeBtn.classList.remove("active");
            setStatus(`Connected ${fromId} -> ${c.id}.`);
            renderCanvas();
          }
        } else {
          selectNode(c.id);
        }
      });

      // Highlight edge-source
      if (state.edgeSource === c.id) {
        rect.setAttribute("stroke", "#3fb950");
        rect.setAttribute("stroke-width", "3");
      }

      // v0.14.4: drag handler now uses a single window-level listener
      // (registered once below the render loop) keyed off
      // `state.draggingNodeId`. Previously each node-render added a
      // fresh `mousemove` + `mouseup` listener to `window`, leaking
      // O(N×renders) handlers — measurable slowdown after a couple
      // minutes of editing.
      g.addEventListener("mousedown", (ev) => {
        if (state.edgeMode) return;
        const ptr = clientToCanvas(ev);
        state.draggingNodeId = c.id;
        state.dragOffsetX = ptr.x - c.x;
        state.dragOffsetY = ptr.y - c.y;
      });

      canvas.appendChild(g);
    });

    // Arrow defs
    const defs = document.createElementNS(svgNS, "defs");
    defs.innerHTML = `<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5"
       markerWidth="6" markerHeight="6" orient="auto-start-reverse">
       <path d="M 0 0 L 10 5 L 0 10 z" fill="#58a6ff" /></marker>`;
    canvas.appendChild(defs);

    updateYamlPreview();
  }

  function clientToCanvas(ev) {
    const rect = canvas.getBoundingClientRect();
    return { x: ev.clientX - rect.left, y: ev.clientY - rect.top };
  }

  // Click empty canvas → deselect
  canvas.addEventListener("click", (ev) => {
    if (ev.target === canvas) {
      state.selectedNodeId = null;
      renderCanvas();
      renderProps();
    }
  });

  // ---- Properties panel ----------------------------------------------
  function renderProps() {
    propsPanel.innerHTML = "";
    if (!state.selectedNodeId) {
      propsPanel.innerHTML =
        "<p class='placeholder'>Click a node to edit its properties. Drag from the palette to add.</p>";
      return;
    }
    const c = state.components.find((x) => x.id === state.selectedNodeId);
    if (!c) return;

    if (!c.metadata) c.metadata = {};
    propsPanel.innerHTML = `
      <h3>Component</h3>
      <label>ID<br><input id="p-id" type="text" value="${escapeAttr(c.id)}" /></label>
      <label>Name<br><input id="p-name" type="text" value="${escapeAttr(c.name)}" /></label>
      <label>Type<br><select id="p-type">${COMPONENT_TYPES.map(
        (ct) => `<option ${ct.type === c.type ? "selected" : ""}>${ct.type}</option>`
      ).join("")}</select></label>
      <label>Trust zone<br><select id="p-zone">${TRUST_ZONES.map(
        (z) => `<option ${z === c.trust_zone ? "selected" : ""}>${z}</option>`
      ).join("")}</select></label>

      <h3 style="margin-top:14px;">Vendor / product / version
        <span style="font-weight:400;color:var(--muted);">(catalog)</span>
      </h3>
      <label>Pick from catalog<br><select id="p-product"><option value="">(custom — none)</option></select></label>
      <label>Vendor<br><input id="p-vendor" type="text" value="${escapeAttr(c.metadata.vendor || "")}" /></label>
      <label>Product<br><input id="p-prodname" type="text" value="${escapeAttr(c.metadata.product || "")}" /></label>
      <label>Version<br><select id="p-version"><option value="">(unspecified)</option></select></label>

      <button class="btn-danger" id="p-delete">Delete</button>

      <h3 style="margin-top:18px;">Outgoing flows</h3>
      <ul class="flow-list" id="flow-out"></ul>
    `;
    populateProductPicker(c);

    document.getElementById("p-id").addEventListener("change", (e) => {
      const newId = e.target.value.trim();
      if (!newId || state.components.some((x) => x.id === newId && x !== c)) {
        e.target.value = c.id;
        return;
      }
      state.dataflows.forEach((d) => {
        if (d.source === c.id) d.source = newId;
        if (d.target === c.id) d.target = newId;
      });
      c.id = newId;
      state.selectedNodeId = newId;
      renderCanvas();
      renderProps();
    });
    document.getElementById("p-name").addEventListener("input", (e) => {
      c.name = e.target.value;
      renderCanvas();
    });
    document.getElementById("p-type").addEventListener("change", (e) => {
      c.type = e.target.value;
      renderCanvas();
    });
    document.getElementById("p-zone").addEventListener("change", (e) => {
      c.trust_zone = e.target.value;
      renderCanvas();
    });
    document.getElementById("p-delete").addEventListener("click", () => {
      deleteNode(c.id);
    });

    const flowOut = document.getElementById("flow-out");
    state.dataflows
      .filter((d) => d.source === c.id)
      .forEach((d, idx) => {
        // v0.14.4: build the row using DOM APIs (textContent / setAttribute)
        // instead of `innerHTML` interpolation. The previous template
        // dropped `d.target` straight into HTML — a malicious component
        // ID like `<img src=x onerror=alert(1)>` would XSS on render.
        const li = document.createElement("li");
        const span = document.createElement("span");
        span.textContent = "-> " + (d.target || "");
        li.appendChild(span);

        const inp = document.createElement("input");
        inp.type = "text";
        inp.placeholder = "label";
        inp.value = String(d.label || "");
        inp.addEventListener("input", (e) => (d.label = e.target.value));
        li.appendChild(inp);

        const del = document.createElement("button");
        del.className = "btn-tiny";
        del.textContent = "x";
        del.addEventListener("click", () => {
          const realIdx = state.dataflows.indexOf(d);
          state.dataflows.splice(realIdx, 1);
          renderCanvas();
          renderProps();
        });
        li.appendChild(del);
        flowOut.appendChild(li);
      });
  }

  function escapeAttr(s) {
    // v0.14.4: also escape `<` / `>` / `'` for defence-in-depth — many
    // call sites today use double-quoted attribute templates, but a
    // future template change to single-quoted attributes shouldn't
    // silently regress.
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // ---- Vendor / product / version picker (v0.11) ---------------------
  // Cache catalog lookups by component_type so we hit the API once per type.
  const _catalogCache = {};
  async function fetchCatalog(type) {
    if (_catalogCache[type]) return _catalogCache[type];
    try {
      const r = await fetch("/api/devices?category=" + encodeURIComponent(type));
      const j = await r.json();
      _catalogCache[type] = j.devices || [];
    } catch (e) {
      _catalogCache[type] = [];
    }
    return _catalogCache[type];
  }

  async function populateProductPicker(c) {
    const sel = document.getElementById("p-product");
    const verSel = document.getElementById("p-version");
    const vendorInp = document.getElementById("p-vendor");
    const prodInp = document.getElementById("p-prodname");
    if (!sel || !verSel) return;

    const list = await fetchCatalog(c.type);
    sel.innerHTML = '<option value="">(custom — none)</option>' +
      list.map((d, i) => {
        const matches =
          (c.metadata.vendor === d.vendor && c.metadata.product === d.product);
        return `<option value="${i}" ${matches ? "selected" : ""}>${escapeAttr(d.vendor + " — " + d.product)}</option>`;
      }).join("");

    function fillVersions(versions) {
      verSel.innerHTML = '<option value="">(unspecified)</option>' +
        versions.map((v) => {
          const sel = c.metadata.version === v ? "selected" : "";
          return `<option ${sel}>${escapeAttr(v)}</option>`;
        }).join("");
    }
    if (c.metadata.vendor && c.metadata.product) {
      const match = list.find(d => d.vendor === c.metadata.vendor && d.product === c.metadata.product);
      fillVersions(match ? match.versions || [] : []);
    } else {
      fillVersions([]);
    }

    sel.addEventListener("change", () => {
      const idx = sel.value;
      if (idx === "") {
        c.metadata.vendor = "";
        c.metadata.product = "";
        c.metadata.version = "";
        c.metadata.product_id = "";
        if (vendorInp) vendorInp.value = "";
        if (prodInp) prodInp.value = "";
        fillVersions([]);
      } else {
        const d = list[parseInt(idx, 10)];
        c.metadata.vendor = d.vendor;
        c.metadata.product = d.product;
        c.metadata.product_id = d.id;
        c.metadata.version = "";
        if (vendorInp) vendorInp.value = d.vendor;
        if (prodInp) prodInp.value = d.product;
        fillVersions(d.versions || []);
      }
      updateYamlPreview();
    });
    verSel.addEventListener("change", () => {
      c.metadata.version = verSel.value;
      updateYamlPreview();
    });
    if (vendorInp) {
      vendorInp.addEventListener("input", () => {
        c.metadata.vendor = vendorInp.value;
        updateYamlPreview();
      });
    }
    if (prodInp) {
      prodInp.addEventListener("input", () => {
        c.metadata.product = prodInp.value;
        updateYamlPreview();
      });
    }
  }

  // ---- Buttons --------------------------------------------------------
  edgeBtn.addEventListener("click", () => {
    state.edgeMode = !state.edgeMode;
    state.edgeSource = null;
    edgeBtn.classList.toggle("active");
    setStatus(state.edgeMode ? "Edge mode: click source, then target." : "");
    renderCanvas();
  });
  clearBtn.addEventListener("click", () => {
    if (confirm("Clear the entire canvas?")) {
      state.components = [];
      state.dataflows = [];
      state.selectedNodeId = null;
      renderCanvas();
      renderProps();
    }
  });
  sysName.addEventListener("input", (e) => {
    state.name = e.target.value;
    updateYamlPreview();
  });
  sysDesc.addEventListener("input", (e) => {
    state.description = e.target.value;
    updateYamlPreview();
  });
  // v0.17.3 Cycle E: deployment_stage dropdown live-updates the preview.
  const stageDropdown = document.getElementById("deployment-stage");
  if (stageDropdown) {
    stageDropdown.addEventListener("change", () => updateYamlPreview());
  }

  // Save → fetch /editor/save → returns YAML, download as file
  saveBtn.addEventListener("click", async () => {
    const payload = exportSystem();
    try {
      const r = await fetch("/editor/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!r.ok) {
        setStatus("Save failed: " + r.statusText);
        return;
      }
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const safe = state.name.toLowerCase().replace(/[^a-z0-9]+/g, "_") || "system";
      a.download = safe + ".yaml";
      a.click();
      URL.revokeObjectURL(url);
      setStatus("Saved YAML.");
    } catch (e) {
      setStatus("Save error: " + e);
    }
  });

  // Analyze → POST JSON to /editor/analyze → page navigates to report
  analyzeBtn.addEventListener("click", async () => {
    const payload = exportSystem();
    if (payload.components.length === 0) {
      setStatus("Add at least one component before analysing.");
      return;
    }
    setStatus("Analysing...");
    const form = document.createElement("form");
    form.method = "POST";
    form.action = "/editor/analyze";
    const inp = document.createElement("input");
    inp.type = "hidden";
    inp.name = "system_json";
    inp.value = JSON.stringify(payload);
    form.appendChild(inp);
    const meth = document.getElementById("methodology");
    if (meth) {
      const m = document.createElement("input");
      m.type = "hidden";
      m.name = "methodology";
      m.value = meth.value;
      form.appendChild(m);
    }
    document.body.appendChild(form);
    form.submit();
  });

  // ---- Export / preview ----------------------------------------------
  function exportSystem() {
    // v0.17.3 Cycle E: include deployment_stage from the toolbar
    // dropdown so it round-trips into the saved YAML + into analysis.
    const stageEl = document.getElementById("deployment-stage");
    const deploymentStage = stageEl && stageEl.value ? stageEl.value : null;
    const payload = {
      name: state.name,
      description: state.description,
      components: state.components.map((c) => {
        const out = {
          id: c.id,
          name: c.name,
          type: c.type,
          trust_zone: c.trust_zone,
        };
        if (c.metadata && Object.keys(c.metadata).some((k) => c.metadata[k])) {
          out.metadata = {};
          for (const k of Object.keys(c.metadata)) {
            if (c.metadata[k]) out.metadata[k] = c.metadata[k];
          }
        }
        return out;
      }),
      dataflows: state.dataflows.map((d) => ({
        source: d.source,
        target: d.target,
        label: d.label || "",
      })),
    };
    if (deploymentStage) payload.deployment_stage = deploymentStage;
    return payload;
  }

  function updateYamlPreview() {
    const sys = exportSystem();
    const lines = [];
    lines.push(`name: ${yamlValue(sys.name)}`);
    if (sys.description) lines.push(`description: ${yamlValue(sys.description)}`);
    if (sys.deployment_stage) lines.push(`deployment_stage: ${sys.deployment_stage}`);
    lines.push("components:");
    sys.components.forEach((c) => {
      lines.push(`  - id: ${c.id}`);
      lines.push(`    name: ${yamlValue(c.name)}`);
      lines.push(`    type: ${c.type}`);
      lines.push(`    trust_zone: ${c.trust_zone}`);
    });
    if (sys.dataflows.length) {
      lines.push("dataflows:");
      sys.dataflows.forEach((d) => {
        lines.push(`  - source: ${d.source}`);
        lines.push(`    target: ${d.target}`);
        if (d.label) lines.push(`    label: ${yamlValue(d.label)}`);
      });
    }
    yamlPreview.textContent = lines.join("\n");
  }

  function yamlValue(s) {
    if (!s) return '""';
    // quote if contains special chars
    if (/[:#\-{}[\]&*!|>'"%@`,?]/.test(s) || /^\s|\s$/.test(s)) {
      return '"' + String(s).replace(/"/g, '\\"') + '"';
    }
    return s;
  }

  function setStatus(msg) {
    status.textContent = msg;
    if (msg) {
      setTimeout(() => {
        if (status.textContent === msg) status.textContent = "";
      }, 4000);
    }
  }

  // ---- Boot ----------------------------------------------------------
  // v0.14.4: single global drag handler (no per-render leaks).
  window.addEventListener("mousemove", (ev) => {
    if (!state.draggingNodeId) return;
    const c = state.components.find((x) => x.id === state.draggingNodeId);
    if (!c) return;
    const ptr = clientToCanvas(ev);
    c.x = Math.max(0, ptr.x - state.dragOffsetX);
    c.y = Math.max(0, ptr.y - state.dragOffsetY);
    renderCanvas();
  });
  window.addEventListener("mouseup", () => {
    state.draggingNodeId = null;
  });

  // v0.16.10: palette is now async (fetches palette-data.json). Canvas
  // + props render synchronously below, then the palette appears once
  // the fetch resolves. This keeps the user-visible canvas responsive
  // even if the static file is slow to load.
  loadPalette();
  renderCanvas();
  renderProps();
})();
