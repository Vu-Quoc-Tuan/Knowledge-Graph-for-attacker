const $ = (selector) => document.querySelector(selector);
const html = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
const chip = (value) => `<span class="chip ${String(value || "unknown").toLowerCase().replaceAll("_", "-")}">${html(value || "UNKNOWN")}</span>`;

function safeReferenceUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return ["http:", "https:"].includes(url.protocol) ? url.href : null;
  } catch (_) {
    return null;
  }
}

let currentGraph = { nodes: [], edges: [] };
let graphState = { zoom: 1, panX: 0, panY: 0, isDragging: false, startX: 0, startY: 0 };
let currentCveId = "";
let pattPayloadState = { offset: 0, total: 0, limit: 50 };
let backendInfo = { backend: "unknown", graphSchema: "ckg-v2" };

const backendInfoPromise = fetch("/healthz")
  .then(async (response) => {
    if (!response.ok) return;
    const data = await response.json();
    backendInfo = { ...backendInfo, ...data };
    updateBackendStatus();
  })
  .catch(() => {
    updateBackendStatus();
  });

function backendLabel() {
  if (backendInfo.backend === "in-memory") return "in-memory";
  if (backendInfo.backend === "neo4j") return "Neo4j";
  return backendInfo.backend || "unknown backend";
}

function updateBackendStatus() {
  const status = $("#backend-status");
  if (status) status.textContent = `Backend: ${backendLabel()}`;
}

async function fetchJson(url) {
  const response = await fetch(url);
  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }
  if (!response.ok) {
    throw new Error(data?.error || `HTTP ${response.status}`);
  }
  return data;
}

function renderCase(data) {
  const vulnerability = data.vulnerability;
  currentCveId = vulnerability.id;
  $("#case-summary").classList.remove("empty");
  $("#case-summary").innerHTML = `
    <div class="case-card-header">
      <span class="case-id-badge">${html(vulnerability.id)}</span>
      <span style="font-family: var(--mono); font-size: 0.78rem; color: var(--text-dim);">${html(vulnerability.props.published_at ? new Date(vulnerability.props.published_at).toLocaleDateString() : "")}</span>
    </div>
    <h3 class="case-title">${html(vulnerability.props.title || "Untitled source record")}</h3>
    <p class="case-desc">${html(vulnerability.props.description || "No source description stored.")}</p>
  `;
  $("#assertions").innerHTML = data.weaknesses.length ? data.weaknesses.map(({props}) => `<li><span class="identifier">${html(props.cwe_id || "unresolved")}</span>${props.stale || props.all_source_snapshots_available === false ? '<span class="badge badge-amber">Legacy · chưa xác minh nguồn</span>' : chip(props.status)}<span style="color: var(--text-dim); font-size: 0.78rem; font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${html((props.evidence_spans || []).map((x) => x.locator).join(", ") || "evidence locator unavailable")}</span></li>`).join("") : "<li>Chưa có ánh xạ CWE từ nguồn xác minh.</li>";
}

function renderNeighbors(data) {
  $("#neighbors").innerHTML = data.neighbors.length ? data.neighbors.map((n) => `<li><span class="identifier" style="color: var(--cyan);">${html(n.vulnerability_id)}</span><small>${html(n.sources.join(" · "))} / score ${Number(n.score).toFixed(2)}</small></li>`).join("") : "<li>Không tìm thấy lỗ hổng tương đồng.</li>";
}

const CONSTRAINT_LABELS = {
  "CONSTRAINT-HTTP-SERVICE-REACHABLE": "🌐 Dịch vụ Web HTTP/HTTPS đang mở",
  "CONSTRAINT-REMOTE-NETWORK-REACHABLE": "📡 Cho phép truy cập mạng từ xa (Remote Reachable)",
  "CONSTRAINT-SQL-BACKEND": "🗄️ CSDL SQL Backend (MySQL, PostgreSQL, SQLite...)",
  "CONSTRAINT-FTP-SERVICE-REACHABLE": "📁 Dịch vụ FTP đang chạy trên cổng 21",
  "CONSTRAINT-COMMAND-EXECUTION-PRIVILEGE": "⚙️ Tiến trình ứng dụng có quyền gọi shell OS",
  "CONSTRAINT-UNAUTHENTICATED-ACCESS": "🔓 Không cần xác thực trước (Pre-Auth / Unauthenticated)",
  "CONSTRAINT-AUTHENTICATED-SESSION": "🔑 Cần phiên đăng nhập người dùng hợp lệ",
  "CONSTRAINT-LOCAL-PROCESS-EXECUTION": "💻 Yêu cầu quyền gọi tiến trình hoặc tương tác cục bộ",
  "CONSTRAINT-CONTAINER-ENVIRONMENT": "🐳 Thực thi trong môi trường Container (Docker/runc/k8s)",
  "CONSTRAINT-ADMIN-PRIVILEGE": "🛡️ Yêu cầu tài khoản đặc quyền quản trị viên",
};

function formatMissingBinding(binding) {
  if (binding.startsWith("endpoint=")) {
    return `<span class="badge-tag badge-tag-blue">🎯 Endpoint: <code>${html(binding.replace("endpoint=", ""))}</code></span>`;
  }
  if (binding.startsWith("parameter:")) {
    return `<span class="badge-tag badge-tag-green">🏷️ Tham số: <code>${html(binding.replace("parameter:", ""))}</code></span>`;
  }
  if (binding.startsWith("function:")) {
    return `<span class="badge-tag badge-tag-purple">⚙️ Hàm: <code>${html(binding.replace("function:", ""))}</code></span>`;
  }
  if (binding.startsWith("service:")) {
    return `<span class="badge-tag badge-tag-orange">🔌 Dịch vụ: <code>${html(binding.replace("service:", ""))}</code></span>`;
  }
  if (binding === "environment_snapshot") {
    return `<span class="badge-tag badge-tag-gray">🌐 IP / Host mục tiêu</span>`;
  }
  if (binding.endsWith("_probe")) {
    return `<span class="badge-tag badge-tag-cyan">💉 Probe: ${html(binding.replace("_probe", ""))}</span>`;
  }
  return `<span class="badge-tag badge-tag-gray">${html(binding)}</span>`;
}

window.copyPoc = function(btn) {
  const code = btn.closest(".poc-box")?.querySelector("code")?.innerText || "";
  if (!code) return;
  navigator.clipboard.writeText(code).then(() => {
    const originalText = btn.innerHTML;
    btn.innerHTML = "✅ Đã Chép!";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.innerHTML = originalText;
      btn.classList.remove("copied");
    }, 2000);
  }).catch(() => {
    prompt("Sao chép câu lệnh dưới đây:", code);
  });
};

window.copyReferencePayload = function(btn) {
  const code = btn.closest(".payload-reference-card")?.querySelector("code")?.innerText || "";
  if (!code) return;
  navigator.clipboard.writeText(code).then(() => {
    const originalText = btn.textContent;
    btn.textContent = "Đã chép";
    setTimeout(() => { btn.textContent = originalText; }, 1500);
  }).catch(() => prompt("Sao chép chuỗi tham khảo này:", code));
};

function renderPattPayloadCard(payload) {
  return `
    <article class="payload-reference-card">
      <div class="payload-reference-header">
        <div class="payload-reference-tags">
          <span class="badge-weakness-tag">${html(payload.cwe_id || "CWE")}</span>
          <span class="badge badge-tech-item">${html(payload.family_name || payload.family_key || "PATT")}</span>
          ${payload.technology ? `<span class="badge badge-tech-type">${html(payload.technology)}</span>` : ""}
        </div>
        <span class="payload-status">${html(payload.validation_status || "untested")}</span>
      </div>
      <div class="payload-code-box">
        <button class="btn-copy-reference" type="button" onclick="copyReferencePayload(this)">Sao chép tham khảo</button>
        <pre><code>${html(payload.value)}</code></pre>
      </div>
      <dl class="payload-provenance">
        <div><dt>Nguồn</dt><dd>${safeReferenceUrl(payload.source_url) ? `<a href="${html(safeReferenceUrl(payload.source_url))}" target="_blank" rel="noopener noreferrer">${html(payload.source_file || "PATT source")}</a>` : html(payload.source_file || "PATT source")}</dd></div>
        <div><dt>Vị trí</dt><dd>${html(payload.locator || "unknown")}</dd></div>
        <div><dt>Snapshot</dt><dd>${html(payload.source_snapshot_digest || "unknown")}</dd></div>
      </dl>
    </article>
  `;
}

function renderPattPayloads(data, append = false) {
  const target = $("#patt-payloads");
  if (!target) return;
  const payloads = data?.payloads || [];
  const total = Number(data?.total || 0);
  const limit = Number(data?.limit || 50);
  const offset = Number(data?.offset || 0);
  if (!append) {
    pattPayloadState = { offset, total, limit };
  } else {
    pattPayloadState = { offset: offset + payloads.length, total, limit };
  }
  if (!total && !append) {
    target.innerHTML = "<p class='payload-reference-empty'>Chưa có payload PATT đã nạp cho các CWE liên quan. Nạp manifest PATT cục bộ trước; dữ liệu này luôn ở trạng thái reference chưa kiểm chứng.</p>";
    return;
  }
  if (!append) {
    const familySummary = (data?.families || []).map((item) =>
      `<span class="badge badge-tech-item">${html(item.family_name || item.family_key)} · ${html(item.payload_count)} refs</span>`
    ).join("");
    target.innerHTML = `
      <div class="payload-reference-summary" style="grid-column: 1 / -1;">
        <strong>${html(total)} reference payloads</strong>
        <span class="reference-only-label">Graph giữ family/source; chi tiết được tải theo trang.</span>
        <div class="payload-reference-tags">${familySummary}</div>
      </div>
      <div id="patt-payload-list" class="payload-reference-grid" style="grid-column: 1 / -1;"></div>
      <div id="patt-payload-pager" style="grid-column: 1 / -1; text-align: center;"></div>
    `;
  }
  const list = $("#patt-payload-list");
  if (!list) return;
  if (append) list.insertAdjacentHTML("beforeend", payloads.map(renderPattPayloadCard).join(""));
  else list.innerHTML = payloads.map(renderPattPayloadCard).join("");
  const pager = $("#patt-payload-pager");
  if (pager) {
    const loaded = offset + payloads.length;
    pager.innerHTML = loaded < total
      ? `<button class="btn-secondary" type="button" data-next-offset="${html(loaded)}" onclick="loadMorePattPayloads(this)">Tải thêm (${html(total - loaded)} còn lại)</button>`
      : `<span class="reference-only-label">Đã tải ${html(total)} / ${html(total)} reference payloads</span>`;
  }
}

window.loadMorePattPayloads = async function(button) {
  const nextOffset = Number(button?.dataset.nextOffset || pattPayloadState.offset);
  button.disabled = true;
  button.textContent = "Đang tải…";
  try {
    const encoded = encodeURIComponent(currentCveId);
    const data = await fetchJson(`/cves/${encoded}/payloads?limit=${pattPayloadState.limit}&offset=${nextOffset}`);
    renderPattPayloads(data, true);
  } catch (error) {
    button.disabled = false;
    button.textContent = "Tải thêm";
    $("#notice").className = "notice warning";
    $("#notice").textContent = `Không tải thêm được PATT references: ${error.message}`;
  }
}

function renderScenarios(data) {
  if (!data.scenarios || data.scenarios.length === 0) {
    $("#scenarios").innerHTML = "<p style='color: var(--text-dim); padding: 1rem;'>Chưa có kịch bản đủ căn cứ cho CVE này. Hãy kiểm tra lại nguồn và liên kết CWE.</p>";
    return;
  }

  // Prioritize rich scenarios with concrete steps/PoC and prune redundant empty skeletons
  const richScenarios = data.scenarios.filter(item => item.scenario.steps && item.scenario.steps.length > 0);
  let displayList = data.scenarios;
  if (richScenarios.length > 0) {
    const coveredWeaknesses = new Set(richScenarios.flatMap(item => item.scenario.weakness_ids || []));
    const validOthers = data.scenarios.filter(item => {
      if (item.scenario.steps && item.scenario.steps.length > 0) return false;
      const weaknesses = item.scenario.weakness_ids || [];
      return weaknesses.some(w => !coveredWeaknesses.has(w));
    });
    displayList = [...richScenarios, ...validOthers];
  }

  $("#scenarios").innerHTML = displayList.map(({scenario, premises, missing_bindings, evidence_ids}) => {
    const title = scenario.title || (premises && premises[0]) || `Kịch bản kiểm thử ${scenario.scenario_id}`;
    const desc = scenario.description || "";
    const steps = scenario.steps || [];
    const poc = scenario.poc_command || "";
    const bindings = missing_bindings || scenario.missing_bindings || [];
    const sourceEvidence = evidence_ids || [];
    const canCopy = scenario.status === "VALIDATED"
      && scenario.applicability === "APPLICABLE"
      && bindings.length === 0
      && sourceEvidence.length > 0;
    const constraints = scenario.constraint_ids || [];

    return `
      <article class="scenario-card">
        <div class="scenario-card-header">
          <div class="scenario-header-left">
            <div class="scenario-badge-row">
              <span class="badge badge-tech-type">${html(scenario.scenario_type)}</span>
              ${(scenario.technique_ids || []).map(t => `<span class="badge badge-tech-item">${html(t.replace("TECH-", ""))}</span>`).join("")}
              <span class="badge-weakness-tag">${html((scenario.weakness_ids || []).join(", "))}</span>
            </div>
            <h3 class="scenario-card-title">${html(title)}</h3>
            <div class="scenario-meta-line">
              <span class="scenario-id-text mono">${html(scenario.scenario_id)}</span>
              ${scenario.confidence ? `<span class="scenario-conf-text">Điểm xếp hạng: <strong>${scenario.confidence.final.toFixed(2)}</strong> · ${sourceEvidence.length ? `Nguồn CWE: ${sourceEvidence.length}` : "Chưa có nguồn CWE"}</span>` : ""}
            </div>
          </div>
          <div class="scenario-header-right">
            ${chip(scenario.status)}
            ${chip(scenario.applicability)}
          </div>
        </div>

        ${desc ? `<p class="scenario-desc">${html(desc)}</p>` : ""}

        ${steps && steps.length ? `
          <div class="scenario-block">
            <div class="scenario-block-title">📋 Quy Trình Thực Thi Từng Bước:</div>
            <ol class="scenario-steps-list">
              ${steps.map(step => `<li>${html(step)}</li>`).join("")}
            </ol>
          </div>
        ` : ""}

        ${poc ? `
          <div class="scenario-block poc-box">
            <div class="poc-header">
              <span class="scenario-block-title">${canCopy ? "⚡ Lệnh kiểm thử đã xác minh:" : "⚠️ Mẫu lệnh tham khảo · chưa xác minh trên đích:"}</span>
              ${canCopy ? `<button class="btn-copy-poc" type="button" onclick="copyPoc(this)">📋 Sao Chép Lệnh</button>` : ""}
            </div>
            <pre class="poc-pre"><code class="poc-code">${html(poc)}</code></pre>
          </div>
        ` : ""}

        <div class="scenario-footer">
          <div class="footer-group">
            <span class="footer-label">🎯 Tham Số Đã Bóc Tách & Cần Thiết Lập:</span>
            <div class="tag-cloud">
              ${bindings.map(formatMissingBinding).join("")}
            </div>
          </div>

          ${constraints.length ? `
            <div class="footer-group">
              <span class="footer-label">🔒 Điều Kiện Khả Dụng (Prerequisites):</span>
              <div class="tag-cloud">
                ${constraints.map(c => `<span class="badge-constraint-item">${html(CONSTRAINT_LABELS[c] || c)}</span>`).join("")}
              </div>
            </div>
          ` : ""}
        </div>
      </article>
    `;
  }).join("");
}

function renderConstraints(data) {
  const richScenarios = (data.scenarios || []).filter(item => item.scenario.steps && item.scenario.steps.length > 0);
  const sourceScenarios = richScenarios.length > 0 ? richScenarios : (data.scenarios || []);
  let constraints = [...new Set(sourceScenarios.flatMap(({scenario}) => scenario.constraint_ids || []))];
  const hasAuth = constraints.includes("CONSTRAINT-AUTHENTICATED-SESSION") || constraints.includes("CONSTRAINT-ADMIN-PRIVILEGE");
  if (hasAuth) {
    constraints = constraints.filter(c => c !== "CONSTRAINT-UNAUTHENTICATED-ACCESS");
  }
  if (!constraints.length) {
    $("#constraints").innerHTML = "<p style='color: var(--text-dim);'>Không có ràng buộc môi trường bắt buộc.</p>";
    return;
  }
  $("#constraints").innerHTML = `
    <p style="margin-bottom: 0.8rem; font-size: 0.85rem; color: var(--text-muted);">
      ${chip("UNKNOWN")} Cần môi trường mục tiêu thỏa mãn các điều kiện sau để thực thi:
    </p>
    <ul class="constraint-custom-list">
      ${constraints.map(id => `
        <li class="constraint-custom-item">
          <div class="constraint-friendly-name">${html(CONSTRAINT_LABELS[id] || id)}</div>
          <div class="constraint-meta-id mono">${html(id)}</div>
        </li>
      `).join("")}
    </ul>
  `;
}

/* ==================== SUBGRAPH CANVAS VISUALIZATION ==================== */
function getNodeColor(label) {
  switch (label) {
    case "CVE": case "GHSA": return "#f43f5e";
    case "CWE": return "#10b981";
    case "Technique": return "#0ea5e9";
    case "WeaknessAssertion": return "#f59e0b";
    case "Constraint": case "ApplicabilityConstraint": return "#a855f7";
    case "Context": case "Language": case "Component": return "#ec4899";
    default: return "#64748b";
  }
}

function initSubgraphCanvas(subgraph) {
  const canvas = $("#subgraph-canvas");
  if (!canvas) return;
  const rect = canvas.parentElement.getBoundingClientRect();
  if (rect.width > 0) {
    canvas.width = rect.width;
    canvas.height = rect.height;
  }

  const rawNodes = (subgraph && subgraph.nodes) || [];
  const rawEdges = (subgraph && subgraph.edges) || [];

  $("#graph-stats").textContent = `${rawNodes.length} Nodes · ${rawEdges.length} Edges`;

  if (rawNodes.length === 0) {
    currentGraph = { nodes: [], edges: [] };
    drawGraph();
    return;
  }

  const nodes = rawNodes.map((n) => ({
    id: n.id,
    label: n.label,
    name: n.props.name || n.props.title || n.props.cwe_id || n.id,
    color: getNodeColor(n.label),
    x: 0,
    y: 0,
    radius: (n.id === subgraph.root_id) ? 22 : 14,
    isRoot: (n.id === subgraph.root_id)
  }));

  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;

  const otherNodes = nodes.filter(n => !n.isRoot);
  const ring1 = otherNodes.slice(0, 8);
  const ring2 = otherNodes.slice(8);

  nodes.forEach(n => {
    if (n.isRoot) {
      n.x = centerX;
      n.y = centerY;
    }
  });

  ring1.forEach((n, i) => {
    const angle = (i / Math.max(1, ring1.length)) * Math.PI * 2;
    n.x = centerX + Math.cos(angle) * 115;
    n.y = centerY + Math.sin(angle) * 115;
  });

  ring2.forEach((n, i) => {
    const angle = (i / Math.max(1, ring2.length)) * Math.PI * 2;
    n.x = centerX + Math.cos(angle) * 180;
    n.y = centerY + Math.sin(angle) * 180;
  });

  const edges = subgraph.edges.map(e => ({
    source: nodeMap.get(e.source || e.subject_id),
    target: nodeMap.get(e.target || e.object_id),
    type: e.type || e.edge_type || "RELATES_TO"
  })).filter(e => e.source && e.target);

  currentGraph = { nodes, edges };
  graphState.panX = 0;
  graphState.panY = 0;
  graphState.zoom = 1;

  drawGraph();
}

function drawGraph() {
  const canvas = $("#subgraph-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  // Deep space background
  ctx.fillStyle = "#090e17";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Subtle coordinate grid dots
  ctx.fillStyle = "rgba(56, 189, 248, 0.08)";
  const gridSize = 28;
  for (let x = (canvas.width / 2 + graphState.panX) % gridSize; x < canvas.width; x += gridSize) {
    for (let y = (canvas.height / 2 + graphState.panY) % gridSize; y < canvas.height; y += gridSize) {
      ctx.beginPath();
      ctx.arc(x, y, 1, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  if (currentGraph.nodes.length === 0) {
    ctx.font = "500 13px Inter, sans-serif";
    ctx.fillStyle = "rgba(148, 163, 184, 0.45)";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("Đồ thị trống. Nhập mã CVE hoặc chọn mẫu nhanh bên trên.", canvas.width / 2, canvas.height / 2);
    return;
  }

  ctx.save();
  ctx.translate(canvas.width / 2 + graphState.panX, canvas.height / 2 + graphState.panY);
  ctx.scale(graphState.zoom, graphState.zoom);
  ctx.translate(-canvas.width / 2, -canvas.height / 2);

  // Draw edges
  currentGraph.edges.forEach(edge => {
    ctx.strokeStyle = "rgba(148, 163, 184, 0.28)";
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(edge.source.x, edge.source.y);
    ctx.lineTo(edge.target.x, edge.target.y);
    ctx.stroke();

    // Directional arrow head
    const angle = Math.atan2(edge.target.y - edge.source.y, edge.target.x - edge.source.x);
    const arrowDist = edge.target.radius + 6;
    const arrowX = edge.target.x - Math.cos(angle) * arrowDist;
    const arrowY = edge.target.y - Math.sin(angle) * arrowDist;
    ctx.fillStyle = "rgba(56, 189, 248, 0.6)";
    ctx.beginPath();
    ctx.moveTo(arrowX, arrowY);
    ctx.lineTo(arrowX - 7 * Math.cos(angle - Math.PI / 6), arrowY - 7 * Math.sin(angle - Math.PI / 6));
    ctx.lineTo(arrowX - 7 * Math.cos(angle + Math.PI / 6), arrowY - 7 * Math.sin(angle + Math.PI / 6));
    ctx.closePath();
    ctx.fill();

    // Edge label pill
    const midX = (edge.source.x + edge.target.x) / 2;
    const midY = (edge.source.y + edge.target.y) / 2;
    ctx.font = "8px 'JetBrains Mono', monospace";
    const textWidth = ctx.measureText(edge.type).width;
    ctx.fillStyle = "rgba(9, 14, 23, 0.85)";
    ctx.fillRect(midX - textWidth / 2 - 4, midY - 6, textWidth + 8, 12);
    ctx.strokeStyle = "rgba(56, 189, 248, 0.2)";
    ctx.strokeRect(midX - textWidth / 2 - 4, midY - 6, textWidth + 8, 12);
    ctx.fillStyle = "#94a3b8";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(edge.type, midX, midY);
  });

  // Draw nodes
  currentGraph.nodes.forEach(node => {
    // Outer radiant glow
    const glow = ctx.createRadialGradient(node.x, node.y, node.radius * 0.7, node.x, node.y, node.radius * 2.2);
    glow.addColorStop(0, node.color + "55");
    glow.addColorStop(1, "transparent");
    ctx.fillStyle = glow;
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.radius * 2.2, 0, Math.PI * 2);
    ctx.fill();

    // Main Circle
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
    ctx.fillStyle = node.color;
    ctx.fill();
    ctx.lineWidth = node.isRoot ? 3 : 1.8;
    ctx.strokeStyle = "#ffffff";
    ctx.stroke();

    // Node label text
    ctx.fillStyle = "#f8fafc";
    ctx.font = node.isRoot ? "600 11px 'JetBrains Mono', monospace" : "500 10px 'Inter', sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    const label = node.name.length > 20 ? node.name.substring(0, 18) + "…" : node.name;
    
    // Tiny background pill for label text
    const labelWidth = ctx.measureText(label).width;
    ctx.fillStyle = "rgba(8, 12, 20, 0.8)";
    ctx.fillRect(node.x - labelWidth / 2 - 3, node.y + node.radius + 4, labelWidth + 6, 14);
    ctx.fillStyle = "#ffffff";
    ctx.fillText(label, node.x, node.y + node.radius + 5);
  });

  ctx.restore();
}

// Canvas interactions: Zoom & Pan
const canvas = $("#subgraph-canvas");
if (canvas) {
  canvas.addEventListener("mousedown", (e) => {
    graphState.isDragging = true;
    graphState.startX = e.clientX - graphState.panX;
    graphState.startY = e.clientY - graphState.panY;
  });
  window.addEventListener("mousemove", (e) => {
    if (graphState.isDragging) {
      graphState.panX = e.clientX - graphState.startX;
      graphState.panY = e.clientY - graphState.startY;
      drawGraph();
    }
  });
  window.addEventListener("mouseup", () => { graphState.isDragging = false; });
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.15 : 0.85;
    graphState.zoom = Math.max(0.4, Math.min(3.0, graphState.zoom * factor));
    drawGraph();
  }, { passive: false });
}

$("#btn-zoom-in")?.addEventListener("click", () => { graphState.zoom = Math.min(3.0, graphState.zoom * 1.25); drawGraph(); });
$("#btn-zoom-out")?.addEventListener("click", () => { graphState.zoom = Math.max(0.4, graphState.zoom / 1.25); drawGraph(); });
$("#btn-reset-graph")?.addEventListener("click", () => { graphState.zoom = 1; graphState.panX = 0; graphState.panY = 0; drawGraph(); });

/* ==================== CASE LOADING ==================== */
async function openCase(identifier) {
  $("#notice").className = "notice";
  $("#notice").textContent = `Đang tải đồ thị cho ${identifier}…`;
  try {
    const encoded = encodeURIComponent(identifier);
    await backendInfoPromise;
    let caseFile;
    try {
      caseFile = await fetchJson(`/cves/${encoded}`);
    } catch (_) {
      throw new Error(`Không tìm thấy case file cho '${identifier}'. Bạn có thể bấm nút 'Nạp Lỗ Hổng' ở trên để thêm vào đồ thị.`);
    }
    renderCase(caseFile);

    // Resolve the primary identity before starting graph-expensive secondary
    // queries. A missing CVE must fail immediately instead of leaving the UI
    // waiting for unrelated neighborhood/scenario traversals.
    const resources = await Promise.allSettled([
      fetchJson(`/cves/${encoded}/historical-neighbors`),
      fetchJson(`/cves/${encoded}/scenarios`),
      fetchJson(`/cves/${encoded}/subgraph`),
      fetchJson(`/cves/${encoded}/payloads?limit=50&offset=0`),
    ]);

    const failures = [];
    if (resources[0].status === "fulfilled") {
      renderNeighbors(resources[0].value);
    } else {
      renderNeighbors({ neighbors: [] });
      failures.push("historical neighbors");
    }
    if (resources[1].status === "fulfilled") {
      const scenarioData = resources[1].value;
      renderScenarios(scenarioData);
      renderConstraints(scenarioData);
    } else {
      $("#scenarios").innerHTML = "<p style='color: var(--text-dim);'>Không tải được scenarios.</p>";
      $("#constraints").innerHTML = "Không tải được constraints.";
      failures.push("scenarios");
    }
    if (resources[2].status === "fulfilled") {
      initSubgraphCanvas(resources[2].value);
    } else {
      initSubgraphCanvas({ nodes: [], edges: [] });
      failures.push("subgraph");
    }
    if (resources[3].status === "fulfilled") {
      renderPattPayloads(resources[3].value);
    } else {
      renderPattPayloads({ payloads: [] });
      failures.push("PATT references");
    }

    $("#notice").className = failures.length ? "notice warning" : "notice success";
    $("#notice").textContent = failures.length
      ? `Case file loaded: ${identifier}. Backend: ${backendLabel()}. Partial load: ${failures.join(", ")}.`
      : `Case file loaded: ${identifier}. Backend: ${backendLabel()}.`;
  } catch (error) {
    $("#notice").className = "notice error";
    $("#notice").textContent = error.message;
  }
}

$("#case-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const cve = $("#cve-id").value.trim();
  if (!cve) {
    initEmptyState();
    return;
  }
  openCase(cve);
});

function renderTechnologyResults(data, nvdNotice = "") {
  const results = data.cves || [];
  const target = $("#technology-results");
  if (!target) return;
  if (!results.length) {
    target.innerHTML = `${nvdNotice}<div class='technology-empty'>Không tìm thấy CVE phù hợp trong khoảng năm đã chọn.</div>`;
    return;
  }
  const totalLabel = data.total == null ? `${data.returned || results.length}+` : data.total;
  const truncationNotice = data.truncated
    ? `<div class="technology-empty">Kết quả đang bị giới hạn bởi kích thước snapshot; hãy thu hẹp khoảng năm hoặc từ khóa.</div>`
    : "";
  target.innerHTML = `
    ${nvdNotice}
    <div class="technology-results-header">${html(totalLabel)} kết quả công nghệ → CVE</div>
    ${truncationNotice}
    <div class="technology-results-grid">
      ${results.map(item => `
        <button type="button" class="technology-result" data-cve-result="${html(item.id)}">
          <span class="technology-result-id">${html(item.id)}</span>
          <span class="technology-result-title">${html(item.title || "Không có tiêu đề")}</span>
          <span class="technology-result-meta">${html(item.published_year || "?")} · ${(item.affected_products || []).map(product => html(product.name || product.package_name || "product")).join(", ")}</span>
        </button>
      `).join("")}
    </div>
  `;
  target.querySelectorAll("[data-cve-result]").forEach(button => {
    button.addEventListener("click", () => {
      const identifier = button.dataset.cveResult;
      $("#cve-id").value = identifier;
      openCase(identifier);
    });
  });
}

$("#technology-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const technology = $("#technology-name").value.trim();
  if (!technology) return;
  const fromYear = $("#technology-from-year").value;
  const toYear = $("#technology-to-year").value;
  const refresh = $("#technology-refresh").checked;
  const resultBox = $("#technology-results");
  const submitButton = event.currentTarget.querySelector("button[type='submit']");
  const originalButtonLabel = submitButton?.textContent;
  if (submitButton) {
    submitButton.disabled = true;
    submitButton.textContent = refresh ? "Đang nạp từ NVD…" : "Đang tra cứu…";
  }
  resultBox.innerHTML = refresh
    ? "<div class='technology-empty'>Đang phân giải CPE trên NVD và nạp CVE; truy vấn này có thể mất thêm thời gian…</div>"
    : "<div class='technology-empty'>Đang tra cứu…</div>";
  let nvdNotice = "";
  try {
    const request = { technology };
    if (fromYear) request.from_year = Number(fromYear);
    if (toYear) request.to_year = Number(toYear);
    if (refresh) {
      const ingest = await fetch("/ingest/cves/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request)
      });
      const ingestData = await ingest.json();
      if (!ingest.ok) throw new Error(ingestData.error || "Không thể tải dữ liệu NVD");
      if (ingestData.status === "NO_CPE_MATCH") {
        resultBox.innerHTML = "<div class='technology-empty'>NVD không tìm thấy CPE sản phẩm phù hợp với tên công nghệ này; graph không bị thay đổi. Hãy thử tên vendor/sản phẩm khác hoặc nhập CPE chính xác qua API.</div>";
        return;
      }
      if (ingestData.status === "CPE_RESOLUTION_INCOMPLETE") {
        resultBox.innerHTML = "<div class='technology-empty error'>NVD trả về quá nhiều CPE ứng viên và giới hạn tra cứu đã đạt trước khi tìm thấy sản phẩm phù hợp; chưa nạp dữ liệu vào graph. Hãy dùng tên sản phẩm cụ thể hơn.</div>";
        return;
      }
      const cpeFamilies = ingestData.cpe_families || [];
      const visibleFamilies = cpeFamilies.slice(0, 5).map(name => html(name)).join(", ");
      const remainingFamilies = cpeFamilies.length > 5 ? `, +${cpeFamilies.length - 5} nhóm` : "";
      const warnings = [];
      if (ingestData.cpe_candidates_truncated) warnings.push("danh sách CPE ứng viên đã bị giới hạn");
      if (ingestData.truncated) warnings.push("số CVE được lấy đã chạm giới hạn");
      nvdNotice = `<div class="technology-empty">NVD đã tra ${html(cpeFamilies.length)} nhóm CPE${visibleFamilies ? ` (${visibleFamilies}${remainingFamilies})` : ""}.${warnings.length ? ` Kết quả chưa đầy đủ: ${html(warnings.join("; "))}.` : ""}</div>`;
    }
    const query = new URLSearchParams({ technology });
    if (fromYear) query.set("from_year", fromYear);
    if (toYear) query.set("to_year", toYear);
    const response = await fetch(`/cves?${query.toString()}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Tra cứu CVE thất bại");
    renderTechnologyResults(data, nvdNotice);
  } catch (error) {
    resultBox.innerHTML = `<div class="technology-empty error">${html(error.message)}</div>`;
  } finally {
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.textContent = originalButtonLabel;
    }
  }
});

/* ==================== INGEST MODAL & TABS ==================== */
const modal = $("#ingest-modal");
const modalStatus = $("#modal-status");

function showModalStatus(msg, isSuccess = false) {
  modalStatus.style.display = "block";
  modalStatus.style.backgroundColor = isSuccess ? "rgba(16, 185, 129, 0.12)" : "rgba(244, 63, 94, 0.12)";
  modalStatus.style.color = isSuccess ? "#6ee7b7" : "#fca5a5";
  modalStatus.style.border = `1px solid ${isSuccess ? "#10b981" : "#f43f5e"}`;
  modalStatus.innerHTML = msg;
}

$("#btn-open-ingest")?.addEventListener("click", () => {
  modal.classList.add("active");
  modalStatus.style.display = "none";
});

$("#btn-close-modal")?.addEventListener("click", () => { modal.classList.remove("active"); });
$("#btn-cancel-online")?.addEventListener("click", () => { modal.classList.remove("active"); });
$("#btn-cancel-manual")?.addEventListener("click", () => { modal.classList.remove("active"); });

// Tabs switching
$("#tab-btn-online")?.addEventListener("click", () => {
  $("#tab-btn-online").classList.add("active");
  $("#tab-btn-manual").classList.remove("active");
  $("#tab-online").classList.add("active");
  $("#tab-manual").classList.remove("active");
});
$("#tab-btn-manual")?.addEventListener("click", () => {
  $("#tab-btn-manual").classList.add("active");
  $("#tab-btn-online").classList.remove("active");
  $("#tab-manual").classList.add("active");
  $("#tab-online").classList.remove("active");
});

// Manual mode radio switching (Form vs Raw JSON)
document.querySelectorAll('input[name="manual-mode"]').forEach(radio => {
  radio.addEventListener("change", (e) => {
    if (e.target.value === "form") {
      $("#manual-form-inputs").style.display = "block";
      $("#manual-json-inputs").style.display = "none";
    } else {
      $("#manual-form-inputs").style.display = "none";
      $("#manual-json-inputs").style.display = "block";
    }
  });
});

// Submit Form Online (Cách 1)
$("#form-ingest-online")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const cveId = $("#online-cve-id").value.trim().toUpperCase();
  const sourceKind = $("#online-source").value;
  const submitBtn = $("#btn-submit-online");

  submitBtn.disabled = true;
  submitBtn.textContent = "⏳ Đang tải từ MITRE/NVD...";
  showModalStatus(`Đang kết nối API nguồn để tải bản ghi cho <strong>${cveId}</strong>...`);

  try {
    const res = await fetch(`/ingest/cve/${encodeURIComponent(cveId)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source_kind: sourceKind, use_model: false })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Nạp dữ liệu thất bại từ API nguồn");

    await backendInfoPromise;
    showModalStatus(`✅ Đã nạp thành công vào ${html(backendLabel())}! Snapshot: <code>${data.snapshot_digest?.substring(0, 18)}...</code>`, true);
    setTimeout(() => {
      modal.classList.remove("active");
      submitBtn.disabled = false;
      submitBtn.textContent = "📥 Tải & Nạp Vào Đồ Thị";
      $("#cve-id").value = cveId;
      openCase(cveId);
    }, 1200);
  } catch (err) {
    showModalStatus(`❌ Lỗi: ${err.message}`);
    submitBtn.disabled = false;
    submitBtn.textContent = "📥 Tải & Nạp Vào Đồ Thị";
  }
});

document.querySelectorAll(".cwe-pill-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const input = $("#manual-cwe");
    if (input) input.value = btn.dataset.cwe;
  });
});

// Submit Form Manual / JSON (Cách 2)
$("#form-ingest-manual")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const mode = document.querySelector('input[name="manual-mode"]:checked').value;
  const submitBtn = $("#btn-submit-manual");

  let cveId = "";
  let payloadBody = {};

  if (mode === "form") {
    cveId = $("#manual-cve-id").value.trim().toUpperCase();
    const title = $("#manual-title").value.trim();
    const desc = $("#manual-desc").value.trim();
    const cwe = $("#manual-cwe").value.trim();

    payloadBody = {
      cveId: cveId,
      title: title,
      description: desc,
      cweId: cwe || undefined
    };
  } else {
    try {
      const rawJson = JSON.parse($("#manual-json-text").value.trim());
      cveId = rawJson.cveId || rawJson.id || (rawJson.cveMetadata && rawJson.cveMetadata.cveId);
      if (!cveId) throw new Error("JSON phải chứa trường 'cveId' hoặc 'cveMetadata.cveId'");
      payloadBody = rawJson;
    } catch (parseErr) {
      showModalStatus(`❌ Lỗi cú pháp JSON: ${parseErr.message}`);
      return;
    }
  }

  submitBtn.disabled = true;
  submitBtn.textContent = "⏳ Đang nạp vào đồ thị...";
  showModalStatus(`Đang chuẩn hóa và ghi vào ${html(backendLabel())} cho <strong>${cveId}</strong>...`);

  try {
    const res = await fetch(`/ingest/cve/${encodeURIComponent(cveId)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payloadBody)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Nạp dữ liệu thất bại");

    await backendInfoPromise;
    showModalStatus(`✅ Nạp thành công vào ${html(backendLabel())}! Mã lỗ hổng: <strong>${cveId}</strong>`, true);
    setTimeout(() => {
      modal.classList.remove("active");
      submitBtn.disabled = false;
      submitBtn.textContent = "⚡ Nạp Vào Đồ Thị";
      $("#cve-id").value = cveId;
      openCase(cveId);
    }, 1200);
  } catch (err) {
    showModalStatus(`❌ Lỗi: ${err.message}`);
    submitBtn.disabled = false;
    submitBtn.textContent = "⚡ Nạp Vào Đồ Thị";
  }
});

// Quick sample chip buttons
document.querySelectorAll(".chip-item").forEach(btn => {
  btn.addEventListener("click", () => {
    const cve = btn.dataset.cve;
    if (cve) {
      $("#cve-id").value = cve;
      openCase(cve);
    }
  });
});

function initEmptyState() {
  currentCveId = "";
  const input = $("#cve-id");
  if (input) {
    input.value = "";
    input.defaultValue = "";
  }
  $("#case-summary").classList.add("empty");
  $("#case-summary").innerHTML = "Chưa chọn lỗ hổng nào. Hãy nhập mã CVE hoặc chọn mẫu nhanh bên trên để khám phá đồ thị.";
  $("#assertions").innerHTML = "";
  $("#neighbors").innerHTML = "<li>Chưa có dữ liệu. Vui lòng chọn một lỗ hổng.</li>";
  $("#scenarios").innerHTML = "<p style='color: var(--text-dim);'>Chưa có kịch bản nào. Vui lòng chọn một lỗ hổng.</p>";
  renderPattPayloads({ payloads: [] });
  $("#constraints").innerHTML = "Không có ràng buộc.";
  $("#notice").className = "notice";
  $("#notice").textContent = "Sẵn sàng tra cứu dữ liệu đồ thị.";
  initSubgraphCanvas({ nodes: [], edges: [] });
}

function isSupportedCaseId(value) {
  return /^(?:CVE|GHSA)-[0-9A-Z]+(?:-[0-9A-Z]+)*$/i.test(value || "");
}

// Initial open case: support direct links to any canonical CVE/GHSA identity.
const urlParams = new URLSearchParams(window.location.search);
const initialCase = urlParams.get("cve");
if (initialCase && isSupportedCaseId(initialCase)) {
  $("#cve-id").value = initialCase;
  openCase(initialCase);
} else {
  // If there was an invalid ?cve= in the address bar from a previous visit, wipe it clean.
  if (window.location.search) {
    window.history.replaceState({}, "", window.location.pathname);
  }
  initEmptyState();
  setTimeout(initEmptyState, 50);
}

window.addEventListener("pageshow", () => {
  const params = new URLSearchParams(window.location.search);
  const cur = params.get("cve");
  if (!cur || !isSupportedCaseId(cur)) {
    if (!currentCveId) {
      initEmptyState();
    }
  }
});
