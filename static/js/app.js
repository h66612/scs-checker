// SCS Checker - Home Page JavaScript (v4.1 - Dramatic Premium UI)
// Handles: text input, file upload, manual input, quick check, scan start, progress polling
// Features: enhanced particle network, animated counters, threat level, typing effect, ticker

let manualPackages = [];
let uploadedFile = null;

// === Enhanced Particle Network Background ===
(function initParticles() {
    var canvas = document.getElementById('particleCanvas');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var particles = [];
    var mouse = { x: null, y: null, radius: 150 };

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    window.addEventListener('mousemove', function(e) {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
    });
    window.addEventListener('mouseout', function() {
        mouse.x = null;
        mouse.y = null;
    });

    var colors = [
        'rgba(59, 130, 246, 0.8)',
        'rgba(139, 92, 246, 0.7)',
        'rgba(6, 182, 212, 0.7)',
        'rgba(16, 185, 129, 0.6)',
        'rgba(236, 72, 153, 0.5)'
    ];

    function createParticles() {
        particles = [];
        var count = Math.min(Math.floor((canvas.width * canvas.height) / 12000), 120);
        for (var i = 0; i < count; i++) {
            particles.push({
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                vx: (Math.random() - 0.5) * 0.5,
                vy: (Math.random() - 0.5) * 0.5,
                r: Math.random() * 2.5 + 1,
                color: colors[Math.floor(Math.random() * colors.length)],
                pulse: Math.random() * Math.PI * 2,
                pulseSpeed: 0.01 + Math.random() * 0.02
            });
        }
    }
    createParticles();

    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (var i = 0; i < particles.length; i++) {
            var p = particles[i];
            p.x += p.vx;
            p.y += p.vy;
            p.pulse += p.pulseSpeed;

            if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
            if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

            // Mouse interaction - gentle push
            if (mouse.x !== null) {
                var dx = p.x - mouse.x, dy = p.y - mouse.y;
                var dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < mouse.radius) {
                    var force = (mouse.radius - dist) / mouse.radius * 0.02;
                    p.vx += dx * force;
                    p.vy += dy * force;
                }
            }

            // Speed damping
            p.vx *= 0.999;
            p.vy *= 0.999;

            // Pulsing glow
            var glow = Math.sin(p.pulse) * 0.3 + 0.7;
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r * glow * 1.5, 0, Math.PI * 2);
            ctx.fillStyle = p.color.replace(/[\d.]+\)$/, (0.15 * glow) + ')');
            ctx.fill();

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r * glow, 0, Math.PI * 2);
            ctx.fillStyle = p.color;
            ctx.fill();

            // Connection lines
            for (var j = i + 1; j < particles.length; j++) {
                var q = particles[j];
                var cdx = p.x - q.x, cdy = p.y - q.y;
                var cdist = Math.sqrt(cdx * cdx + cdy * cdy);
                if (cdist < 180) {
                    var alpha = 0.2 * (1 - cdist / 180);
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(q.x, q.y);
                    ctx.strokeStyle = 'rgba(59, 130, 246,' + alpha + ')';
                    ctx.lineWidth = 0.8;
                    ctx.stroke();
                }
            }

            // Mouse connection lines
            if (mouse.x !== null) {
                var mdx = p.x - mouse.x, mdy = p.y - mouse.y;
                var mdist = Math.sqrt(mdx * mdx + mdy * mdy);
                if (mdist < mouse.radius) {
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(mouse.x, mouse.y);
                    ctx.strokeStyle = 'rgba(139, 92, 246,' + (0.3 * (1 - mdist / mouse.radius)) + ')';
                    ctx.lineWidth = 0.6;
                    ctx.stroke();
                }
            }
        }
        requestAnimationFrame(draw);
    }
    draw();
})();

// === Typing Effect on Hero Title ===
(function initTyping() {
    var el = document.getElementById('heroTitle');
    if (!el) return;
    var text = el.textContent.trim();
    el.textContent = '';
    el.classList.add('typing-cursor');
    var i = 0;
    function type() {
        if (i < text.length) {
            el.textContent += text.charAt(i);
            i++;
            setTimeout(type, 60 + Math.random() * 40);
        } else {
            setTimeout(function() { el.classList.remove('typing-cursor'); }, 2000);
        }
    }
    setTimeout(type, 500);
})();

// === Update System Time ===
(function updateTime() {
    var el = document.getElementById('lastUpdateTime');
    if (!el) return;
    function tick() {
        var now = new Date();
        var h = String(now.getHours()).padStart(2, '0');
        var m = String(now.getMinutes()).padStart(2, '0');
        el.textContent = h + ':' + m;
    }
    tick();
    setInterval(tick, 60000);
})();

// === Animated Counter ===
function animateCounter(el, target, duration) {
    if (!el) return;
    const start = parseInt(el.textContent) || 0;
    if (start === target) return;
    const range = target - start;
    const startTime = performance.now();
    duration = duration || 800;

    function step(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        el.textContent = Math.round(start + range * ease);
        el.setAttribute('data-count', el.textContent);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// === Threat Level Update ===
function updateThreatMeter(vulns, critical) {
    const dots = document.querySelectorAll('#threatMeter .threat-dot');
    const label = document.getElementById('threatLabel');
    if (!dots.length) return;

    let level = 0;
    let levelClass = 'safe';
    let text = '安全';

    if (critical > 0) { level = Math.min(critical + 6, 10); levelClass = 'critical'; text = '严重'; }
    else if (vulns > 10) { level = 8; levelClass = 'high'; text = '高危'; }
    else if (vulns > 5) { level = 6; levelClass = 'high'; text = '较高'; }
    else if (vulns > 2) { level = 4; levelClass = 'medium'; text = '中等'; }
    else if (vulns > 0) { level = 2; levelClass = 'low'; text = '低危'; }

    dots.forEach(function(dot, i) {
        dot.className = 'threat-dot';
        if (i < level) dot.classList.add('active', levelClass);
    });
    if (label) { label.textContent = text; label.className = 'risk-' + levelClass; }
}

document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('statScans')) loadStats();

    const btnScan = document.getElementById('btnScan');
    if (!btnScan) return;

    // Main scan button
    btnScan.addEventListener('click', startScan);

    // Sample buttons
    const btnVuln = document.getElementById('btnSampleVuln');
    const btnSafe = document.getElementById('btnSampleSafe');
    const btnPkg = document.getElementById('btnSamplePkg');
    const btnClear = document.getElementById('btnClear');
    if (btnVuln) btnVuln.addEventListener('click', function() { loadSample('vulnerable'); });
    if (btnSafe) btnSafe.addEventListener('click', function() { loadSample('safe'); });
    if (btnPkg) btnPkg.addEventListener('click', function() { loadSample('npm'); });
    if (btnClear) btnClear.addEventListener('click', function() { document.getElementById('reqInput').value = ''; });

    // File upload
    const fileInput = document.getElementById('fileInput');
    if (fileInput) fileInput.addEventListener('change', handleFileSelect);

    const uploadZone = document.getElementById('uploadZone');
    if (uploadZone) {
        uploadZone.addEventListener('dragover', function(e) { e.preventDefault(); uploadZone.classList.add('drag-over'); });
        uploadZone.addEventListener('dragleave', function() { uploadZone.classList.remove('drag-over'); });
        uploadZone.addEventListener('drop', function(e) {
            e.preventDefault();
            uploadZone.classList.remove('drag-over');
            if (e.dataTransfer.files.length > 0) {
                document.getElementById('fileInput').files = e.dataTransfer.files;
                handleFileSelect({ target: { files: e.dataTransfer.files } });
            }
        });
    }

    // Manual input
    const btnAddPkg = document.getElementById('btnAddPkg');
    if (btnAddPkg) btnAddPkg.addEventListener('click', addManualPackage);
    const btnClearManual = document.getElementById('btnClearManual');
    if (btnClearManual) btnClearManual.addEventListener('click', function() {
        manualPackages = [];
        renderManualTable();
    });

    // Quick check
    const btnQuick = document.getElementById('btnQuickCheck');
    if (btnQuick) btnQuick.addEventListener('click', quickCheck);

    // Load supported formats
    loadFormats();

    // Auto-detect format on text input
    const reqInput = document.getElementById('reqInput');
    if (reqInput) {
        let detectTimer;
        reqInput.addEventListener('input', function() {
            clearTimeout(detectTimer);
            detectTimer = setTimeout(detectFormat, 500);
        });
    }
});

// === Load Stats ===
function loadStats() {
    fetch('/api/stats')
        .then(r => r.json())
        .then(data => {
            const scans = data.total_scans || 0;
            const packages = data.total_packages || 0;
            const vulns = data.total_vulns || 0;
            const critical = data.total_critical || 0;

            animateCounter(document.getElementById('statScans'), scans);
            animateCounter(document.getElementById('statPackages'), packages);
            animateCounter(document.getElementById('statVulns'), vulns);
            animateCounter(document.getElementById('statCritical'), critical);

            updateThreatMeter(vulns, critical);
        })
        .catch(err => console.error('Stats error:', err));
}

// === Load Supported Formats ===
function loadFormats() {
    fetch('/api/formats')
        .then(r => r.json())
        .then(data => {
            // Populate format select dropdown
            const select = document.getElementById('formatSelect');
            if (select) {
                for (const eco in data.formats) {
                    const group = document.createElement('optgroup');
                    group.label = eco;
                    for (const fmt of data.formats[eco]) {
                        const opt = document.createElement('option');
                        opt.value = fmt.id;
                        opt.textContent = fmt.id;
                        group.appendChild(opt);
                    }
                    select.appendChild(group);
                }
            }
            // Render formats grid
            const grid = document.getElementById('formatsGrid');
            if (grid) {
                const ecoIcons = {
                    'PyPI': 'bi-filetype-py', 'npm': 'bi-filetype-jsx', 'Maven': 'bi-filetype-java',
                    'Packagist': 'bi-filetype-php', 'RubyGems': 'bi-gem', 'Go': 'bi-braces',
                    'crates.io': 'bi-gear', 'NuGet': 'bi-filetype-cs', 'Pub': 'bi-phone',
                    'Swift': 'bi-apple', 'Hackage': 'bi-hash', 'Docker': 'bi-box',
                    'SBOM': 'bi-file-earmark-code', 'Debian': 'bi-hdd', 'Alpine': 'bi-snow'
                };
                let html = '';
                for (const eco in data.formats) {
                    const icon = ecoIcons[eco] || 'bi-box';
                    const fmtList = data.formats[eco].map(f => f.id).join(', ');
                    html += '<div class="col-md-6 col-lg-4">' +
                        '<div class="d-flex align-items-center gap-2 p-2 rounded" style="background:rgba(255,255,255,.03)">' +
                        '<i class="bi ' + icon + ' text-info" style="font-size:1.2rem"></i>' +
                        '<div><strong>' + escapeHtml(eco) + '</strong><br>' +
                        '<small class="text-muted">' + escapeHtml(fmtList) + '</small></div>' +
                        '</div></div>';
                }
                grid.innerHTML = html;
            }
        })
        .catch(err => console.error('Formats error:', err));
}

// === Format Detection ===
function detectFormat() {
    const content = document.getElementById('reqInput').value;
    const detectedEl = document.getElementById('detectedFormat');
    if (!content.trim() || !detectedEl) { detectedEl.textContent = ''; return; }

    fetch('/api/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: content, filename: 'input' })
    })
    .then(r => r.json())
    .then(data => {
        if (data.format && data.count > 0) {
            detectedEl.innerHTML = '<i class="bi bi-check-circle text-success"></i> 检测到: <strong>' + data.format + '</strong> (' + data.count + ' 个包)';
        } else {
            detectedEl.innerHTML = '<i class="bi bi-question-circle text-muted"></i> 未识别格式';
        }
    })
    .catch(() => { detectedEl.textContent = ''; });
}

// === Sample Loading ===
function loadSample(type) {
    if (type === 'npm') {
        document.getElementById('reqInput').value = JSON.stringify({
            "name": "npm-test-project",
            "version": "1.0.0",
            "dependencies": {
                "express": "4.17.1",
                "lodash": "4.17.20",
                "axios": "0.21.1",
                "jsonwebtoken": "8.5.1"
            }
        }, null, 2);
        document.getElementById('projectName').value = 'npm Test Project';
        return;
    }
    fetch('/api/sample/' + type)
        .then(r => r.json())
        .then(data => {
            document.getElementById('reqInput').value = data.content;
            document.getElementById('projectName').value = data.name;
        })
        .catch(err => {
            if (type === 'vulnerable') {
                document.getElementById('reqInput').value =
                    'flask==2.0.1\nrequests==2.25.1\nurllib3==1.26.4\njinja2==2.11.3\nnumpy==1.21.0\ncryptography==3.4.7\ndjango==3.2.0\ncertifi==2022.12.7\nsetuptools==65.5.0\npyyaml==5.4.1';
                document.getElementById('projectName').value = 'Vulnerable Test Project';
            } else {
                document.getElementById('reqInput').value =
                    'flask>=3.0.0\nrequests>=2.31.0\nnumpy>=1.26.0\ndjango>=5.0.0';
                document.getElementById('projectName').value = 'Safe Test Project';
            }
        });
}

// === File Upload ===
function handleFileSelect(e) {
    const file = e.target.files[0];
    if (!file) return;
    uploadedFile = file;

    document.getElementById('uploadFileName').textContent = file.name;
    document.getElementById('uploadFileSize').textContent = '(' + (file.size / 1024).toFixed(1) + ' KB)';
    document.getElementById('uploadInfo').classList.remove('d-none');

    // Read file content for preview
    const reader = new FileReader();
    reader.onload = function(ev) {
        const content = ev.target.result;
        // Try to detect format
        fetch('/api/parse', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: content, filename: file.name })
        })
        .then(r => r.json())
        .then(data => {
            document.getElementById('uploadFormat').textContent = data.format || 'unknown';
        })
        .catch(err => {
            var formatDisplay = document.getElementById('uploadFormat');
            if (formatDisplay) {
                formatDisplay.textContent = '检测失败';
                formatDisplay.classList.add('text-warning');
            }
            console.error('[SCS] Format detection error:', err);
        });
    };
    if (file.size < 10 * 1024 * 1024) { // < 10MB
        reader.readAsText(file);
    }
}

// === Manual Input ===
function addManualPackage() {
    const name = document.getElementById('manualPkgName').value.trim();
    const version = document.getElementById('manualPkgVersion').value.trim();
    const ecosystem = document.getElementById('manualEcosystem').value;

    if (!name) { alert('请输入包名'); return; }

    manualPackages.push({ package: name, version: version, ecosystem: ecosystem });
    renderManualTable();
    document.getElementById('manualPkgName').value = '';
    document.getElementById('manualPkgVersion').value = '';
    document.getElementById('manualPkgName').focus();
}

function renderManualTable() {
    const tbody = document.getElementById('manualTableBody');
    if (!manualPackages.length) {
        tbody.innerHTML = '<tr class="text-muted"><td colspan="4" class="text-center py-3">暂无包，请在上方添加</td></tr>';
        return;
    }
    tbody.innerHTML = manualPackages.map(function(p, i) {
        return '<tr>' +
            '<td><strong>' + escapeHtml(p.package) + '</strong></td>' +
            '<td>' + escapeHtml(p.version || '-') + '</td>' +
            '<td><span class="badge bg-secondary">' + escapeHtml(p.ecosystem) + '</span></td>' +
            '<td><button class="btn btn-sm btn-outline-danger" onclick="removeManualPkg(' + i + ')"><i class="bi bi-x"></i></button></td>' +
            '</tr>';
    }).join('');
}

window.removeManualPkg = function(idx) {
    manualPackages.splice(idx, 1);
    renderManualTable();
};

// === Quick Check ===
function quickCheck() {
    const name = document.getElementById('quickPkgName').value.trim();
    const version = document.getElementById('quickPkgVersion').value.trim();

    if (!name) { alert('请输入包名'); return; }

    const btn = document.getElementById('btnQuickCheck');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';

    fetch('/api/quick-check/' + encodeURIComponent(name) + (version ? '?version=' + encodeURIComponent(version) : ''))
        .then(r => r.json())
        .then(data => {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-search"></i> 查询';

            const resultDiv = document.getElementById('quickResult');
            const contentDiv = document.getElementById('quickResultContent');
            resultDiv.classList.remove('d-none');

            if (data.error) {
                contentDiv.innerHTML = '<div class="text-danger"><i class="bi bi-x-circle"></i> ' + escapeHtml(data.error) + '</div>';
                return;
            }

            if (data.vuln_count === 0) {
                contentDiv.innerHTML = '<div class="text-success"><i class="bi bi-check-circle-fill"></i> <strong>' +
                    escapeHtml(name) + (version ? '@' + version : '') + '</strong> 未发现已知漏洞</div>';
            } else {
                let html = '<div class="mb-2"><i class="bi bi-exclamation-triangle-fill text-warning"></i> <strong>' +
                    escapeHtml(name) + (version ? '@' + version : '') + '</strong>: 发现 ' + data.vuln_count + ' 个漏洞</div>';
                html += '<div class="table-responsive"><table class="table table-dark table-sm mb-0"><thead><tr><th>漏洞ID</th><th>严重性</th><th>摘要</th></tr></thead><tbody>';
                for (const v of data.vulnerabilities.slice(0, 10)) {
                    const sev = v.severity || 'unknown';
                    html += '<tr><td><code>' + escapeHtml(v.id) + '</code></td>' +
                        '<td><span class="badge sev-' + sev + '">' + sev.toUpperCase() + '</span></td>' +
                        '<td style="max-width:300px">' + escapeHtml((v.summary || '').substring(0, 80)) + '</td></tr>';
                }
                html += '</tbody></table></div>';
                contentDiv.innerHTML = html;
            }
        })
        .catch(err => {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-search"></i> 查询';
            alert('查询失败: ' + err.message);
        });
}

// === Start Scan ===
function startScan() {
    // Determine which tab is active
    const activeTab = document.querySelector('.tab-pane.active');
    let requestBody = {};
    const projectName = document.getElementById('projectName').value.trim() || 'Untitled Project';

    if (activeTab.id === 'tabText') {
        const content = document.getElementById('reqInput').value.trim();
        const format = document.getElementById('formatSelect').value;
        if (!content) { alert('请输入文件内容'); return; }
        requestBody = { requirements: content, project_name: projectName, filename: 'input', format: format || undefined };
    } else if (activeTab.id === 'tabUpload') {
        if (!uploadedFile) { alert('请先选择文件'); return; }
        // Use FormData for file upload
        const formData = new FormData();
        formData.append('file', uploadedFile);
        formData.append('project_name', projectName);
        return submitScan(formData, true);
    } else if (activeTab.id === 'tabManual') {
        if (!manualPackages.length) { alert('请先添加包'); return; }
        requestBody = { input_type: 'manual', packages: manualPackages, project_name: projectName };
    } else {
        alert('请切换到文件内容、上传文件或手动输入选项卡进行扫描');
        return;
    }

    submitScan(requestBody, false);
}

function submitScan(body, isFormData) {
    const btn = document.getElementById('btnScan');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> 扫描中...';

    // Reset modal
    document.getElementById('scanSpinner').classList.remove('d-none');
    document.getElementById('scanSuccessIcon').classList.add('d-none');
    document.getElementById('scanErrorIcon').classList.add('d-none');
    document.getElementById('scanResultButtons').classList.add('d-none');
    document.getElementById('scanLog').innerHTML = '';
    document.getElementById('scanProgressBar').style.width = '0%';
    document.getElementById('scanMessage').textContent = '正在初始化扫描...';

    // Show modal using Bootstrap API (getOrCreateInstance avoids duplicate instances)
    var modalEl = document.getElementById('scanModal');
    var modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    modal.show();

    const fetchOpts = { method: 'POST', body: body };
    if (!isFormData) {
        fetchOpts.headers = { 'Content-Type': 'application/json' };
        fetchOpts.body = JSON.stringify(body);
    }

    fetch('/scan', fetchOpts)
        .then(r => r.json())
        .then(data => {
            if (data.error) { showScanError(data.error); return; }
            if (data.task_id) pollScanProgress(data.task_id);
        })
        .catch(err => showScanError('网络错误: ' + err.message));
}

// === Poll Progress ===
function pollScanProgress(taskId) {
    var pollCount = 0;
    var maxPolls = 300; // 300 seconds (5 min) timeout
    var interval = setInterval(function() {
        pollCount++;
        if (pollCount > maxPolls) {
            clearInterval(interval);
            showScanError('扫描超时（5分钟），可能是PyPI API响应慢或PythonAnywhere免费版网络限制。请点击右上角X关闭，稍后重试。');
            return;
        }
        fetch('/api/scan/' + taskId + '/status')
            .then(r => r.json())
            .then(data => {
                window.pollNetworkErrors = 0;
                if (data.error) { clearInterval(interval); showScanError(data.error); return; }

                document.getElementById('scanProgressBar').style.width = (data.progress || 0) + '%';
                document.getElementById('scanMessage').textContent = data.message || '处理中...';

                if (data.status === 'completed') {
                    clearInterval(interval);
                    document.getElementById('scanProgressBar').style.width = '100%';
                    document.getElementById('scanSpinner').classList.add('d-none');
                    document.getElementById('scanSuccessIcon').classList.remove('d-none');
                    document.getElementById('scanMessage').textContent = '扫描完成！';
                    document.getElementById('scanResultButtons').classList.remove('d-none');
                    if (data.scan_id) document.getElementById('btnViewResult').href = '/result/' + data.scan_id;
                    resetScanButton();
                    loadStats();
                } else if (data.status === 'error') {
                    clearInterval(interval);
                    showScanError(data.error || '扫描失败');
                }
            })
            .catch(err => {
                console.error('[SCS] Poll error:', err);
                window.pollNetworkErrors = (window.pollNetworkErrors || 0) + 1;
                if (window.pollNetworkErrors > 5) {
                    clearInterval(interval);
                    showScanError('网络连接中断，请检查网络后重试');
                }
            });
    }, 1000);
}

function showScanError(msg) {
    document.getElementById('scanSpinner').classList.add('d-none');
    document.getElementById('scanErrorIcon').classList.remove('d-none');
    document.getElementById('scanMessage').textContent = '扫描失败: ' + msg;
    document.getElementById('scanResultButtons').classList.remove('d-none');
    document.getElementById('btnViewResult').style.display = 'none';
    resetScanButton();
}

function resetScanButton() {
    const btn = document.getElementById('btnScan');
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-search"></i> 开始安全检测';
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

// === Force close modal failsafe (called by close button onclick) ===
function forceCloseModal() {
    // Try Bootstrap API first
    try {
        var modalEl = document.getElementById('scanModal');
        var instance = bootstrap.Modal.getInstance(modalEl);
        if (instance) instance.hide();
    } catch(e) {}
    // Force hide the modal element
    var modalEl = document.getElementById('scanModal');
    if (modalEl) {
        modalEl.classList.remove('show');
        modalEl.style.display = 'none';
        modalEl.removeAttribute('aria-modal');
        modalEl.removeAttribute('role');
    }
    // Remove ALL backdrop elements
    document.querySelectorAll('.modal-backdrop').forEach(function(el) { el.remove(); });
    // Clean up body classes and styles
    document.body.classList.remove('modal-open');
    document.body.style.removeProperty('overflow');
    document.body.style.removeProperty('padding-right');
}
