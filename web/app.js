// Global State
let scanData = [];
let dbUpdateInterval = null;
let currentFilter = 'all';

// DOM Elements
const menuItems = document.querySelectorAll('.menu-item');
const tabs = document.querySelectorAll('.tab-content');
const btnScan = document.getElementById('btn-scan');
const searchInput = document.getElementById('search-input');
const filterPills = document.querySelectorAll('.filter-pills .pill');
const tableBody = document.getElementById('table-body');
const tableStatusLabel = document.getElementById('table-status-label');

// KPI elements
const statScanned = document.getElementById('stat-scanned');
const statMatched = document.getElementById('stat-matched');
const statCves = document.getElementById('stat-cves');
const statCritical = document.getElementById('stat-critical');

// Database elements
const dbTotalCpes = document.getElementById('db-total-cpes');
const dbTotalCves = document.getElementById('db-total-cves');
const btnUpdateDb = document.getElementById('btn-update-db');
const updaterBadge = document.getElementById('updater-badge');
const updaterTime = document.getElementById('updater-time');
const updaterMessage = document.getElementById('updater-message');
const updaterProgress = document.getElementById('updater-progress');

// Page texts
const pageTitleText = document.getElementById('page-title-text');
const pageSubtitleText = document.getElementById('page-subtitle-text');

// Init
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initScan();
    initFilters();
    initDatabaseUpdater();
    loadDashboardStats();
    loadScanHistory();
});

// 1. Tab Navigation
function initTabs() {
    menuItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const tabId = item.getAttribute('data-tab');
            
            // Toggle active menu class
            menuItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
            // Toggle active tab content
            tabs.forEach(tab => tab.classList.remove('active'));
            document.getElementById(`tab-${tabId}`).classList.add('active');
            
            // Update Title Texts
            updateTitleText(tabId);
        });
    });
}

function updateTitleText(tabId) {
    if (tabId === 'dashboard') {
        pageTitleText.textContent = "Dashboard";
        pageSubtitleText.textContent = "Real-time vulnerability mapping and asset auditing";
    } else if (tabId === 'history') {
        pageTitleText.textContent = "Scan History";
        pageSubtitleText.textContent = "Browse and audit historical scan logs";
    } else if (tabId === 'database') {
        pageTitleText.textContent = "NIST Dictionary Settings";
        pageSubtitleText.textContent = "Manage and sync local vulnerability reference databases";
        loadDbStats();
        checkDbUpdateStatus();
    }
}

// 2. Load Stats
async function loadDashboardStats() {
    try {
        const response = await fetch('/api/stats');
        if (response.ok) {
            const stats = await response.json();
            statScanned.textContent = stats.scanned_count;
            statMatched.textContent = stats.matched_cpes_count;
            statCves.textContent = stats.total_vulnerabilities;
            statCritical.textContent = (stats.severity_distribution.CRITICAL || 0) + (stats.severity_distribution.HIGH || 0);
            
            updateRadialProgress(stats.severity_distribution);
        }
    } catch (e) {
        console.error("Failed to load statistics", e);
    }
}

function updateRadialProgress(severities) {
    const total = (severities.CRITICAL || 0) + (severities.HIGH || 0) + (severities.MEDIUM || 0) + (severities.LOW || 0) || 1;
    
    updateCircle('radial-critical', severities.CRITICAL || 0, total);
    updateCircle('radial-high', severities.HIGH || 0, total);
    updateCircle('radial-medium', severities.MEDIUM || 0, total);
    updateCircle('radial-low', severities.LOW || 0, total);
}

function updateCircle(elementId, value, total) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const percentage = Math.round((value / total) * 100);
    el.style.setProperty('--percentage', percentage);
    el.querySelector('.radial-num').textContent = value;
}

// 3. Vulnerability Scan
function initScan() {
    btnScan.addEventListener('click', runScan);
}

async function runScan() {
    btnScan.disabled = true;
    const scanBtnText = btnScan.querySelector('span');
    const scanBtnIcon = btnScan.querySelector('i');
    
    scanBtnText.textContent = "Scanning...";
    scanBtnIcon.className = "fa-solid fa-radar fa-spin";
    
    tableBody.innerHTML = `
        <tr>
            <td colspan="7" class="text-center empty-state">
                <i class="fa-solid fa-radar fa-spin" style="color: var(--primary-color);"></i>
                <p>Auditing local registry and resolving CPE-CVE associations...</p>
            </td>
        </tr>
    `;
    
    try {
        const response = await fetch('/api/scan');
        if (response.ok) {
            scanData = await response.json();
            renderTable();
            loadDashboardStats();
            loadScanHistory();
            tableStatusLabel.textContent = `Last scan: ${new Date().toLocaleTimeString()}`;
        } else {
            throw new Error("Scan api failed");
        }
    } catch (e) {
        console.error(e);
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center empty-state">
                    <i class="fa-solid fa-triangle-exclamation" style="color: var(--accent-red);"></i>
                    <p>Failed to complete scanning process. Please verify server logs.</p>
                </td>
            </tr>
        `;
    } finally {
        btnScan.disabled = false;
        scanBtnText.textContent = "Start Scan";
        scanBtnIcon.className = "fa-solid fa-radar";
    }
}

// 4. Render and Filter table
function initFilters() {
    searchInput.addEventListener('input', renderTable);
    
    filterPills.forEach(pill => {
        pill.addEventListener('click', () => {
            filterPills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            currentFilter = pill.getAttribute('data-filter');
            renderTable();
        });
    });
}

function renderTable() {
    const searchTerm = searchInput.value.toLowerCase().trim();
    
    // Filter scan data
    const filtered = scanData.filter(item => {
        // Search matches
        const matchesSearch = item.scanned_name.toLowerCase().includes(searchTerm) || 
                              item.scanned_publisher.toLowerCase().includes(searchTerm);
                              
        // Pill matches
        let matchesPill = true;
        if (currentFilter === 'vulnerable') {
            matchesPill = item.cves_count > 0;
        } else if (currentFilter === 'secure') {
            matchesPill = item.cves_count === 0;
        }
        
        return matchesSearch && matchesPill;
    });
    
    if (filtered.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center empty-state">
                    <i class="fa-solid fa-box-open"></i>
                    <p>No matching software assets found.</p>
                </td>
            </tr>
        `;
        return;
    }
    
    tableBody.innerHTML = '';
    
    filtered.forEach((item, index) => {
        const isVulnerable = item.cves_count > 0;
        const statusBadge = isVulnerable 
            ? `<span class="badge badge-red">Vulnerable</span>` 
            : `<span class="badge badge-green">Secure</span>`;
            
        const cpeUriText = item.cpe23uri 
            ? `<span class="cpe-ref" title="${item.cpe23uri}">${item.cpe23uri.substring(0, 35)}...</span>` 
            : `<span class="text-secondary">-</span>`;
            
        const chevronHtml = isVulnerable 
            ? `<i class="fa-solid fa-chevron-right chevron" onclick="toggleRow(this, ${index})"></i>`
            : '';
            
        // Row HTML
        const tr = document.createElement('tr');
        tr.id = `row-${index}`;
        tr.innerHTML = `
            <td>${chevronHtml}</td>
            <td><strong>${item.scanned_name}</strong></td>
            <td>${item.scanned_publisher || '<span class="text-secondary">Unknown</span>'}</td>
            <td>${item.scanned_version || '<span class="text-secondary">Unknown</span>'}</td>
            <td>${cpeUriText}</td>
            <td class="confidence-indicator">
                <span>${item.cves_count}</span>
            </td>
            <td>${statusBadge}</td>
        `;
        tableBody.appendChild(tr);
        
        // Detailed row (vulnerabilities list) if vulnerable
        if (isVulnerable) {
            const detailTr = document.createElement('tr');
            detailTr.className = 'detail-row';
            detailTr.id = `detail-row-${index}`;
            
            let cveListHtml = '<div class="cve-detail-list">';
            item.cves.forEach(cve => {
                const score = cve.cvss_v3_score || cve.cvss_v2_score || 0;
                let scoreClass = 'score-low';
                if (score >= 9.0) scoreClass = 'score-critical';
                else if (score >= 7.0) scoreClass = 'score-high';
                else if (score >= 4.0) scoreClass = 'score-medium';
                
                cveListHtml += `
                    <div class="cve-detail-item">
                        <div class="cve-meta">
                            <span class="cve-id"><i class="fa-solid fa-triangle-exclamation"></i> ${cve.cve_id}</span>
                            <span class="cve-score-badge ${scoreClass}">CVSS Score: ${score.toFixed(1)} (${cve.severity})</span>
                        </div>
                        <p class="cve-desc">${cve.description}</p>
                        <div style="font-size: 0.75rem; color: var(--text-secondary);">Published Date: ${cve.published_date}</div>
                    </div>
                `;
            });
            cveListHtml += '</div>';
            
            detailTr.innerHTML = `
                <td colspan="7">
                    <div class="detail-content">
                        ${cveListHtml}
                    </div>
                </td>
            `;
            tableBody.appendChild(detailTr);
        }
    });
}

window.toggleRow = function(chevron, index) {
    const row = document.getElementById(`row-${index}`);
    const detailRow = document.getElementById(`detail-row-${index}`);
    
    if (detailRow.classList.contains('open')) {
        detailRow.classList.remove('open');
        row.classList.remove('expanded');
    } else {
        detailRow.classList.add('open');
        row.classList.add('expanded');
    }
};

// 5. Scan History
async function loadScanHistory() {
    try {
        const response = await fetch('/api/history');
        if (response.ok) {
            const history = await response.json();
            const container = document.getElementById('history-items');
            if (history.length === 0) {
                container.innerHTML = `
                    <div class="text-center empty-state">
                        <i class="fa-solid fa-folder-open"></i>
                        <p>No previous scans found in database.</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = '';
            history.forEach(scan => {
                const card = document.createElement('div');
                card.className = 'history-card';
                card.innerHTML = `
                    <div class="history-meta">
                        <h4>Audit Report: ${scan.timestamp}</h4>
                        <p>Scan Registry ID: #${scan.id}</p>
                    </div>
                    <button class="btn btn-secondary btn-sm" onclick="loadHistoryScan(${scan.id})">
                        <i class="fa-solid fa-eye"></i> View Results
                    </button>
                `;
                container.appendChild(card);
            });
        }
    } catch (e) {
        console.error("Failed to load history list", e);
    }
}

window.loadHistoryScan = async function(scanId) {
    try {
        const response = await fetch(`/api/history/${scanId}`);
        if (response.ok) {
            scanData = await response.json();
            
            // Switch tab to dashboard to display
            const dashboardMenu = document.querySelector('[data-tab="dashboard"]');
            dashboardMenu.click();
            
            renderTable();
            tableStatusLabel.textContent = `Historical Log ID: #${scanId}`;
        }
    } catch (e) {
        console.error(e);
    }
};

// 6. Database Update
function initDatabaseUpdater() {
    btnUpdateDb.addEventListener('click', triggerDbUpdate);
}

async function loadDbStats() {
    try {
        const response = await fetch('/api/stats');
        if (response.ok) {
            const stats = await response.json();
            dbTotalCpes.textContent = stats.db_cpes_total.toLocaleString();
            dbTotalCves.textContent = stats.db_cves_total.toLocaleString();
        }
    } catch (e) {
        console.error(e);
    }
}

async function triggerDbUpdate() {
    btnUpdateDb.disabled = true;
    try {
        const response = await fetch('/api/update_db', { method: 'POST' });
        if (response.ok) {
            checkDbUpdateStatus();
            // Start polling
            if (dbUpdateInterval) clearInterval(dbUpdateInterval);
            dbUpdateInterval = setInterval(checkDbUpdateStatus, 2000);
        }
    } catch (e) {
        console.error(e);
        btnUpdateDb.disabled = false;
    }
}

async function checkDbUpdateStatus() {
    try {
        const response = await fetch('/api/update_db/status');
        if (response.ok) {
            const status = await response.json();
            
            updaterBadge.textContent = status.status;
            updaterBadge.className = `status-badge ${status.status}`;
            updaterMessage.textContent = status.message;
            
            if (status.last_updated) {
                updaterTime.textContent = `Last sync: ${status.last_updated}`;
            }
            
            if (status.status === 'updating') {
                btnUpdateDb.disabled = true;
                btnUpdateDb.querySelector('span').textContent = "Syncing Feeds...";
                btnUpdateDb.querySelector('i').className = "fa-solid fa-rotate fa-spin";
                
                // Animate progress bar as simulated indicator if progress is flat
                updaterProgress.style.width = "45%"; // Static/simulated mid point
            } else {
                btnUpdateDb.disabled = false;
                btnUpdateDb.querySelector('span').textContent = "Sync NIST Feeds";
                btnUpdateDb.querySelector('i').className = "fa-solid fa-rotate";
                updaterProgress.style.width = status.status === 'failed' ? "0%" : "100%";
                
                if (dbUpdateInterval && status.status !== 'updating') {
                    clearInterval(dbUpdateInterval);
                    dbUpdateInterval = null;
                    loadDbStats(); // Reload statistics counts
                }
            }
        }
    } catch (e) {
        console.error(e);
    }
}
