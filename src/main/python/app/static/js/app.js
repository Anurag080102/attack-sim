/**
 * Attack-Sim JavaScript Application
 * Provides AJAX functionality, real-time updates, and UI interactions
 */

// ============================================
// Global State
// ============================================
const AppState = {
    currentJobId: null,
    pollInterval: null,
    attacks: [],
    startTime: null
};

// ============================================
// API Client
// ============================================
const API = {
    baseUrl: '/api',
    
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };
        
        try {
            const response = await fetch(url, config);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Request failed');
            }
            
            return data;
        } catch (error) {
            console.error(`API Error [${endpoint}]:`, error);
            throw error;
        }
    },
    
    // Attacks
    getAttacks: () => API.request('/attacks'),
    getAttack: (id) => API.request(`/attacks/${id}`),
    runAttack: (data) => API.request('/attacks/run', { 
        method: 'POST', 
        body: JSON.stringify(data) 
    }),
    runAllAttacks: (data) => API.request('/attacks/run-all', { 
        method: 'POST', 
        body: JSON.stringify(data) 
    }),
    getStatus: (jobId) => API.request(`/attacks/status/${jobId}`),
    getResults: (jobId) => API.request(`/attacks/results/${jobId}`),
    cancelAttack: (jobId) => API.request(`/attacks/cancel/${jobId}`, { method: 'POST' }),
    getJobs: (limit = 50) => API.request(`/attacks/jobs?limit=${limit}`),
    
    // Reports
    getReports: () => API.request('/reports'),
    generateReport: (jobId, title) => API.request('/reports/generate', {
        method: 'POST',
        body: JSON.stringify({ job_id: jobId, title })
    }),
    deleteReport: (id) => API.request(`/reports/${id}`, { method: 'DELETE' })
};

// ============================================
// Toast Notifications
// ============================================
const Toast = {
    container: null,
    
    init() {
        this.container = document.getElementById('toast-container');
    },
    
    show(message, type = 'info', title = '', duration = 5000) {
        if (!this.container) this.init();
        
        const icons = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        };
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <span class="toast-icon">${icons[type]}</span>
            <div class="toast-content">
                ${title ? `<div class="toast-title">${title}</div>` : ''}
                <div class="toast-message">${message}</div>
            </div>
            <button class="toast-close">&times;</button>
        `;
        
        // Close button
        toast.querySelector('.toast-close').addEventListener('click', () => {
            this.dismiss(toast);
        });
        
        this.container.appendChild(toast);
        
        // Auto dismiss
        if (duration > 0) {
            setTimeout(() => this.dismiss(toast), duration);
        }
        
        return toast;
    },
    
    dismiss(toast) {
        toast.classList.add('hiding');
        setTimeout(() => toast.remove(), 300);
    },
    
    success: (msg, title) => Toast.show(msg, 'success', title),
    error: (msg, title) => Toast.show(msg, 'error', title),
    warning: (msg, title) => Toast.show(msg, 'warning', title),
    info: (msg, title) => Toast.show(msg, 'info', title)
};

// ============================================
// Modal System
// ============================================
const Modal = {
    overlay: null,
    container: null,
    title: null,
    content: null,
    
    init() {
        this.overlay = document.getElementById('modal-overlay');
        this.container = document.getElementById('modal-container');
        this.title = document.getElementById('modal-title');
        this.content = document.getElementById('modal-content');
        
        // Close button
        document.getElementById('modal-close')?.addEventListener('click', () => this.close());
        
        // Close on overlay click
        this.overlay?.addEventListener('click', (e) => {
            if (e.target === this.overlay) this.close();
        });
        
        // Close on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !this.overlay?.classList.contains('hidden')) {
                this.close();
            }
        });
    },
    
    open(title, content) {
        if (!this.overlay) this.init();
        
        this.title.textContent = title;
        
        if (typeof content === 'string') {
            this.content.innerHTML = content;
        } else {
            this.content.innerHTML = '';
            this.content.appendChild(content);
        }
        
        this.overlay.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    },
    
    close() {
        this.overlay?.classList.add('hidden');
        document.body.style.overflow = '';
    }
};

// ============================================
// Attack Card Rendering
// ============================================
function renderAttackCard(attack) {
    const card = document.createElement('div');
    card.className = 'card attack-card';
    card.dataset.attackId = attack.id;
    
    card.innerHTML = `
        <div class="card-header">
            <h3>${escapeHtml(attack.name)}</h3>
            <p>${escapeHtml(attack.description?.substring(0, 80) || '')}...</p>
        </div>
        <div class="card-body">
            <span class="attack-category ${attack.category}">${attack.category}</span>
            <span class="attack-id">${attack.id}</span>
        </div>
    `;
    
    card.addEventListener('click', () => showAttackConfig(attack));
    
    return card;
}

async function loadAttacks() {
    try {
        const data = await API.getAttacks();
        AppState.attacks = data.attacks;
        
        const owaspContainer = document.getElementById('owasp-attacks');
        
        if (!owaspContainer) return;
        
        // Clear loading
        owaspContainer.innerHTML = '';
        
        // Render OWASP attacks
        data.attacks.forEach(attack => {
            owaspContainer.appendChild(renderAttackCard(attack));
        });
        
        if (data.attacks.length === 0) {
            owaspContainer.innerHTML = '<p class="text-muted">No OWASP attacks available</p>';
        }
        
    } catch (error) {
        Toast.error('Failed to load attacks', 'Error');
        console.error(error);
    }
}

// ============================================
// Attack Configuration
// ============================================
function showAttackConfig(attack) {
    const configPanel = document.getElementById('attack-config');
    const attacksSection = document.getElementById('attacks-section');
    const jobsSection = document.getElementById('jobs-section');
    
    if (!configPanel) return;
    
    // Update config panel
    document.getElementById('config-attack-name').textContent = attack.name;
    document.getElementById('config-attack-description').textContent = attack.description;
    document.getElementById('attack-id').value = attack.id;
    document.getElementById('target-url').value = '';
    
    // Generate dynamic config fields
    const configFields = document.getElementById('config-fields');
    configFields.innerHTML = '';
    
    if (attack.parameters) {
        Object.entries(attack.parameters).forEach(([key, param]) => {
            configFields.appendChild(createConfigField(key, param));
        });
    }
    
    // Show config, hide others
    configPanel.classList.remove('hidden');
    attacksSection.classList.add('hidden');
    jobsSection.classList.add('hidden');
}

function createConfigField(key, param) {
    const group = document.createElement('div');
    group.className = 'form-group';
    
    let inputHtml = '';
    const value = param.default || '';
    
    switch (param.type) {
        case 'number':
            inputHtml = `<input type="number" id="config-${key}" name="${key}" class="form-input" 
                         value="${value}" ${param.min !== undefined ? `min="${param.min}"` : ''} 
                         ${param.max !== undefined ? `max="${param.max}"` : ''}>`;
            break;
        case 'boolean':
            inputHtml = `<label class="checkbox-label">
                <input type="checkbox" id="config-${key}" name="${key}" ${value ? 'checked' : ''}>
                <span>${param.description || ''}</span>
            </label>`;
            break;
        case 'select':
            const options = (param.options || []).map(opt => 
                `<option value="${opt}" ${opt === value ? 'selected' : ''}>${opt}</option>`
            ).join('');
            inputHtml = `<select id="config-${key}" name="${key}" class="form-select">${options}</select>`;
            break;
        default:
            inputHtml = `<input type="text" id="config-${key}" name="${key}" class="form-input" 
                         value="${value}" placeholder="${param.placeholder || ''}">`;
    }
    
    group.innerHTML = `
        <label class="form-label" for="config-${key}">${param.name || key}</label>
        ${inputHtml}
        ${param.description && param.type !== 'boolean' ? `<p class="form-hint">${param.description}</p>` : ''}
    `;
    
    return group;
}

function hideAttackConfig() {
    document.getElementById('attack-config')?.classList.add('hidden');
    document.getElementById('attacks-section')?.classList.remove('hidden');
    document.getElementById('jobs-section')?.classList.remove('hidden');
}

// ============================================
// Attack Execution
// ============================================
async function runAttack() {
    const attackId = document.getElementById('attack-id').value;
    const target = document.getElementById('target-url').value;
    
    if (!target) {
        Toast.warning('Please enter a target URL');
        return;
    }
    
    // Collect config from form
    const config = {};
    document.querySelectorAll('#config-fields input, #config-fields select').forEach(input => {
        if (input.type === 'checkbox') {
            config[input.name] = input.checked;
        } else if (input.type === 'number') {
            config[input.name] = parseFloat(input.value) || 0;
        } else {
            config[input.name] = input.value;
        }
    });
    
    // Debug: Show what we're sending
    console.log('🚀 Starting attack with config:', { attack_id: attackId, target, config });
    
    try {
        const result = await API.runAttack({ attack_id: attackId, target, config });
        
        AppState.currentJobId = result.job.id;
        AppState.startTime = Date.now();
        
        showRunningPanel(result.job);
        startPolling();
        
        Toast.success('Attack started successfully');
        
    } catch (error) {
        Toast.error(error.message, 'Failed to start attack');
    }
}

async function runAllAttacks() {
    const target = prompt('Enter target URL for all OWASP attacks:');
    
    if (!target) return;
    
    try {
        const result = await API.runAllAttacks({ target, config: {} });
        Toast.success(`Started ${result.jobs.length} OWASP attacks`, 'Success');
        loadJobs();
    } catch (error) {
        Toast.error(error.message, 'Failed to start attacks');
    }
}

function showRunningPanel(job) {
    document.getElementById('attack-config')?.classList.add('hidden');
    document.getElementById('attacks-section')?.classList.add('hidden');
    document.getElementById('jobs-section')?.classList.add('hidden');
    
    const panel = document.getElementById('running-panel');
    if (!panel) return;
    
    panel.classList.remove('hidden');
    
    document.getElementById('running-attack-name').textContent = job.attack_name;
    document.getElementById('running-attack-target').textContent = `Target: ${job.target}`;
    
    // Reset stats
    ['critical', 'high', 'medium', 'low', 'info'].forEach(s => {
        document.getElementById(`stat-${s}`).textContent = '0';
    });
    
    updateProgress(0, 'Initializing...');
}

function updateProgress(percent, status) {
    const fill = document.getElementById('progress-fill');
    const percentText = document.getElementById('progress-percent');
    const statusText = document.getElementById('progress-status');
    
    if (fill) fill.style.width = `${percent}%`;
    if (percentText) percentText.textContent = `${percent.toFixed(1)}%`;
    if (statusText) statusText.textContent = status;
}

function updateElapsedTime() {
    if (!AppState.startTime) return;
    
    const elapsed = Math.floor((Date.now() - AppState.startTime) / 1000);
    const timeEl = document.getElementById('running-time');
    if (timeEl) timeEl.textContent = `Elapsed: ${elapsed}s`;
}

// ============================================
// Polling System
// ============================================
function startPolling() {
    stopPolling();
    
    AppState.pollInterval = setInterval(async () => {
        if (!AppState.currentJobId) {
            stopPolling();
            return;
        }
        
        try {
            const status = await API.getStatus(AppState.currentJobId);
            const results = await API.getResults(AppState.currentJobId);
            
            updateProgress(status.progress, status.status === 'running' ? 'Scanning...' : status.status);
            updateElapsedTime();
            updateLiveStats(results.findings);
            
            if (status.status === 'completed' || status.status === 'failed' || status.status === 'cancelled') {
                stopPolling();
                showResults(status, results.findings);
            }
            
        } catch (error) {
            console.error('Polling error:', error);
        }
    }, 1000);
}

function stopPolling() {
    if (AppState.pollInterval) {
        clearInterval(AppState.pollInterval);
        AppState.pollInterval = null;
    }
}

function updateLiveStats(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    
    findings.forEach(f => {
        counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    
    Object.keys(counts).forEach(severity => {
        const el = document.getElementById(`stat-${severity}`);
        if (el) el.textContent = counts[severity];
    });
}

// ============================================
// Results Display
// ============================================
function showResults(job, findings) {
    document.getElementById('running-panel')?.classList.add('hidden');
    
    const panel = document.getElementById('results-panel');
    if (!panel) return;
    
    panel.classList.remove('hidden');
    
    // Render final stats
    const statsContainer = document.getElementById('final-stats');
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    
    findings.forEach(f => {
        counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    
    statsContainer.innerHTML = Object.entries(counts).map(([severity, count]) => `
        <div class="stat-item ${severity}">
            <div class="stat-count">${count}</div>
            <div class="stat-label">${severity.charAt(0).toUpperCase() + severity.slice(1)}</div>
        </div>
    `).join('');
    
    // Render findings
    renderFindings(findings);
}

function renderFindings(findings) {
    const container = document.getElementById('findings-list');
    if (!container) return;
    
    if (findings.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">✅</div>
                <h3 class="empty-state-title">No Vulnerabilities Found</h3>
                <p class="empty-state-description">Great! No security issues were detected during this scan.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = findings.map((finding, index) => `
        <div class="finding-item" onclick="this.classList.toggle('expanded')">
            <div class="finding-header">
                <span class="finding-number">#${index + 1}</span>
                <span class="finding-title">${escapeHtml(finding.title)}</span>
                <span class="badge badge-${finding.severity}">${finding.severity.toUpperCase()}</span>
                <span class="finding-chevron">▼</span>
            </div>
            <div class="finding-body">
                <div class="finding-field">
                    <div class="finding-field-label">Description</div>
                    <div class="finding-field-value">${escapeHtml(finding.description)}</div>
                </div>
                <div class="finding-field">
                    <div class="finding-field-label">Evidence</div>
                    <div class="finding-field-value"><code>${escapeHtml(finding.evidence)}</code></div>
                </div>
                <div class="finding-field">
                    <div class="finding-field-label">Remediation</div>
                    <div class="finding-field-value">${escapeHtml(finding.remediation)}</div>
                </div>
            </div>
        </div>
    `).join('');
}

// ============================================
// Cancel Attack
// ============================================
async function cancelAttack() {
    if (!AppState.currentJobId) return;
    
    if (!confirm('Are you sure you want to cancel this attack?')) return;
    
    try {
        await API.cancelAttack(AppState.currentJobId);
        stopPolling();
        Toast.info('Attack cancelled');
        resetToHome();
    } catch (error) {
        Toast.error(error.message, 'Failed to cancel');
    }
}

// ============================================
// Export Functions
// ============================================
async function exportResults(format) {
    if (!AppState.currentJobId) return;
    
    try {
        const report = await API.generateReport(AppState.currentJobId);
        window.location.href = `/api/reports/${report.report_id}/download?format=${format}`;
        Toast.success(`Downloading ${format.toUpperCase()} report`);
    } catch (error) {
        Toast.error(error.message, 'Export failed');
    }
}

function startNewAttack() {
    AppState.currentJobId = null;
    document.getElementById('results-panel')?.classList.add('hidden');
    document.getElementById('attacks-section')?.classList.remove('hidden');
    document.getElementById('jobs-section')?.classList.remove('hidden');
    loadJobs();
}

// ============================================
// Jobs List
// ============================================
async function loadJobs() {
    try {
        const data = await API.getJobs(20);
        renderJobsTable(data.jobs);
    } catch (error) {
        console.error('Failed to load jobs:', error);
    }
}

function renderJobsTable(jobs) {
    const tbody = document.getElementById('jobs-tbody');
    if (!tbody) return;
    
    if (jobs.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center text-muted">
                    No recent scans. Select an attack to get started.
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = jobs.map(job => `
        <tr>
            <td><strong>${escapeHtml(job.attack_name)}</strong></td>
            <td><code>${escapeHtml(job.target.substring(0, 40))}${job.target.length > 40 ? '...' : ''}</code></td>
            <td>
                <span class="status status-${job.status}">
                    <span class="status-dot"></span>
                    ${job.status}
                </span>
            </td>
            <td>
                <div class="progress-bar" style="width: 80px; height: 6px;">
                    <div class="progress-fill" style="width: ${job.progress}%"></div>
                </div>
            </td>
            <td>${job.findings_count}</td>
            <td>${job.started_at ? formatTime(job.started_at) : 'N/A'}</td>
            <td>
                ${job.status === 'completed' ? `
                    <button class="btn btn-sm btn-outline" onclick="viewJobResults('${job.id}')">
                        View
                    </button>
                ` : job.status === 'running' ? `
                    <button class="btn btn-sm btn-outline" onclick="resumeJobView('${job.id}')">
                        Monitor
                    </button>
                ` : ''}
            </td>
        </tr>
    `).join('');
}

async function viewJobResults(jobId) {
    try {
        const status = await API.getStatus(jobId);
        const results = await API.getResults(jobId);
        
        AppState.currentJobId = jobId;
        
        document.getElementById('attacks-section')?.classList.add('hidden');
        document.getElementById('jobs-section')?.classList.add('hidden');
        
        showResults(status, results.findings);
    } catch (error) {
        Toast.error(error.message, 'Failed to load results');
    }
}

async function resumeJobView(jobId) {
    try {
        const status = await API.getStatus(jobId);
        
        AppState.currentJobId = jobId;
        AppState.startTime = new Date(status.started_at).getTime();
        
        showRunningPanel(status);
        startPolling();
    } catch (error) {
        Toast.error(error.message, 'Failed to resume monitoring');
    }
}

function resetToHome() {
    AppState.currentJobId = null;
    document.getElementById('attack-config')?.classList.add('hidden');
    document.getElementById('running-panel')?.classList.add('hidden');
    document.getElementById('results-panel')?.classList.add('hidden');
    document.getElementById('attacks-section')?.classList.remove('hidden');
    document.getElementById('jobs-section')?.classList.remove('hidden');
    loadJobs();
}

// ============================================
// Utility Functions
// ============================================
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString();
}

// ============================================
// Event Listeners
// ============================================
function setupEventListeners() {
    // Cancel config
    document.getElementById('cancel-config')?.addEventListener('click', hideAttackConfig);
    
    // Run attack
    document.getElementById('run-attack')?.addEventListener('click', runAttack);
    
    // Run all attacks
    document.getElementById('run-all-attacks')?.addEventListener('click', runAllAttacks);
    
    // Cancel running attack
    document.getElementById('cancel-attack')?.addEventListener('click', cancelAttack);
    
    // Export buttons
    document.getElementById('export-json')?.addEventListener('click', () => exportResults('json'));
    document.getElementById('export-html')?.addEventListener('click', () => exportResults('html'));
    
    // New attack button
    document.getElementById('new-attack')?.addEventListener('click', startNewAttack);
    
    // Refresh jobs
    document.getElementById('refresh-jobs')?.addEventListener('click', loadJobs);
    
    // Allow Enter to submit target
    document.getElementById('target-url')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            runAttack();
        }
    });
}

// ============================================
// Initialize Application
// ============================================
document.addEventListener('DOMContentLoaded', function() {
    console.log('Attack-Sim initialized');
    
    // Initialize components
    Toast.init();
    Modal.init();
    
    // Setup event listeners
    setupEventListeners();
    
    // Load initial data
    loadAttacks();
    loadJobs();
});
