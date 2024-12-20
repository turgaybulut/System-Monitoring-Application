class MonitorApp {
    constructor() {
        this.statsDiv = {
            system: document.getElementById('system-stats'),
            process: document.getElementById('process-stats'),
            user: document.getElementById('user-stats'),
            log: document.getElementById('log-stats')
        };
        this.errorDiv = document.getElementById('error');
        this.ws = null;
        this.sortConfig = {
            column: 'cpu_percent',
            direction: 'desc'
        };
        this.latestStats = null;
        this.initialLoadDone = false;
        this.init();
    }

    init() {
        const server_url = 'wss://' + location.host + location.pathname.replace('monitor', 'ws');
        this.ws = new WebSocket(server_url);
        this.setupWebSocket();
        this.startStatsInterval();
    }

    setupWebSocket() {
        this.ws.onopen = () => this.handleConnect();
        this.ws.onerror = (e) => this.handleError(e);
        this.ws.onmessage = (event) => this.handleMessage(event);
        this.ws.onclose = () => this.handleClose();
    }

    handleConnect() {
        console.log('Connected to WebSocket');
        this.getStats();
    }

    handleError(e) {
        this.errorDiv.style.display = 'block';
        this.errorDiv.innerHTML = `Error: ${e.message}`;
    }

    handleMessage(event) {
        try {
            const message = JSON.parse(event.data);
            if (message[0] === 'stats') {
                this.updateStats(message[1]);
            } else {
                this.showError(message);
            }
        } catch (error) {
            console.error('Error parsing message:', error);
            this.showError('Failed to parse server message');
        }
    }

    handleClose() {
        this.errorDiv.style.display = 'block';
        this.errorDiv.innerHTML = 'Connection closed. Attempting to reconnect...';
        setTimeout(() => this.init(), 5000);
    }

    showError(message) {
        this.errorDiv.style.display = 'block';
        this.errorDiv.innerHTML = `Error: ${message}`;
        setTimeout(() => {
            this.errorDiv.style.display = 'none';
        }, 5000);
    }

    formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
    }

    parseLogEntry(logLine) {
        // Regular expression to match syslog format
        const cleanLogLine = logLine.trim().replace(/\u0000/g, '');
        const regex = /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[]+)(?:\[(\d+)\])?:\s+(.+)$/;
        const match = cleanLogLine.match(regex);
        if (match) {
            return {
                timestamp: match[1],
                hostname: match[2],
                program: match[3].trim(),
                pid: match[4] || '',
                message: match[5],
                severity: this.detectLogSeverity(match[5])
            };
        }

        return {
            timestamp: 'Unknown',
            hostname: '',
            program: '',
            pid: '',
            message: logLine,
            severity: 'info'
        };
    }

    detectLogSeverity(message) {
        if (message.includes('ERROR') || message.includes('FAIL') || message.includes('CRITICAL')) {
            return 'error';
        }
        if (message.includes('WARNING')) {
            return 'warning';
        }
        if (message.includes('DEBUG')) {
            return 'debug';
        }
        return 'info';
    }

    initLogFilters() {
        const filterButtons = document.querySelectorAll('.filter-button');
        filterButtons.forEach(button => {
            button.addEventListener('click', () => {
                filterButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');

                const severity = button.dataset.severity;
                const entries = document.querySelectorAll('.log-entry');

                entries.forEach(entry => {
                    if (severity === 'all') {
                        entry.style.display = '';
                    } else {
                        // Check if entry has the selected severity class
                        if (entry.classList.contains(severity)) {
                            entry.style.display = '';
                        } else {
                            entry.style.display = 'none';
                        }
                    }
                });
            });
        });
    }

    updateStats(stats) {
        if (!stats) return;

        // Always update system and process stats
        this.statsDiv.system.innerHTML = this.renderSystemStats(stats);
        this.statsDiv.process.innerHTML = this.renderProcessStats(stats);
        this.statsDiv.user.innerHTML = this.renderUserStats(stats);

        // Store the latest stats for manual refresh sections
        this.latestStats = stats;

        // Only update user and log stats if it's the first load
        if (!this.initialLoadDone) {
            this.statsDiv.log.innerHTML = this.renderLogStats(stats);
            this.initialLoadDone = true;
        }

        this.addSortEventListeners();
        this.initializeTooltips();
        this.initLogFilters();
    }

    renderSystemStats(stats) {
        const memoryPercent = ((stats.memory.used / stats.memory.total) * 100).toFixed(1);
        const usedMemory = this.formatBytes(stats.memory.used);
        const totalMemory = this.formatBytes(stats.memory.total);

        return `
            <h2>System Overview</h2>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-header">
                        <span class="stat-title">CPU Usage</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${stats.cpu}%"></div>
                        </div>
                    </div>
                    <div class="stat-value">${stats.cpu.toFixed(1)}%</div>
                </div>
                
                <div class="stat-item">
                    <div class="stat-header">
                        <span class="stat-title">Memory Usage</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${memoryPercent}%"></div>
                        </div>
                    </div>
                    <div class="stat-value">${usedMemory} / ${totalMemory}</div>
                </div>

                <div class="stat-item">
                    <div class="stat-header">
                        <span class="stat-title">Disk Usage</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${stats.disk.percent}%"></div>
                        </div>
                    </div>
                    <div class="stat-value">
                        ${this.formatBytes(stats.disk.used)} / ${this.formatBytes(stats.disk.total)}
                    </div>
                </div>

                <div class="stat-item">
                    <div class="stat-header">
                        <span class="stat-title">Load Average</span>
                    </div>
                    <div class="stat-value load-values">
                        <span>1m: ${stats.load_avg[0].toFixed(2)}</span>
                        <span>5m: ${stats.load_avg[1].toFixed(2)}</span>
                        <span>15m: ${stats.load_avg[2].toFixed(2)}</span>
                    </div>
                </div>

                <div class="stat-item">
                    <div class="stat-header">
                        <span class="stat-title">System Uptime</span>
                    </div>
                    <div class="stat-value">${stats.uptime}</div>
                </div>
            </div>
        `;
    }

    renderProcessStats(stats) {
        if (!stats.processes || !Array.isArray(stats.processes)) {
            return '<div class="error-message">No process data available</div>';
        }

        const sortedProcesses = this.sortProcesses(stats.processes);
        const summary = stats.process_summary;

        return `
            <h2>Process Information</h2>
            <div class="process-summary">
                <div class="summary-grid">
                    <div class="summary-item">
                        <span class="summary-label">Total</span>
                        <span class="summary-value">${summary.total}</span>
                    </div>
                    ${Object.entries(summary)
                .filter(([key]) => key !== 'total')
                .map(([state, count]) => `
                            <div class="summary-item">
                                <span class="summary-label">${state}</span>
                                <span class="summary-value">${count}</span>
                            </div>
                        `).join('')}
                </div>
            </div>
            <div class="table-container">
                <table class="process-table">
                    <thead>
                        <tr>
                            <th data-sort="pid" class="sortable ${this.getSortClass('pid')}">PID</th>
                            <th data-sort="name" class="sortable ${this.getSortClass('name')}">Name</th>
                            <th data-sort="cpu_percent" class="sortable ${this.getSortClass('cpu_percent')}">CPU %</th>
                            <th data-sort="memory_percent" class="sortable ${this.getSortClass('memory_percent')}">Memory %</th>
                            <th data-sort="status" class="sortable ${this.getSortClass('status')}">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${sortedProcesses.map(proc => `
                            <tr>
                                <td>${proc.pid}</td>
                                <td>${this.escapeHtml(proc.name)}</td>
                                <td>${proc.cpu_percent.toFixed(1)}</td>
                                <td>${proc.memory_percent.toFixed(1)}</td>
                                <td><span class="status-badge status-${proc.status.toLowerCase()}">${proc.status}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    renderUserStats(stats) {
        const currentUsers = stats.current_users;
        const lastLogins = stats.last_logins;

        return `
            <div class="section-header">
                <h2>User Information</h2>
            </div>
            <div class="users-container">
                <div class="current-users">
                    <h3>Current Users</h3>
                    <div class="table-container">
                        <table class="user-table">
                            <thead>
                                <tr>
                                    <th>User</th>
                                    <th>Terminal</th>
                                    <th>Host</th>
                                    <th>Login Time</th>
                                    <th>CPU %</th>
                                    <th>Memory %</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${currentUsers.map(user => `
                                    <tr>
                                        <td>${this.escapeHtml(user.name)}</td>
                                        <td>${this.escapeHtml(user.terminal)}</td>
                                        <td>${this.escapeHtml(user.host)}</td>
                                        <td>${user.started}</td>
                                        <td>${user.cpu_usage.toFixed(1)}</td>
                                        <td>${user.memory_usage.toFixed(1)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
    
                <div class="login-history">
                    <h3>Recent Logins</h3>
                    <div class="table-container">
                        <table class="user-table">
                            <thead>
                                <tr>
                                    <th>User</th>
                                    <th>Terminal</th>
                                    <th>Host</th>
                                    <th>Login Time</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${lastLogins.map(login => `
                                    <tr>
                                        <td>${this.escapeHtml(login.name)}</td>
                                        <td>${this.escapeHtml(login.terminal)}</td>
                                        <td>${this.escapeHtml(login.host)}</td>
                                        <td>${login.login_time}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    }

    renderLogStats(stats) {
        return `
            <div class="section-header">
                <h2>System Logs</h2>
                <button class="refresh-btn" onclick="window.monitorApp.refreshLogStats()">
                    Refresh
                </button>
            </div>
            <div class="log-container">
                <div class="log-controls">
                    <div class="log-filters">
                        <button class="filter-button active" data-severity="all">All</button>
                        <button class="filter-button" data-severity="error">Errors</button>
                        <button class="filter-button" data-severity="warning">Warnings</button>
                        <button class="filter-button" data-severity="info">Info</button>
                    </div>
                    <span class="log-info">
                        Showing last ${stats.system_logs.length} entries
                    </span>
                </div>
                <div class="log-entries">
                    ${stats.system_logs.map(log => {
            const parsed = this.parseLogEntry(log);
            return `
                            <div class="log-entry ${parsed.severity}">
                                <span class="log-timestamp">${parsed.timestamp}</span>
                                <span class="log-message">
                                    ${parsed.program ? `<strong>${this.escapeHtml(parsed.program)}</strong>: ` : ''}
                                    ${this.escapeHtml(parsed.message)}
                                </span>
                            </div>
                        `;
        }).join('')}
                </div>
            </div>
        `;
    }

    sortProcesses(processes) {
        return [...processes].sort((a, b) => {
            const aVal = a[this.sortConfig.column];
            const bVal = b[this.sortConfig.column];

            let comparison;
            if (typeof aVal === 'string') {
                comparison = aVal.localeCompare(bVal);
            } else {
                comparison = aVal - bVal;
            }

            return this.sortConfig.direction === 'asc' ? comparison : -comparison;
        });
    }

    getSortClass(column) {
        if (this.sortConfig.column === column) {
            return `sort-${this.sortConfig.direction}`;
        }
        return '';
    }

    escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    addSortEventListeners() {
        document.querySelectorAll('.sortable').forEach(header => {
            header.addEventListener('click', () => {
                const column = header.dataset.sort;
                if (this.sortConfig.column === column) {
                    this.sortConfig.direction = this.sortConfig.direction === 'asc' ? 'desc' : 'asc';
                } else {
                    this.sortConfig.column = column;
                    this.sortConfig.direction = 'desc';
                }
                this.getStats();
            });
        });
    }

    addLogFilterEventListeners() {
        const filterButtons = document.querySelectorAll('.filter-button');
        filterButtons.forEach(button => {
            button.addEventListener('click', () => {
                // Update active state of buttons
                filterButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');

                // Filter log entries
                const severity = button.dataset.severity;
                const entries = document.querySelectorAll('.log-entry');
                entries.forEach(entry => {
                    if (severity === 'all' || entry.classList.contains(severity)) {
                        entry.style.display = '';
                    } else {
                        entry.style.display = 'none';
                    }
                });
            });
        });
    }

    initializeTooltips() {
        // Initialize tooltips if needed
    }

    startStatsInterval() {
        setInterval(() => this.getStats(), 2000);
    }

    getStats() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send('stats');
        }
    }

    refreshLogStats() {
        if (this.latestStats) {
            this.statsDiv.log.innerHTML = this.renderLogStats(this.latestStats);
            this.initLogFilters();
        }
    }
}

// Logout functionality
async function logout() {
    try {
        const response = await fetch('/logout');
        if (response.ok) {
            window.location.href = '/login';
        } else {
            console.error('Logout failed');
        }
    } catch (error) {
        console.error('Error during logout:', error);
    }
}

// Initialize the monitor application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.monitorApp = new MonitorApp();
});