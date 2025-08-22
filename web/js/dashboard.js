// Enhanced CryptoScanner Dashboard
// Business-grade security analysis interface

// Register Chart.js plugins
Chart.register(ChartDataLabels);

// Global state management
let globalData = [];
let filteredData = [];
let currentPage = 1;
const itemsPerPage = 25;
let sortConfig = { field: null, direction: 'asc' };

// Color schemes for professional look
const colorSchemes = {
  primary: {
    colors: ['#0052cc', '#0065ff', '#003d99', '#0891b2', '#059669'],
    gradients: ['rgba(0, 82, 204, 0.8)', 'rgba(0, 101, 255, 0.8)', 'rgba(0, 61, 153, 0.8)']
  },
  danger: {
    colors: ['#dc2626', '#ef4444', '#f87171', '#fca5a5'],
    gradients: ['rgba(220, 38, 38, 0.8)', 'rgba(239, 68, 68, 0.8)']
  },
  warning: {
    colors: ['#d97706', '#f59e0b', '#fbbf24', '#fcd34d'],
    gradients: ['rgba(217, 119, 6, 0.8)', 'rgba(245, 158, 11, 0.8)']
  },
  success: {
    colors: ['#059669', '#10b981', '#34d399', '#6ee7b7'],
    gradients: ['rgba(5, 150, 105, 0.8)', 'rgba(16, 185, 129, 0.8)']
  }
};

// Professional color generator
function generateProfessionalColors(count, scheme = 'primary') {
  const schemeColors = colorSchemes[scheme]?.colors || colorSchemes.primary.colors;
  return Array.from({ length: count }, (_, i) => 
    schemeColors[i % schemeColors.length]
  );
}

// Risk assessment calculator
function calculateRiskScore(findings) {
  const secretFindings = findings.filter(f => f.category === 'secret');
  const libraryFindings = findings.filter(f => f.category === 'library');
  
  // Risk scoring algorithm
  let riskScore = 0;
  
  // Secrets contribute heavily to risk
  riskScore += secretFindings.length * 15;
  
  // High-risk secret types
  const highRiskSecrets = secretFindings.filter(f => 
    ['AWS Access Key', 'GitHub Token', 'Private Key', 'Database URI'].includes(f.keyword)
  );
  riskScore += highRiskSecrets.length * 25;
  
  // Library diversity (too many different libraries can indicate complexity)
  const uniqueLibraries = new Set(libraryFindings.map(f => f.keyword)).size;
  riskScore += Math.min(uniqueLibraries * 2, 20);
  
  // Normalize to 0-100 scale
  return Math.min(Math.round(riskScore), 100);
}

// Risk level categorization
function getRiskLevel(score) {
  if (score >= 80) return { level: 'Critical', class: 'danger', icon: '⚠️' };
  if (score >= 60) return { level: 'High', class: 'danger', icon: '🔴' };
  if (score >= 40) return { level: 'Medium', class: 'warning', icon: '🟡' };
  if (score >= 20) return { level: 'Low', class: 'warning', icon: '🟠' };
  return { level: 'Minimal', class: 'success', icon: '🟢' };
}

// Navigation handling
function initializeNavigation() {
  const navLinks = document.querySelectorAll('.nav-link');
  const sections = document.querySelectorAll('main section');
  
  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const targetId = link.getAttribute('href').substring(1);
      const targetSection = document.getElementById(targetId);
      
      // Update active nav state
      navLinks.forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      
      // Scroll to section
      if (targetSection) {
        targetSection.scrollIntoView({ behavior: 'smooth' });
      }
    });
  });
}

// Table functionality
class FindingsTable {
  constructor(data) {
    this.data = data;
    this.filteredData = data;
    this.currentPage = 1;
    this.itemsPerPage = 25;
    this.sortConfig = { field: null, direction: 'asc' };
    
    this.initializeEventListeners();
  }
  
  initializeEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('tableSearch');
    const categoryFilter = document.getElementById('categoryFilter');
    
    if (searchInput) {
      searchInput.addEventListener('input', () => this.applyFilters());
    }
    
    if (categoryFilter) {
      categoryFilter.addEventListener('change', () => this.applyFilters());
    }
  }
  
  applyFilters() {
    const searchTerm = document.getElementById('tableSearch')?.value.toLowerCase() || '';
    const categoryFilter = document.getElementById('categoryFilter')?.value || 'all';
    
    this.filteredData = this.data.filter(item => {
      const matchesSearch = !searchTerm || 
        item.file.toLowerCase().includes(searchTerm) ||
        item.keyword.toLowerCase().includes(searchTerm) ||
        item.line_content.toLowerCase().includes(searchTerm) ||
        item.language.toLowerCase().includes(searchTerm);
      
      const matchesCategory = categoryFilter === 'all' || item.category === categoryFilter;
      
      return matchesSearch && matchesCategory;
    });
    
    this.currentPage = 1;
    this.render();
  }
  
  sort(field) {
    if (this.sortConfig.field === field) {
      this.sortConfig.direction = this.sortConfig.direction === 'asc' ? 'desc' : 'asc';
    } else {
      this.sortConfig.field = field;
      this.sortConfig.direction = 'asc';
    }
    
    this.filteredData.sort((a, b) => {
      let aVal = a[field];
      let bVal = b[field];
      
      if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }
      
      if (aVal < bVal) return this.sortConfig.direction === 'asc' ? -1 : 1;
      if (aVal > bVal) return this.sortConfig.direction === 'asc' ? 1 : -1;
      return 0;
    });
    
    this.render();
  }
  
  getSeverityBadge(finding) {
    if (finding.category === 'secret') {
      const highRiskSecrets = ['AWS Access Key', 'GitHub Token', 'Private Key', 'Database URI'];
      if (highRiskSecrets.includes(finding.keyword)) {
        return '<span class="badge danger">Critical</span>';
      }
      return '<span class="badge warning">High</span>';
    } else if (finding.category === 'library') {
      return '<span class="badge info">Medium</span>';
    } else {
      return '<span class="badge secondary">Low</span>';
    }
  }
  
  render() {
    const tbody = document.getElementById('findingsTableBody');
    const startIndex = (this.currentPage - 1) * this.itemsPerPage;
    const endIndex = startIndex + this.itemsPerPage;
    const pageData = this.filteredData.slice(startIndex, endIndex);
    
    tbody.innerHTML = pageData.map(finding => `
      <tr onclick="showFindingDetails(${JSON.stringify(finding).replace(/"/g, '&quot;')})" style="cursor: pointer;">
        <td>${this.getSeverityBadge(finding)}</td>
        <td><span class="badge secondary">${finding.category}</span></td>
        <td><strong>${finding.keyword}</strong></td>
        <td class="font-mono text-sm">${this.truncateFilePath(finding.file)}</td>
        <td>${finding.line_number}</td>
        <td><span class="badge info">${finding.language}</span></td>
        <td>
          <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); openInVSCode('${finding.file}', ${finding.line_number})">
            🔗 VS Code
          </button>
        </td>
      </tr>
    `).join('');
    
    // Update table info and pagination
    this.updateTableInfo();
    this.updatePagination();
  }
  
  truncateFilePath(filePath) {
    const parts = filePath.split('/');
    if (parts.length > 3) {
      return `.../${parts.slice(-2).join('/')}`;
    }
    return filePath;
  }
  
  updateTableInfo() {
    const tableInfo = document.getElementById('tableInfo');
    const startIndex = (this.currentPage - 1) * this.itemsPerPage + 1;
    const endIndex = Math.min(startIndex + this.itemsPerPage - 1, this.filteredData.length);
    
    if (tableInfo) {
      tableInfo.textContent = `Showing ${startIndex}-${endIndex} of ${this.filteredData.length} findings`;
    }
  }
  
  updatePagination() {
    const pagination = document.getElementById('tablePagination');
    const totalPages = Math.ceil(this.filteredData.length / this.itemsPerPage);
    
    if (!pagination) return;
    
    pagination.innerHTML = '';
    
    // Previous button
    if (this.currentPage > 1) {
      const prevBtn = document.createElement('button');
      prevBtn.className = 'btn btn-sm btn-secondary';
      prevBtn.textContent = '← Previous';
      prevBtn.onclick = () => { this.currentPage--; this.render(); };
      pagination.appendChild(prevBtn);
    }
    
    // Page numbers
    const startPage = Math.max(1, this.currentPage - 2);
    const endPage = Math.min(totalPages, startPage + 4);
    
    for (let i = startPage; i <= endPage; i++) {
      const pageBtn = document.createElement('button');
      pageBtn.className = `btn btn-sm ${i === this.currentPage ? 'btn-primary' : 'btn-secondary'}`;
      pageBtn.textContent = i;
      pageBtn.onclick = () => { this.currentPage = i; this.render(); };
      pagination.appendChild(pageBtn);
    }
    
    // Next button
    if (this.currentPage < totalPages) {
      const nextBtn = document.createElement('button');
      nextBtn.className = 'btn btn-sm btn-secondary';
      nextBtn.textContent = 'Next →';
      nextBtn.onclick = () => { this.currentPage++; this.render(); };
      pagination.appendChild(nextBtn);
    }
  }
}

// Chart creation with professional styling
function createChart(elementId, type, data, options = {}) {
  const ctx = document.getElementById(elementId);
  if (!ctx) return null;
  
  const defaultOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          usePointStyle: true,
          padding: 20,
          font: { size: 12, family: 'Inter, sans-serif' }
        }
      },
      tooltip: {
        backgroundColor: 'rgba(17, 24, 39, 0.95)',
        titleColor: '#ffffff',
        bodyColor: '#ffffff',
        borderColor: '#374151',
        borderWidth: 1,
        cornerRadius: 8,
        titleFont: { size: 14, weight: 'bold' },
        bodyFont: { size: 12 }
      }
    }
  };
  
  const mergedOptions = { ...defaultOptions, ...options };
  
  return new Chart(ctx, {
    type,
    data,
    options: mergedOptions
  });
}

// Main data loading and dashboard initialization
fetch('data/findings.json')
  .then(response => {
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  })
  .then(data => {
    globalData = data;
    initializeDashboard(data);
  })
  .catch(error => {
    console.error('Error loading findings data:', error);
    showErrorState('Failed to load security analysis data. Please ensure the scan has been completed.');
  });

function initializeDashboard(data) {
  // Hide loading state
  document.getElementById('loadingState').classList.add('hidden');
  document.getElementById('dashboardContent').classList.remove('hidden');
  
  // Initialize navigation
  initializeNavigation();
  
  // Update timestamp
  updateScanTimestamp();
  
  // Categorize findings
  const libraryFindings = data.filter(f => f.category === 'library');
  const secretFindings = data.filter(f => f.category === 'secret');
  const keystoreFindings = data.filter(f => f.category === 'keystore');
  const commandFindings = data.filter(f => f.category === 'key-command');
  const otherFindings = data.filter(f => !['library', 'secret', 'keystore', 'key-command'].includes(f.category));
  
  // Update metrics cards
  updateMetricsCards({
    total: data.length,
    secrets: secretFindings.length,
    libraries: libraryFindings.length,
    keystores: keystoreFindings.length,
    files: new Set(data.map(f => f.file)).size
  });
  
  // Update risk assessment
  updateRiskAssessment(data);
  
  // Create charts
  createLibraryCharts(libraryFindings);
  createSecretsCharts(secretFindings);
  
  // Initialize findings table
  const findingsTable = new FindingsTable(data);
  findingsTable.render();
  
  // Setup global search
  setupGlobalSearch(data);
}

function updateMetricsCards(metrics) {
  document.getElementById('totalFindings').textContent = metrics.total;
  document.getElementById('totalSecrets').textContent = metrics.secrets;
  document.getElementById('totalLibraries').textContent = metrics.libraries;
  document.getElementById('totalKeystores').textContent = metrics.keystores;
  document.getElementById('filesScanned').textContent = metrics.files;
  
  // Add click animations
  const cards = document.querySelectorAll('.metric-card');
  cards.forEach(card => {
    card.style.cursor = 'pointer';
    card.addEventListener('click', function() {
      this.style.transform = 'translateY(-4px)';
      setTimeout(() => {
        this.style.transform = 'translateY(-2px)';
      }, 150);
    });
  });
}

function updateRiskAssessment(data) {
  const riskScore = calculateRiskScore(data);
  const riskInfo = getRiskLevel(riskScore);
  
  // Update risk score display
  document.getElementById('riskScore').textContent = riskScore;
  const riskIcon = document.getElementById('riskIcon');
  const riskCard = document.getElementById('riskScoreCard');
  
  if (riskIcon) riskIcon.textContent = riskInfo.icon;
  if (riskCard) {
    const iconElement = riskCard.querySelector('.metric-icon');
    if (iconElement) {
      iconElement.className = `metric-icon ${riskInfo.class}`;
    }
  }
  
  // Update security breakdown
  updateSecurityBreakdown(data);
  
  // Update recommendations
  updateRecommendations(data, riskInfo);
}

function updateSecurityBreakdown(data) {
  const breakdown = document.getElementById('securityBreakdown');
  if (!breakdown) return;
  
  const secretsCount = data.filter(f => f.category === 'secret').length;
  const librariesCount = data.filter(f => f.category === 'library').length;
  const keystoresCount = data.filter(f => f.category === 'keystore').length;
  
  breakdown.innerHTML = `
    <div class="flex items-center gap-sm mb-sm">
      <span class="badge danger">🚨 ${secretsCount}</span>
      <span class="text-sm">Hardcoded secrets detected</span>
    </div>
    <div class="flex items-center gap-sm mb-sm">
      <span class="badge warning">📦 ${librariesCount}</span>
      <span class="text-sm">Cryptographic libraries in use</span>
    </div>
    <div class="flex items-center gap-sm">
      <span class="badge info">🔑 ${keystoresCount}</span>
      <span class="text-sm">Keystore files found</span>
    </div>
  `;
}

function updateRecommendations(data, riskInfo) {
  const recommendations = document.getElementById('recommendationsList');
  if (!recommendations) return;
  
  const secretsCount = data.filter(f => f.category === 'secret').length;
  const highRiskSecrets = data.filter(f => 
    f.category === 'secret' && 
    ['AWS Access Key', 'GitHub Token', 'Private Key'].includes(f.keyword)
  ).length;
  
  let recs = [];
  
  if (secretsCount > 0) {
    recs.push('🔐 Immediately rotate any exposed secrets');
    recs.push('🏗️ Implement proper secrets management system');
  }
  
  if (highRiskSecrets > 0) {
    recs.push('⚠️ Review high-risk credential exposures');
  }
  
  if (riskInfo.level === 'Critical' || riskInfo.level === 'High') {
    recs.push('📋 Conduct security audit of affected systems');
    recs.push('🔍 Review access logs for potential compromises');
  }
  
  if (recs.length === 0) {
    recs.push('✅ Continue monitoring for security threats');
    recs.push('📚 Review cryptographic implementations');
  }
  
  recommendations.innerHTML = recs.map(rec => `<li>${rec}</li>`).join('');
}

function createLibraryCharts(libraryFindings) {
  // Library usage bar chart
  const libCounts = {};
  libraryFindings.forEach(f => {
    const key = f.version ? `${f.keyword} v${f.version}` : f.keyword;
    libCounts[key] = (libCounts[key] || 0) + 1;
  });
  
  const libLabels = Object.keys(libCounts);
  const libData = Object.values(libCounts);
  
  createChart('libraryChartBar', 'bar', {
    labels: libLabels,
    datasets: [{
      label: 'Usage Count',
      data: libData,
      backgroundColor: generateProfessionalColors(libLabels.length, 'primary'),
      borderRadius: 4,
      borderSkipped: false
    }]
  }, {
    scales: {
      x: {
        ticks: { maxRotation: 45, minRotation: 0 },
        grid: { display: false }
      },
      y: {
        beginAtZero: true,
        grid: { color: 'rgba(0, 0, 0, 0.05)' }
      }
    }
  });
  
  // Library types pie chart
  createChart('libraryChartPie', 'doughnut', {
    labels: libLabels,
    datasets: [{
      data: libData,
      backgroundColor: generateProfessionalColors(libLabels.length, 'primary'),
      borderWidth: 2,
      borderColor: '#ffffff'
    }]
  }, {
    cutout: '60%'
  });
  
  // File types charts
  const fileTypeCounts = {};
  libraryFindings.forEach(f => {
    const ext = f.file.split('.').pop().toLowerCase();
    fileTypeCounts[ext] = (fileTypeCounts[ext] || 0) + 1;
  });
  
  const typeLabels = Object.keys(fileTypeCounts);
  const typeData = Object.values(fileTypeCounts);
  
  createChart('fileTypeChartBar', 'bar', {
    labels: typeLabels,
    datasets: [{
      label: 'File Count',
      data: typeData,
      backgroundColor: generateProfessionalColors(typeLabels.length, 'warning'),
      borderRadius: 4
    }]
  });
  
  createChart('fileTypeChartPie', 'doughnut', {
    labels: typeLabels,
    datasets: [{
      data: typeData,
      backgroundColor: generateProfessionalColors(typeLabels.length, 'warning'),
      borderWidth: 2,
      borderColor: '#ffffff'
    }]
  }, {
    cutout: '60%'
  });
}

function createSecretsCharts(secretFindings) {
  const secretCounts = {};
  secretFindings.forEach(f => {
    secretCounts[f.keyword] = (secretCounts[f.keyword] || 0) + 1;
  });
  
  const secretLabels = Object.keys(secretCounts);
  const secretData = Object.values(secretCounts);
  
  if (secretLabels.length === 0) {
    // Show "no secrets found" message
    const chartsContainer = document.querySelector('#secrets .charts-grid');
    if (chartsContainer) {
      chartsContainer.innerHTML = `
        <div class="card" style="grid-column: 1 / -1;">
          <div class="card-body text-center">
            <div class="metric-icon success" style="margin: 0 auto var(--spacing-md) auto;">✅</div>
            <h4>No Hardcoded Secrets Detected</h4>
            <p class="text-muted">Great! No hardcoded secrets were found in the scanned codebase.</p>
          </div>
        </div>
      `;
    }
    return;
  }
  
  createChart('secretsChartBar', 'bar', {
    labels: secretLabels,
    datasets: [{
      label: 'Secret Count',
      data: secretData,
      backgroundColor: generateProfessionalColors(secretLabels.length, 'danger'),
      borderRadius: 4
    }]
  }, {
    scales: {
      x: {
        ticks: { maxRotation: 45, minRotation: 0 },
        grid: { display: false }
      },
      y: {
        beginAtZero: true,
        grid: { color: 'rgba(0, 0, 0, 0.05)' }
      }
    }
  });
  
  createChart('secretsChartPie', 'doughnut', {
    labels: secretLabels,
    datasets: [{
      data: secretData,
      backgroundColor: generateProfessionalColors(secretLabels.length, 'danger'),
      borderWidth: 2,
      borderColor: '#ffffff'
    }]
  }, {
    cutout: '60%'
  });
}

// Utility functions
function updateScanTimestamp() {
  const timestamp = document.getElementById('scanTimestamp');
  if (timestamp) {
    timestamp.textContent = `Last scan: ${new Date().toLocaleString()}`;
  }
}

function setupGlobalSearch(data) {
  const globalSearch = document.getElementById('globalSearch');
  if (!globalSearch) return;
  
  globalSearch.addEventListener('input', (e) => {
    const searchTerm = e.target.value.toLowerCase();
    if (searchTerm.length < 2) return;
    
    const results = data.filter(item => 
      item.file.toLowerCase().includes(searchTerm) ||
      item.keyword.toLowerCase().includes(searchTerm) ||
      item.line_content.toLowerCase().includes(searchTerm)
    );
    
    // Update table with search results
    const tableSearch = document.getElementById('tableSearch');
    if (tableSearch) {
      tableSearch.value = searchTerm;
      tableSearch.dispatchEvent(new Event('input'));
    }
    
    // Scroll to detailed findings
    document.getElementById('detailed-findings').scrollIntoView({ behavior: 'smooth' });
  });
}

function showErrorState(message) {
  const loadingState = document.getElementById('loadingState');
  if (loadingState) {
    loadingState.innerHTML = `
      <div class="text-center">
        <div class="metric-icon danger" style="margin: 0 auto var(--spacing-md) auto;">⚠️</div>
        <h3 class="mb-md">Error Loading Data</h3>
        <p class="text-muted mb-lg">${message}</p>
        <button class="btn btn-primary" onclick="location.reload()">🔄 Retry</button>
      </div>
    `;
  }
}

// Modal and interaction functions
function showFindingDetails(finding) {
  const modal = document.getElementById('findingModal');
  const modalBody = document.getElementById('findingModalBody');
  
  if (!modal || !modalBody) return;
  
  const riskLevel = finding.category === 'secret' ? 'High' : 
                   finding.category === 'library' ? 'Medium' : 'Low';
  
  modalBody.innerHTML = `
    <div class="mb-lg">
      <div class="flex items-center gap-md mb-md">
        <span class="badge ${finding.category === 'secret' ? 'danger' : 'info'}">${finding.category}</span>
        <span class="badge secondary">${riskLevel} Risk</span>
      </div>
      <h4>${finding.keyword}</h4>
      <p class="text-muted">${finding.context}</p>
    </div>
    
    <div class="mb-lg">
      <h4 class="mb-sm">File Information</h4>
      <div class="code-snippet">
        <div class="text-sm text-muted mb-sm">📁 ${finding.file}:${finding.line_number}</div>
        <div class="text-sm text-muted mb-sm">🔤 Language: ${finding.language}</div>
        <div class="text-sm text-muted mb-md">📝 Source: ${finding.source}</div>
        <div style="background-color: var(--gray-800); padding: var(--spacing-md); border-radius: var(--radius-md);">
          <code style="color: var(--gray-100); font-family: var(--font-family-mono);">${finding.line_content}</code>
        </div>
      </div>
    </div>
    
    ${finding.category === 'secret' ? `
    <div class="card" style="border-left: 4px solid var(--danger-red);">
      <div class="card-body">
        <h4 class="mb-sm">⚠️ Security Recommendation</h4>
        <p class="text-sm">This appears to be a hardcoded secret. Immediate action required:</p>
        <ul class="text-sm mt-sm">
          <li>Rotate the exposed credential immediately</li>
          <li>Remove the hardcoded value from source code</li>
          <li>Use environment variables or secure credential storage</li>
          <li>Review access logs for potential unauthorized access</li>
        </ul>
      </div>
    </div>
    ` : ''}
  `;
  
  // Setup VS Code button
  const vscodeBtn = document.getElementById('openInVSCode');
  if (vscodeBtn) {
    vscodeBtn.onclick = () => openInVSCode(finding.file, finding.line_number);
  }
  
  modal.classList.remove('hidden');
}

function closeFindingModal() {
  const modal = document.getElementById('findingModal');
  if (modal) {
    modal.classList.add('hidden');
  }
}

function openInVSCode(filePath, lineNumber = 1) {
  const vscodeUrl = `vscode://file${filePath}:${lineNumber}`;
  window.open(vscodeUrl, '_blank');
}

function exportReport() {
  const reportData = {
    timestamp: new Date().toISOString(),
    summary: {
      totalFindings: globalData.length,
      riskScore: calculateRiskScore(globalData),
      filesScanned: new Set(globalData.map(f => f.file)).size
    },
    findings: globalData
  };
  
  const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `cryptoscan-report-${new Date().toISOString().split('T')[0]}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function refreshData() {
  location.reload();
}

function toggleTableView() {
  // This could toggle between table and card view
  console.log('Toggle table view - feature to be implemented');
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  // Any additional initialization can go here
  console.log('CryptoScanner Dashboard initialized');
});
            y: {
              beginAtZero: true,
              title: { display: true, text: "Count" }
            }
          }
        }
      });
      setupClickHandler(secretBarChart, secretLabels);

      const secretPieChart = new Chart(document.getElementById("secretsChartPie"), {
        type: "pie",
        data: {
          labels: secretLabels,
          datasets: [{
            data: secretData,
            backgroundColor: secretColors
          }]
        },
        options: {
          plugins: {
            legend: { position: 'bottom' },
            datalabels: {
              color: "#fff",
              formatter: val => val
            }
          }
        }
      });
      setupClickHandler(secretPieChart, secretLabels);
    } else {
      // Show "No secrets found" message
      document.getElementById("secretsChartBar").parentElement.innerHTML = "<p style='text-align: center; padding: 2rem;'>✅ No hardcoded secrets detected!</p>";
      document.getElementById("secretsChartPie").parentElement.innerHTML = "<p style='text-align: center; padding: 2rem;'>🔒 Great security posture!</p>";
    }

    const tbody = document.getElementById("artefactBody");
    artefacts.forEach(f => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${f.category}</td>
        <td>${f.keyword}</td>
        <td>${f.context}</td>
        <td>${f.file}</td>
        <td>${f.line_number}</td>
      `;
      tbody.appendChild(row);
    });
  })
  .catch(err => {
    console.error("❌ Failed to load findings.json", err);
  });
