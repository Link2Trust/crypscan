// Enhanced CryptoScanner Dashboard
// Business-grade security analysis interface

// Note: Chart.js plugins will be registered when available

// Global state management
let globalData = [];
let filteredData = [];
let currentPage = 1;
const itemsPerPage = 25;
let sortConfig = { field: null, direction: 'asc' };
let scanInProgress = false;
let scanStatusInterval = null;

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
    if (!tbody) return;
    
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
  // Check if Chart.js is available
  if (typeof Chart === 'undefined') {
    console.warn('Chart.js not loaded, skipping chart creation for', elementId);
    return null;
  }
  
  const ctx = document.getElementById(elementId);
  if (!ctx) {
    console.warn(`Chart element ${elementId} not found`);
    return null;
  }
  
  try {
    // Get current theme
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDark ? '#f9fafb' : '#111827';
    const gridColor = isDark ? '#374151' : '#e5e7eb';
    
    const defaultOptions = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            usePointStyle: true,
            padding: 20,
            font: {
              size: 12
            },
            color: textColor
          }
        }
      },
      scales: type !== 'doughnut' && type !== 'pie' ? {
        x: {
          ticks: {
            color: textColor
          },
          grid: {
            color: gridColor
          }
        },
        y: {
          ticks: {
            color: textColor
          },
          grid: {
            color: gridColor
          }
        }
      } : undefined
    };
    
    // Merge options for Chart.js 3.x compatibility
    const mergedOptions = {
      ...defaultOptions,
      ...options
    };
    
    // Handle scales merge separately for Chart.js 3.x
    if (options.scales && defaultOptions.scales) {
      mergedOptions.scales = {
        ...defaultOptions.scales,
        ...options.scales
      };
    }
    
    const chart = new Chart(ctx, {
      type,
      data,
      options: mergedOptions
    });
    
    // Store chart for theme updates
    if (!window.dashboardCharts) {
      window.dashboardCharts = {};
    }
    window.dashboardCharts[elementId] = chart;
    
    console.log('Chart created successfully:', elementId);
    return chart;
  } catch (error) {
    console.error('Error creating chart', elementId, error);
    return null;
  }
}

// Global charts object for theme updates
window.dashboardCharts = {};

// Main data loading and dashboard initialization
console.log('Starting dashboard initialization...');

// Wait for DOM to be ready and Chart.js to load
function startDashboard() {
  console.log('Starting data fetch...');
  fetch('data/findings.json')
    .then(response => {
      console.log('Fetch response:', response.status, response.statusText);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      console.log('Data loaded successfully:', data.length, 'findings');
      globalData = data;
      initializeDashboard(data);
    })
    .catch(error => {
      console.error('Error loading findings data:', error);
      showErrorState('Failed to load security analysis data. Please check the console for details.');
    });
}

// Global modal control - Force close any open modals
function forceCloseModal() {
  const modal = document.getElementById('findingModal');
  if (modal) {
    modal.classList.add('hidden');
    console.log('Modal force closed');
  }
}

// Make closeFindingModal globally available
window.closeFindingModal = function() {
  const modal = document.getElementById('findingModal');
  if (modal) {
    modal.classList.add('hidden');
    console.log('Modal closed via global function');
  }
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('DOM loaded, checking Chart.js availability...');
  
  // Force close any modals on page load
  forceCloseModal();
  
  // Add escape key handler
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      forceCloseModal();
    }
  });
  
  // Check Chart.js availability with retries
  function checkChartJs(retries = 5) {
    if (typeof Chart !== 'undefined') {
      console.log('Chart.js loaded successfully!');
      startDashboard();
    } else if (retries > 0) {
      console.log('Chart.js not ready, retrying...', retries, 'attempts left');
      setTimeout(() => checkChartJs(retries - 1), 200);
    } else {
      console.warn('Chart.js failed to load, proceeding without charts');
      startDashboard();
    }
  }
  
  // Start checking after a brief delay
  setTimeout(checkChartJs, 100);
});

function initializeDashboard(data) {
  console.log('Initializing dashboard with', data.length, 'findings');
  
  try {
    // Hide loading state
    console.log('Hiding loading state...');
    const loadingState = document.getElementById('loadingState');
    const dashboardContent = document.getElementById('dashboardContent');
    
    if (loadingState) {
      loadingState.classList.add('hidden');
      console.log('Loading state hidden');
    } else {
      console.warn('Loading state element not found');
    }
    
    if (dashboardContent) {
      dashboardContent.classList.remove('hidden');
      console.log('Dashboard content shown');
    } else {
      console.warn('Dashboard content element not found');
    }
    
    // Ensure modal is hidden on initialization
    const modal = document.getElementById('findingModal');
    if (modal) {
      modal.classList.add('hidden');
      console.log('Modal hidden on init');
    }
    
    // Initialize navigation
    console.log('Initializing navigation...');
    initializeNavigation();
    
    // Update timestamp
    console.log('Updating timestamp...');
    updateScanTimestamp();
    
    // Categorize findings
    console.log('Categorizing findings...');
    const libraryFindings = data.filter(f => f.category === 'library');
    const secretFindings = data.filter(f => f.category === 'secret');
    const keystoreFindings = data.filter(f => f.category === 'keystore');
    const commandFindings = data.filter(f => f.category === 'key-command');
    const otherFindings = data.filter(f => !['library', 'secret', 'keystore', 'key-command'].includes(f.category));
    
    console.log('Categorized findings:', {
      total: data.length,
      secrets: secretFindings.length,
      libraries: libraryFindings.length,
      keystores: keystoreFindings.length,
      commands: commandFindings.length,
      other: otherFindings.length
    });
    
    // Update metrics cards
    console.log('Updating metrics cards...');
    updateMetricsCards({
      total: data.length,
      secrets: secretFindings.length,
      libraries: libraryFindings.length,
      keystores: keystoreFindings.length,
      files: new Set(data.map(f => f.file)).size
    });
    
    // Update risk assessment
    console.log('Updating risk assessment...');
    updateRiskAssessment(data);
    
    // Create charts
    console.log('Creating charts...');
    createLibraryCharts(libraryFindings);
    createSecretsCharts(secretFindings);
    
    // Initialize findings table
    console.log('Initializing findings table...');
    const findingsTable = new FindingsTable(data);
    findingsTable.render();
    
    // Setup global search
    console.log('Setting up global search...');
    setupGlobalSearch(data);
    
    console.log('Dashboard initialization completed successfully!');
  } catch (error) {
    console.error('Error during dashboard initialization:', error);
    showErrorState('Dashboard initialization failed: ' + error.message);
  }
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

// ================================
// SCAN INITIATION AND TRACKING
// ================================

// Initiate a new scan
function initiateScan() {
  if (scanInProgress) {
    alert('A scan is already in progress. Please wait for it to complete.');
    return;
  }
  
  const scanInput = document.getElementById('scanLocationInput');
  const scanButton = document.getElementById('scanButton');
  
  if (!scanInput || !scanInput.value.trim()) {
    alert('Please enter a location to scan (local path or repository URL)');
    return;
  }
  
  const location = scanInput.value.trim();
  
  // Validate input format
  if (!isValidScanLocation(location)) {
    alert('Please enter a valid local path (e.g., /path/to/folder) or repository URL (e.g., https://github.com/user/repo.git)');
    return;
  }
  
  // Update UI to show scan in progress
  scanInProgress = true;
  scanButton.disabled = true;
  scanButton.innerHTML = '⏳ Scanning...';
  scanInput.disabled = true;
  
  // Show loading state
  showScanProgress('Initiating scan...');
  
  // Send scan request to backend
  fetch('/api/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      location: location,
      timestamp: new Date().toISOString()
    })
  })
  .then(response => {
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  })
  .then(data => {
    console.log('Scan initiated successfully:', data);
    
    if (data.scanId) {
      // Start polling for scan status
      startScanStatusPolling(data.scanId);
    } else {
      throw new Error('No scan ID returned from server');
    }
  })
  .catch(error => {
    console.error('Error initiating scan:', error);
    alert('Failed to initiate scan: ' + error.message);
    resetScanUI();
  });
}

// Validate scan location format
function isValidScanLocation(location) {
  // Check for local path (starts with / or ~/ or ./ or ../ or drive letter on Windows)
  const localPathRegex = /^(\/|~\/|\.\.\/|\.\/).*|^[a-zA-Z]:\\.*$/;
  
  // Check for repository URL (git, https, ssh)
  const repoUrlRegex = /^(https?:\/\/|git@|ssh:\/\/).*\.(git|com|org|net).*$/i;
  
  return localPathRegex.test(location) || repoUrlRegex.test(location);
}

// Show scan progress in UI
function showScanProgress(message) {
  const loadingState = document.getElementById('loadingState');
  const dashboardContent = document.getElementById('dashboardContent');
  
  if (loadingState && dashboardContent) {
    loadingState.innerHTML = `
      <div class="spinner"></div>
      <span>${message}</span>
      <div class="mt-md">
        <button class="btn btn-secondary" onclick="cancelScan()">Cancel Scan</button>
      </div>
    `;
    loadingState.classList.remove('hidden');
    dashboardContent.classList.add('hidden');
  }
}

// Start polling for scan status
function startScanStatusPolling(scanId) {
  console.log('Starting scan status polling for ID:', scanId);
  
  scanStatusInterval = setInterval(() => {
    checkScanStatus(scanId);
  }, 2000); // Poll every 2 seconds
  
  // Also check immediately
  checkScanStatus(scanId);
}

// Check scan status
function checkScanStatus(scanId) {
  fetch(`/api/scan/status/${scanId}`)
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      console.log('Scan status:', data);
      
      if (data.status === 'completed') {
        // Scan completed successfully
        clearInterval(scanStatusInterval);
        scanStatusInterval = null;
        
        showScanProgress('Scan completed! Loading results...');
        
        // Reload data and refresh dashboard
        setTimeout(() => {
          location.reload();
        }, 1500);
        
      } else if (data.status === 'failed') {
        // Scan failed
        clearInterval(scanStatusInterval);
        scanStatusInterval = null;
        
        console.error('Scan failed:', data.error);
        alert('Scan failed: ' + (data.error || 'Unknown error'));
        resetScanUI();
        
      } else if (data.status === 'running') {
        // Scan still in progress
        const progress = data.progress || 'Scanning in progress...';
        showScanProgress(progress);
        
      } else {
        // Unknown status
        console.warn('Unknown scan status:', data.status);
      }
    })
    .catch(error => {
      console.error('Error checking scan status:', error);
      
      // If we get repeated errors, stop polling and reset UI
      if (scanStatusInterval) {
        clearInterval(scanStatusInterval);
        scanStatusInterval = null;
        alert('Lost connection to scan process. Please refresh the page to check results.');
        resetScanUI();
      }
    });
}

// Cancel ongoing scan
function cancelScan() {
  if (scanStatusInterval) {
    clearInterval(scanStatusInterval);
    scanStatusInterval = null;
  }
  
  // Try to cancel the scan on the server
  fetch('/api/scan/cancel', {
    method: 'POST'
  })
  .then(response => {
    if (response.ok) {
      console.log('Scan cancelled');
    }
  })
  .catch(error => {
    console.error('Error cancelling scan:', error);
  })
  .finally(() => {
    resetScanUI();
  });
}

// Reset scan UI to initial state
function resetScanUI() {
  scanInProgress = false;
  
  const scanInput = document.getElementById('scanLocationInput');
  const scanButton = document.getElementById('scanButton');
  const loadingState = document.getElementById('loadingState');
  const dashboardContent = document.getElementById('dashboardContent');
  
  if (scanInput) {
    scanInput.disabled = false;
  }
  
  if (scanButton) {
    scanButton.disabled = false;
    scanButton.innerHTML = '🚀 Scan';
  }
  
  if (loadingState && dashboardContent) {
    loadingState.classList.add('hidden');
    dashboardContent.classList.remove('hidden');
  }
}

// Handle Enter key in scan input
document.addEventListener('DOMContentLoaded', function() {
  const scanInput = document.getElementById('scanLocationInput');
  if (scanInput) {
    scanInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        initiateScan();
      }
    });
  }
});

// Make functions globally available
window.initiateScan = initiateScan;
window.cancelScan = cancelScan;
window.resetScanUI = resetScanUI;

