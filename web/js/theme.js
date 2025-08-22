/**
 * Theme Toggle Functionality
 * Handles dark/light theme switching with localStorage persistence
 */

class ThemeManager {
    constructor() {
        this.currentTheme = this.getStoredTheme() || this.getSystemTheme();
        this.themeToggle = null;
        this.mobileToggle = null;
        
        this.init();
    }
    
    init() {
        this.applyTheme(this.currentTheme);
        this.setupToggleButtons();
        this.setupSystemThemeListener();
    }
    
    getStoredTheme() {
        return localStorage.getItem('cryptoscanner-theme');
    }
    
    getSystemTheme() {
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    
    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        this.currentTheme = theme;
        localStorage.setItem('cryptoscanner-theme', theme);
        
        // Update toggle button icons
        this.updateToggleIcons();
        
        // Update Chart.js theme if charts exist
        this.updateChartThemes();
    }
    
    toggleTheme() {
        const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        this.applyTheme(newTheme);
    }
    
    setupToggleButtons() {
        // Main theme toggle
        this.themeToggle = document.getElementById('theme-toggle');
        if (this.themeToggle) {
            this.themeToggle.addEventListener('click', () => this.toggleTheme());
        }
        
        // Mobile theme toggle
        this.mobileToggle = document.getElementById('mobile-theme-toggle');
        if (this.mobileToggle) {
            this.mobileToggle.addEventListener('click', () => this.toggleTheme());
        }
    }
    
    updateToggleIcons() {
        const icon = this.currentTheme === 'light' ? '🌙' : '☀️';
        const title = this.currentTheme === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
        
        if (this.themeToggle) {
            this.themeToggle.innerHTML = icon;
            this.themeToggle.title = title;
        }
        
        if (this.mobileToggle) {
            this.mobileToggle.innerHTML = icon;
            this.mobileToggle.title = title;
        }
    }
    
    setupSystemThemeListener() {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
            // Only auto-switch if user hasn't manually set a preference
            if (!this.getStoredTheme()) {
                this.applyTheme(e.matches ? 'dark' : 'light');
            }
        });
    }
    
    updateChartThemes() {
        // Update Chart.js theme if charts exist
        if (window.Chart && window.dashboardCharts) {
            const isDark = this.currentTheme === 'dark';
            const textColor = isDark ? '#f9fafb' : '#111827';
            const gridColor = isDark ? '#374151' : '#e5e7eb';
            
            Object.values(window.dashboardCharts).forEach(chart => {
                if (chart && chart.options) {
                    // Update scale colors
                    if (chart.options.scales) {
                        Object.values(chart.options.scales).forEach(scale => {
                            if (scale.ticks) scale.ticks.color = textColor;
                            if (scale.grid) scale.grid.color = gridColor;
                        });
                    }
                    
                    // Update legend colors
                    if (chart.options.plugins && chart.options.plugins.legend) {
                        chart.options.plugins.legend.labels.color = textColor;
                    }
                    
                    chart.update();
                }
            });
        }
    }
}

/**
 * Mobile Navigation Manager
 * Handles mobile sidebar toggle functionality
 */
class MobileNavManager {
    constructor() {
        this.mobileToggle = null;
        this.mobileSidebar = null;
        this.mobileOverlay = null;
        this.isOpen = false;
        
        this.init();
    }
    
    init() {
        this.setupElements();
        this.setupEventListeners();
    }
    
    setupElements() {
        this.mobileToggle = document.getElementById('mobile-nav-toggle');
        this.mobileSidebar = document.getElementById('mobile-sidebar');
        this.mobileOverlay = document.getElementById('mobile-overlay');
    }
    
    setupEventListeners() {
        if (this.mobileToggle) {
            this.mobileToggle.addEventListener('click', () => this.toggleSidebar());
        }
        
        if (this.mobileOverlay) {
            this.mobileOverlay.addEventListener('click', () => this.closeSidebar());
        }
        
        // Close sidebar on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isOpen) {
                this.closeSidebar();
            }
        });
        
        // Close sidebar on window resize if moving to desktop
        window.addEventListener('resize', () => {
            if (window.innerWidth > 1024 && this.isOpen) {
                this.closeSidebar();
            }
        });
    }
    
    toggleSidebar() {
        if (this.isOpen) {
            this.closeSidebar();
        } else {
            this.openSidebar();
        }
    }
    
    openSidebar() {
        if (this.mobileSidebar && this.mobileOverlay) {
            this.mobileSidebar.classList.add('open');
            this.mobileOverlay.classList.add('active');
            this.mobileOverlay.style.display = 'block';
            this.isOpen = true;
            
            // Prevent body scroll
            document.body.style.overflow = 'hidden';
        }
    }
    
    closeSidebar() {
        if (this.mobileSidebar && this.mobileOverlay) {
            this.mobileSidebar.classList.remove('open');
            this.mobileOverlay.classList.remove('active');
            
            // Delay hiding overlay to allow animation
            setTimeout(() => {
                if (!this.isOpen) {
                    this.mobileOverlay.style.display = 'none';
                }
            }, 300);
            
            this.isOpen = false;
            
            // Restore body scroll
            document.body.style.overflow = '';
        }
    }
}

/**
 * Responsive Table Manager
 * Enhances table responsiveness on mobile devices
 */
class ResponsiveTableManager {
    constructor() {
        this.tables = [];
        this.init();
    }
    
    init() {
        this.setupTables();
        this.setupResizeListener();
    }
    
    setupTables() {
        const tables = document.querySelectorAll('.table');
        tables.forEach(table => {
            this.makeTableResponsive(table);
        });
    }
    
    makeTableResponsive(table) {
        if (window.innerWidth <= 768) {
            this.addMobileTableStyles(table);
        } else {
            this.removeMobileTableStyles(table);
        }
    }
    
    addMobileTableStyles(table) {
        const container = table.closest('.table-container');
        if (container && !container.classList.contains('mobile-scroll')) {
            container.classList.add('mobile-scroll');
            container.style.overflowX = 'auto';
            container.style.WebkitOverflowScrolling = 'touch';
        }
    }
    
    removeMobileTableStyles(table) {
        const container = table.closest('.table-container');
        if (container && container.classList.contains('mobile-scroll')) {
            container.classList.remove('mobile-scroll');
            container.style.overflowX = '';
            container.style.WebkitOverflowScrolling = '';
        }
    }
    
    setupResizeListener() {
        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                this.setupTables();
            }, 250);
        });
    }
}

// Initialize managers when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize theme manager
    window.themeManager = new ThemeManager();
    
    // Initialize mobile navigation
    window.mobileNavManager = new MobileNavManager();
    
    // Initialize responsive tables
    window.responsiveTableManager = new ResponsiveTableManager();
    
    console.log('Theme and responsive managers initialized');
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ThemeManager, MobileNavManager, ResponsiveTableManager };
}
