// app/static/js/status.js

// Constants
const CONFIG = {
    notificationDuration: 5000,
    fadeDelay: 300,
    modalFocusDelay: 100
};

// Status Manager Class
class StatusManager {
    constructor() {
        // Return existing instance if it exists
        if (window._statusManagerInstance) {
            return window._statusManagerInstance;
        }

        // Set up instance and status check flag
        window._statusManagerInstance = this;
        this.hasCheckedStatus = sessionStorage.getItem('statusChecked') === 'true';

        // Initialize elements
        this.elements = {
            indicator: document.getElementById('status-indicator'),
            text: document.getElementById('status-text'),
            container: document.getElementById('status-container'),
            popover: document.getElementById('issues-popover'),
            issuesList: document.getElementById('issues-list')
        };
        
        this.state = {
            isPopoverVisible: false,
            currentIssues: []
        };

        // If we've already checked status before, set active state without checking
        if (this.hasCheckedStatus) {
            this.setInitialState();
        }

        this.handleClickOutside = this.handleClickOutside.bind(this);
    }

    setInitialState() {
        if (this.elements.indicator && this.elements.text) {
            this.elements.indicator.className = 'w-3 h-3 rounded-full transition-colors duration-200 bg-green-500 animate-pulse';
            this.elements.text.className = 'font-medium transition-colors duration-200 text-green-500';
            this.elements.text.textContent = 'Active';
        }
    }

    init() {
        if (!this.hasCheckedStatus) {
            this.checkStatus();
            sessionStorage.setItem('statusChecked', 'true');
            this.hasCheckedStatus = true;
        }
        document.addEventListener('click', this.handleClickOutside);
    }

    // Rest of your methods stay exactly the same
    async checkStatus() {
        try {
            const response = await fetch('/health');
            const data = await response.json();

            if (data.status === 'ok') {
                this.setActiveState();
            } else {
                const issues = data.issues || [];
                this.setDegradedState(issues);
            }
        } catch (error) {
            this.handleError(error);
        }
    }

    resetClasses() {
        const { indicator, text } = this.elements;
        indicator.className = 'w-3 h-3 rounded-full transition-colors duration-200';
        text.className = 'font-medium transition-colors duration-200';
    }

    setActiveState() {
        const { indicator, text, container } = this.elements;
        
        this.resetClasses();
        indicator.classList.add('bg-green-500', 'animate-pulse');
        text.classList.add('text-green-500');
        text.textContent = 'Active';
        
        container.style.cursor = 'default';
        this.hidePopover();
        this.removeClickHandler();
    }

    setDegradedState(issues) {
        const { indicator, text } = this.elements;
        
        this.resetClasses();
        indicator.classList.add('bg-red-500', 'animate-pulse');
        text.classList.add('text-red-500');
        text.textContent = 'Degraded';

        if (issues && issues.length > 0) {
            this.state.currentIssues = issues;
            this.updateIssuesDisplay(issues);
            this.setupClickHandler();
        }
    }

    updateIssuesDisplay(issues) {
        const { issuesList, container } = this.elements;
        
        issuesList.innerHTML = '';
        issues.forEach(issue => {
            const li = document.createElement('li');
            li.textContent = issue;
            li.className = 'text-red-300 mb-1 last:mb-0';
            issuesList.appendChild(li);
        });

        container.style.cursor = 'pointer';
    }

    handleError(error) {
        const { indicator, text } = this.elements;
        
        this.resetClasses();
        indicator.classList.add('bg-red-500');
        text.classList.add('text-red-500');
        text.textContent = 'Error';

        const errorMessage = error.message.includes('Failed to fetch')
            ? 'Cannot connect to server. Please check your connection.'
            : error.message;

        this.updateIssuesDisplay([errorMessage]);
        this.setupClickHandler();
    }

    setupClickHandler() {
        const { container } = this.elements;
        
        this.removeClickHandler();
        container.onclick = (e) => {
            e.stopPropagation();
            this.togglePopover();
        };
    }

    removeClickHandler() {
        const { container } = this.elements;
        container.onclick = null;
    }

    togglePopover() {
        this.state.isPopoverVisible ? this.hidePopover() : this.showPopover();
    }

    showPopover() {
        const { popover } = this.elements;
        
        popover.classList.remove('hidden');
        requestAnimationFrame(() => {
            popover.classList.add('fade-in');
        });
        
        this.state.isPopoverVisible = true;
    }

    hidePopover() {
        const { popover } = this.elements;
        if (!popover) return;
        
        popover.classList.remove('fade-in');
        
        setTimeout(() => {
            popover.classList.add('hidden');
        }, 200);
        
        this.state.isPopoverVisible = false;
    }

    handleClickOutside(event) {
        const { container } = this.elements;
        
        if (this.state.isPopoverVisible && !container.contains(event.target)) {
            this.hidePopover();
        }
    }

    destroy() {
        document.removeEventListener('click', this.handleClickOutside);
        this.removeClickHandler();
    }
}

// Show Summary
function showSummary() {
    window.location.href = '/summary';
}

// Show Blender
function openBlender() {
    window.location.href = '/blender';
}

// Notification System
const NotificationSystem = {
    show(message, className, duration = CONFIG.notificationDuration) {
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded-lg text-white ${className} shadow-lg z-50 transition-opacity duration-300`;
        notification.style.maxWidth = '400px';
        
        const container = this.createContainer(message);
        notification.appendChild(container);
        document.body.appendChild(notification);
        
        this.setupAutoDismiss(notification, duration);
    },

    createContainer(message) {
        const container = document.createElement('div');
        container.className = 'flex justify-between items-start gap-2';
        
        const messageDiv = document.createElement('div');
        messageDiv.style.whiteSpace = 'pre-line';
        messageDiv.textContent = message;
        
        const closeButton = this.createCloseButton();
        
        container.appendChild(messageDiv);
        container.appendChild(closeButton);
        
        return container;
    },

    createCloseButton() {
        const closeButton = document.createElement('button');
        closeButton.innerHTML = '×';
        closeButton.className = 'text-white hover:text-gray-200 font-bold text-xl leading-none';
        closeButton.onclick = (e) => {
            const notification = e.target.closest('div.fixed');
            this.dismiss(notification);
        };
        return closeButton;
    },

    dismiss(notification) {
        notification.classList.add('opacity-0');
        setTimeout(() => notification.remove(), CONFIG.fadeDelay);
    },

    setupAutoDismiss(notification, duration) {
        setTimeout(() => {
            if (document.body.contains(notification)) {
                this.dismiss(notification);
            }
        }, duration);
    }
};

// Modal Management
const ModalManager = {
    showProcessWarning() {
        const modal = document.getElementById('processWarningModal');
        if (modal) {
            modal.classList.remove('hidden');
            this.focusPIDInput();
        }
    },

    hideProcessWarning() {
        const modal = document.getElementById('processWarningModal');
        if (modal) {
            modal.classList.add('hidden');
        }
    },

    showCleanupWarning() {
        const modal = document.getElementById('cleanupWarningModal');
        modal?.classList.remove('hidden');
    },

    hideCleanupWarning() {
        const modal = document.getElementById('cleanupWarningModal');
        modal?.classList.add('hidden');
    },

    focusPIDInput() {
        setTimeout(() => {
            const pidInput = document.getElementById('processId');
            pidInput?.focus();
        }, CONFIG.modalFocusDelay);
    }
};

const ProcessManager = {
    validatePID(pid) {
        if (!pid) {
            return { isValid: false, error: 'Please enter a process ID' };
        }
        
        if (!/^\d+$/.test(pid)) {
            return { isValid: false, error: 'PID must be a positive number' };
        }
        
        if (parseInt(pid) <= 0) {
            return { isValid: false, error: 'PID must be greater than 0' };
        }
        
        return { isValid: true };
    },

    async startAnalysis() {
        const pid = document.getElementById('processId')?.value;
        const validation = this.validatePID(pid);
        
        if (!validation.isValid) {
            NotificationSystem.show(validation.error, 'bg-red-500');
            return;
        }
        
        const submitButton = this.updateButtonState('Validating...');
        
        try {
            // First validate the PID on the server
            const validationResponse = await fetch(`/validate/${pid}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            
            if (!validationResponse.ok) {
                const data = await validationResponse.json();
                throw new Error(this.getErrorMessage(validationResponse.status, pid, data));
            }
            
            // If validation successful, hide modal and show notification
            ModalManager.hideProcessWarning();
            NotificationSystem.show(`Starting analysis of process ${pid}...`, 'bg-green-500');
            
            // Navigate to analysis page - this single GET request will trigger the analysis
            window.location.href = `/analyze/dynamic/${pid}`;
            
        } catch (error) {
            console.error('Process analysis error:', error);
            NotificationSystem.show(`${error.message}`, 'bg-red-500');
        } finally {
            this.resetButtonState(submitButton);
        }
    },

    getErrorMessage(status, pid, data) {
        switch (status) {
            case 404: return `Process ID ${pid} not found. Please verify the PID and try again.`;
            case 403: return `Access denied to process ${pid}. Please check permissions.`;
            default: return data.error || 'Unknown error occurred';
        }
    },

    updateButtonState(text) {
        const button = document.querySelector('[onclick="startProcessAnalysis()"]');
        if (button) {
            button.disabled = true;
            button.textContent = text;
        }
        return button;
    },

    resetButtonState(button) {
        if (button) {
            button.disabled = false;
            button.textContent = 'Start Analysis';
        }
    }
};
// Cleanup System
const CleanupSystem = {
    async execute() {
        ModalManager.hideCleanupWarning();
        try {
            const response = await fetch('/cleanup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            
            const data = await response.json();
            const { message, className } = this.formatResponse(data);
            NotificationSystem.show(message, className);
            
        } catch (error) {
            NotificationSystem.show(`Error during cleanup: ${error.message}`, 'bg-red-500');
        }
    },

    formatResponse(data) {
        if (data.status === 'success') {
            return {
                message: `Cleanup successful:\n- ${data.details.uploads_cleaned} files removed\n- ${data.details.analysis_cleaned} PE-Sieve folders cleaned\n- ${data.details.result_cleaned} result folders cleaned`,
                className: 'bg-green-500'
            };
        } else if (data.status === 'warning') {
            return {
                message: `Cleanup completed with warnings:\n- ${data.details.uploads_cleaned} files removed\n- ${data.details.analysis_cleaned} PE-Sieve folders cleaned\n- ${data.details.result_cleaned} result folders cleaned\n\nErrors:\n${data.details.errors.join('\n')}`,
                className: 'bg-yellow-500'
            };
        } else {
            return {
                message: `Cleanup failed: ${data.message || data.error}`,
                className: 'bg-red-500'
            };
        }
    }
};



// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize Status Manager
    const statusManager = new StatusManager();
    statusManager.init();

    // Setup Modal Event Listeners
    const processModal = document.getElementById('processWarningModal');
    if (processModal) {
        processModal.addEventListener('click', (e) => {
            if (e.target === processModal) ModalManager.hideProcessWarning();
        });
    }

    const cleanupModal = document.getElementById('cleanupWarningModal');
    if (cleanupModal) {
        cleanupModal.addEventListener('click', (e) => {
            if (e.target === cleanupModal) ModalManager.hideCleanupWarning();
        });
    }

    // Global ESC key handler
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            ModalManager.hideProcessWarning();
            ModalManager.hideCleanupWarning();
        }
    });
});

// Export functions for global access
window.showProcessWarning = ModalManager.showProcessWarning.bind(ModalManager);
window.hideProcessWarning = ModalManager.hideProcessWarning.bind(ModalManager);
window.startProcessAnalysis = ProcessManager.startAnalysis.bind(ProcessManager);
window.showCleanupWarning = ModalManager.showCleanupWarning.bind(ModalManager);
window.hideCleanupWarning = ModalManager.hideCleanupWarning.bind(ModalManager);
window.executeCleanup = CleanupSystem.execute.bind(CleanupSystem);
window.cleanupSystem = ModalManager.showCleanupWarning.bind(ModalManager);
window.showNotification = NotificationSystem.show.bind(NotificationSystem);