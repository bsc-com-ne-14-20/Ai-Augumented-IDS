// realtime.js

document.addEventListener("DOMContentLoaded", () => {
    if (typeof io !== 'undefined') {
        const socket = io();

        socket.on('connect', () => {
            updateEngineStatus(true);
        });

        socket.on('disconnect', () => {
            updateEngineStatus(false);
        });

        socket.on('alert', (data) => {
            // 1. Prepend to live alert feed on overview page
            if (typeof window.prependAlertToFeed === 'function') {
                window.prependAlertToFeed(data);
            }

            // 2. Increment notification bell counter
            if (typeof incrementNotificationCount === 'function') {
                incrementNotificationCount();
            }

            // 3. If severity is CRITICAL or HIGH: show toast notification
            if (data.severity === 'CRITICAL' || data.severity === 'HIGH') {
                if (typeof showToast === 'function') {
                    showToast(data);
                }
            }
        });
        
    } else {
        console.warn("Socket.io not loaded. Real-time alerts disabled.");
        updateEngineStatus(false);
    }
});

function updateEngineStatus(isActive) {
    const dot = document.getElementById('engine-status-dot');
    const text = document.getElementById('engine-status-text');
    
    if (!dot || !text) return;
    
    if (isActive) {
        dot.className = "w-2 h-2 rounded-full bg-[var(--success)] animate-pulse";
        text.textContent = "Engine Active";
    } else {
        dot.className = "w-2 h-2 rounded-full bg-[var(--critical)]";
        text.textContent = "Engine Paused";
    }
}
