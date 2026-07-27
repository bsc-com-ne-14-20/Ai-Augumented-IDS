// Function to copy code from the API section
function copyCode() {
    const codeElement = document.getElementById('api-code');
    const textToCopy = codeElement.innerText;
    
    navigator.clipboard.writeText(textToCopy).then(() => {
        const copyBtn = document.querySelector('.copy-btn');
        const originalText = copyBtn.innerText;
        
        copyBtn.innerText = 'Copied!';
        copyBtn.style.color = '#10B981';
        copyBtn.style.borderColor = '#10B981';
        
        setTimeout(() => {
            copyBtn.innerText = originalText;
            copyBtn.style.color = '#94A3B8';
            copyBtn.style.borderColor = '#334155';
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}

// Add simple scroll animation for elements
document.addEventListener('DOMContentLoaded', () => {
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Initial state for elements
    const elementsToAnimate = document.querySelectorAll('.about-card, .pipeline-step, .api-demo');
    elementsToAnimate.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease-out, transform 0.6s ease-out';
        observer.observe(el);
    });
});
