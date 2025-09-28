// Mobile menu toggle
document.addEventListener('DOMContentLoaded', function() {
    const hamburger = document.querySelector('.hamburger');
    const navMenu = document.querySelector('.nav-menu');
    
    if (hamburger && navMenu) {
        hamburger.addEventListener('click', function() {
            hamburger.classList.toggle('active');
            navMenu.classList.toggle('active');
        });
    }

    // Close flash messages when clicking close button
    document.querySelectorAll('.flash-close').forEach(button => {
        button.addEventListener('click', function() {
            this.parentElement.remove();
        });
    });

    // Auto-close flash messages after 5 seconds
    setTimeout(() => {
        document.querySelectorAll('.flash').forEach(flash => {
            flash.remove();
        });
    }, 5000);
});