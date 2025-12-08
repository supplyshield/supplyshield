// Auto-submit form when filters change
document.addEventListener('DOMContentLoaded', function() {
    const filterInputs = document.querySelectorAll('#filterForm select, #filterForm input');
    const searchInput = document.getElementById('search');
    
    // Auto-submit for select elements
    filterInputs.forEach(input => {
        if (input.tagName === 'SELECT') {
            input.addEventListener('change', function() {
                document.getElementById('filterForm').submit();
            });
        }
    });
    
    // Debounced search for text input
    let searchTimeout;
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            document.getElementById('filterForm').submit();
        }, 500);
    });
});
