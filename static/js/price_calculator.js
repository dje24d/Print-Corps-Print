document.addEventListener('DOMContentLoaded', function() {
    // Get all form elements that affect pricing
    const pagesInput = document.getElementById('pages');
    const copiesInput = document.getElementById('copies');
    const paperTypeSelect = document.getElementById('paper_type');
    const paperSizeSelect = document.getElementById('paper_size');
    const colorCheckbox = document.getElementById('color');
    const prioritySelect = document.getElementById('priority');
    const estimatedPriceElement = document.getElementById('estimated_price');
    
    // Get the price multipliers from the template
    const priceMultipliers = JSON.parse(document.getElementById('price_multipliers').textContent);
    
    // Function to calculate price
    function calculatePrice() {
        const pages = parseInt(pagesInput.value) || 1;
        const copies = parseInt(copiesInput.value) || 1;
        const paperType = paperTypeSelect.value;
        const paperSize = paperSizeSelect.value;
        const color = colorCheckbox.checked;
        const priority = prioritySelect.value;
        
        // Calculate price using the same formula as the server
        let total = priceMultipliers.base_price * pages * copies;
        total *= priceMultipliers.paper_type[paperType] || 1.0;
        total *= priceMultipliers.paper_size[paperSize] || 1.0;
        total *= color ? priceMultipliers.color : 1.0;
        total *= priceMultipliers.priority[priority] || 1.0;
        
        return total;
    }
    
    // Function to update the displayed price
    function updatePriceDisplay() {
        const price = calculatePrice();
        estimatedPriceElement.textContent = `UGX ${Math.round(price).toLocaleString()}`;
    }
    
    // Add event listeners to all form elements
    pagesInput.addEventListener('input', updatePriceDisplay);
    copiesInput.addEventListener('input', updatePriceDisplay);
    paperTypeSelect.addEventListener('change', updatePriceDisplay);
    paperSizeSelect.addEventListener('change', updatePriceDisplay);
    colorCheckbox.addEventListener('change', updatePriceDisplay);
    prioritySelect.addEventListener('change', updatePriceDisplay);
    
    // Initial price calculation
    updatePriceDisplay();
});