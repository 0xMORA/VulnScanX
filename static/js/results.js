// Function to display results dynamically
function displayResult(result) {
    const resultsTable = document.getElementById('results-table').getElementsByTagName('tbody')[0];
    const newRow = resultsTable.insertRow();

    newRow.insertCell(0).textContent = result.vulnerability;
    newRow.insertCell(1).textContent = result.severity;
    newRow.insertCell(2).innerHTML = `<a href="${result.url}" target="_blank">${result.url}</a>`;

    // Format the description for better readability
    const formattedDesc = JSON.stringify(result.description, null, 2)
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;"); // Prevent XSS

    const descCell = newRow.insertCell(3);
    descCell.innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word;">${formattedDesc}</pre>`;
}


// Sort table by severity
function sortTableBySeverity() {
    const table = document.getElementById('results-table');
    const tbody = table.getElementsByTagName('tbody')[0];
    const rows = Array.from(tbody.getElementsByTagName('tr'));

    const severityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };

    rows.sort((a, b) => severityOrder[b.cells[1].textContent] - severityOrder[a.cells[1].textContent]);

    rows.forEach(row => tbody.appendChild(row));
}

// Display scan finished message in a styled banner
function displayScanFinishedMessage() {
    const messageContainer = document.createElement('div');
    messageContainer.textContent = 'Scan is finished!';
    messageContainer.style.position = 'fixed';
    messageContainer.style.bottom = '20px';
    messageContainer.style.right = '20px';
    messageContainer.style.backgroundColor = '#4CAF50'; // Green background
    messageContainer.style.color = 'white';
    messageContainer.style.padding = '15px 25px';
    messageContainer.style.borderRadius = '5px';
    messageContainer.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.2)';
    messageContainer.style.fontWeight = 'bold';
    messageContainer.style.zIndex = '1000'; // Ensure it's on top
    messageContainer.style.animation = 'fadeIn 0.5s ease-in-out';

    // Add fade-in animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
    `;
    document.head.appendChild(style);

    document.body.appendChild(messageContainer);

    // Automatically remove the message after 5 seconds
    setTimeout(() => {
        messageContainer.style.animation = 'fadeOut 0.5s ease-in-out';
        setTimeout(() => messageContainer.remove(), 500);
    }, 5000);
}

// Add a loading spinner
function addLoadingSpinner() {
    const spinner = document.createElement('div');
    spinner.id = 'loading-spinner';
    spinner.style.position = 'fixed';
    spinner.style.top = '50%';
    spinner.style.left = '50%';
    spinner.style.transform = 'translate(-50%, -50%)';
    spinner.style.border = '4px solid #f3f3f3';
    spinner.style.borderTop = '4px solid #3498db';
    spinner.style.borderRadius = '50%';
    spinner.style.width = '40px';
    spinner.style.height = '40px';
    spinner.style.animation = 'spin 1s linear infinite';

    const style = document.createElement('style');
    style.textContent = `
        @keyframes spin {
            0% { transform: translate(-50%, -50%) rotate(0deg); }
            100% { transform: translate(-50%, -50%) rotate(360deg); }
        }
    `;
    document.head.appendChild(style);

    document.body.appendChild(spinner);
}

// Remove the loading spinner
function removeLoadingSpinner() {
    const spinner = document.getElementById('loading-spinner');
    if (spinner) {
        spinner.remove();
    }
}

// Polling for results
function getResults() {
    addLoadingSpinner(); // Show spinner while waiting for results

    const interval = setInterval(() => {
        fetch('/getresults')
            .then(response => response.json())
            .then(data => {
                if (data.scan_finish) {
                    clearInterval(interval);
                    removeLoadingSpinner(); // Hide spinner when scan is finished
                    displayScanFinishedMessage();
                }
                if (data.results && Array.isArray(data.results)) {
                    data.results.forEach(displayResult);
                }
            })
            .catch(error => {
                console.error('Error fetching results:', error);
                removeLoadingSpinner(); // Hide spinner on error
            });
    }, 5000);
}

// Initialize polling when on /results page
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname === '/results') {
        console.log('On the results page, starting polling for results...');
        getResults();
    }
});