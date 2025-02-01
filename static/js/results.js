// Function to display results dynamically
function displayResult(result) {
    const resultsTable = document.getElementById('results-table').getElementsByTagName('tbody')[0];

    const newRow = resultsTable.insertRow();
    newRow.insertCell(0).textContent = result.vulnerability;
    newRow.insertCell(1).textContent = result.severity;
    newRow.insertCell(2).textContent = result.url;
    newRow.insertCell(3).innerHTML = result.description;

    sortTableBySeverity();
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

// Display scan finished message
function displayScanFinishedMessage() {
    const messageContainer = document.createElement('div');
    messageContainer.textContent = 'Scan is finished!';
    messageContainer.style.fontWeight = 'bold';
    messageContainer.style.color = 'green';
    messageContainer.style.marginTop = '20px';
    document.body.appendChild(messageContainer);
}

// Polling for results
function getResults() {
    const interval = setInterval(() => {
        fetch('/getresults')
            .then(response => response.json())
            .then(data => {
                if (data.scan_finish) {
                    clearInterval(interval);
                    displayScanFinishedMessage();
                }
                else{
                    data.results.forEach(displayResult);
                }
            })
            .catch(error => console.error('Error fetching results:', error));
    }, 5000);
}

// Initialize polling when on /results page
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname === '/results') {
        console.log('On the results page, starting polling for results...');
        getResults();
    }
});
