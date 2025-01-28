document.getElementById('scan-form').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent the form from submitting the traditional way

    // Get form data
    const formData = new FormData(this);

    // Convert FormData to JSON
    const jsonObject = {};
    formData.forEach((value, key) => {
        jsonObject[key] = value;
    });

    // Send the form data using fetch
    fetch('https://127.0.0.1:80/start-scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(jsonObject)
    })
    .then(response)
    .then(data => {
        if (data) {
            // Redirect to the results page with the scan ID
            window.location.href = `/results`;
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
    });
});

// WebSocket connection for real-time results
function connectWebSocket(scanId) {
    const ws = new WebSocket(`wss://127.0.0.1:80/results`);

    ws.onopen = () => {
        console.log('WebSocket connection established');
    };

    ws.onmessage = (event) => {
        const result = JSON.parse(event.data);
        displayResult(result);
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };

    ws.onclose = () => {
        console.log('WebSocket connection closed');
    };
}

// Display results dynamically
function displayResult(result) {
    const resultsTable = document.getElementById('results-table').getElementsByTagName('tbody')[0];

    // Create a new row for the result
    const newRow = resultsTable.insertRow();

    // Add cells for each column
    const vulnerabilityCell = newRow.insertCell(0);
    const severityCell = newRow.insertCell(1);
    const urlCell = newRow.insertCell(2);
    const descriptionCell = newRow.insertCell(3);

    // Populate the cells with data
    vulnerabilityCell.textContent = result.vulnerability;
    severityCell.textContent = result.severity;
    urlCell.textContent = result.url;
    descriptionCell.innerHTML = result.description;

    // Sort the table by severity (High > Medium > Low)
    sortTableBySeverity();
}

// Sort the table by severity
function sortTableBySeverity() {
    const table = document.getElementById('results-table');
    const tbody = table.getElementsByTagName('tbody')[0];
    const rows = Array.from(tbody.getElementsByTagName('tr'));

    // Define severity order
    const severityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };

    rows.sort((a, b) => {
        const severityA = severityOrder[a.cells[1].textContent];
        const severityB = severityOrder[b.cells[1].textContent];
        return severityB - severityA; // Sort in descending order
    });

    // Re-append sorted rows to the table
    rows.forEach(row => tbody.appendChild(row));
}

// Check if we are on the results page and connect WebSocket
if (window.location.pathname === '/results') {
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('scanId');

    if (scanId) {
        connectWebSocket(scanId);
    }
}