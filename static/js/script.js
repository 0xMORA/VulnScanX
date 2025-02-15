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
    fetch('http://127.0.0.1:80/start-scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(jsonObject)
    })
    .then(response => response.json()) // Parse the response as JSON
    .then(data => {
        if (data.message) {
            // Redirect to the results page with the URL parameter
            const targetUrl = jsonObject.url; // Get the URL from the form data
            window.location.href = `/results?url=${encodeURIComponent(targetUrl)}`;
        } else if (data.error) {
            // Display an error message if the scan failed
            alert(`Error: ${data.error}`);
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
        alert('An error occurred while starting the scan. Please try again.');
    });
});