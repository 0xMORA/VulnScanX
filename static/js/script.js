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
    .then(response => response.text())
    .then(data => {
        if (data) {
            // Redirect to the results page 
            window.location.href = `/results`;
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
    });
});

