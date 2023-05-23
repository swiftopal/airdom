// Select the necessary elements
const emailForm = document.getElementById('emailForm');
const domainInput = document.getElementById('domain');
const loader = document.getElementById('loader');
const resultContainer = document.getElementById('result-container');
const result = document.getElementById('result');
const errorMessage = document.getElementById('error-message');

// Domain format regular expression
const domainRegex = /^(?![.-])(?!\d+\.$)(([a-zA-Z0-9_][a-zA-Z0-9_-]{0,62})?[a-zA-Z0-9]\.)+([a-zA-Z]{2,63})$/;

// Handle form submission
emailForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  // Clear previous results and error message
  resultContainer.style.display = 'none';
  result.innerHTML = '';
  errorMessage.innerHTML = '';

  // Retrieve the domain value
  const domain = domainInput.value.trim();

  if (domain === '') {
    errorMessage.innerHTML = 'Please enter a domain.';
    return;
  }

  // Validate the domain format
  if (!domainRegex.test(domain)) {
    errorMessage.innerHTML = 'Please enter a valid domain.';
    return;
  }

  // Display the loader
  loader.style.display = 'block';

  try {
    // Send a GET request to the server
    const response = await fetch(`/validate-email?domain=${encodeURIComponent(domain)}`);

    // Parse the response as JSON
    const data = await response.json();

    // Check if the response is successful
    if (response.ok) {
      // Format the results
      const formattedResults = `
        <div class="result-row">
          <span class="result-label">DMARC:</span>
          <span class="result-value">${data.dmarc}</span>
        </div>
        <div class="result-separator"></div>
        <div class="result-row">
          <span class="result-label">SPF:</span>
          <span class="result-value">${data.spf}</span>
        </div>
        <div class="result-separator"></div>
        <div class="result-row">
          <span class="result-label">DKIM:</span>
          <span class="result-value">${data.dkim}</span>
        </div>
        <div class="result-separator"></div>
        <div class="result-row">
          <span class="result-label">MTA-STS:</span>
          <span class="result-value">${data.mtaSts}</span>
        </div>
        <div class="result-separator"></div>
        <div class="result-row">
          <span class="result-label">TLS:</span>
          <span class="result-value">${data.tls}</span>
        </div>
        <div class="result-separator"></div>
        <div class="result-row">
          <span class="result-label">MX:</span>
          <span class="result-value">${data.mx}</span>
        </div>
        <div class="result-separator"></div>
        <div class="result-row">
          <span class="result-label">DMARC Recommendation:</span>
          <span class="result-value">${data.dmarcRecommendation}</span>
        </div>
        <div class="result-separator"></div>
        <div class="result-row">
          <span class="result-label">SPF Recommendation:</span>
          <span class="result-value">${data.spfRecommendation}</span>
        </div>
        <div class="result-separator"></div>
        <div class="result-row">
          <span class="result-label">DKIM Recommendation:</span>
          <span class="result-value">${data.dkimRecommendation}</span>
        </div>
        <div class="result-separator"></div>
        <div class="result-row">
          <span class="result-label">MTA-STS Recommendation:</span>
          <span class="result-value">${data.mtaStsRecommendation}</span>
        </div>
        <div class="result-separator"></div>
        <div class="result-row">
          <span class="result-label">TLS Recommendation:</span>
          <span class="result-value">${data.tlsRecommendation}</span>
        </div>
        <div class="result-separator"></div>
        <div class="result-row">
          <span class="result-label">MX Recommendation:</span>
          <span class="result-value">${data.mxRecommendation}</span>
        </div>
      `;

      // Display the results
      result.innerHTML = formattedResults;
      resultContainer.style.display = 'block';
    } else {
      // Display the error message
      errorMessage.innerHTML = data.error;
    }
  } catch (error) {
    // Display a generic error message
    errorMessage.innerHTML = 'An error occurred. Please try again later.';
  } finally {
    // Hide the loader
    loader.style.display = 'none';
  }
});
