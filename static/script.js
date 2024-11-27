const queryButton = document.getElementById('queryButton');
const requeryButton = document.getElementById('requeryButton');
const domainInput = document.getElementById('domainInput');
var lastDomain = "";
var lastRecordTypes = [];

domainInput.addEventListener('keydown', async (event) => {
    if (event.key === 'Enter') {
        if (lastRecordTypes && lastDomain == domainInput.value) {
            await queryDomain(requeryButton, lastRecordTypes);
        } else {
            await queryDomain(queryButton);
        }
    }
});

queryButton.addEventListener('click', async () => {
    await queryDomain(queryButton);
});

requeryButton.addEventListener('click', async () => {
    if (lastRecordTypes && lastDomain == domainInput.value) {
        await queryDomain(requeryButton, lastRecordTypes);
    } else {
        await queryDomain(queryButton);
    }
    
});

async function queryDomain(button, types) {
    const domain = document.getElementById('domainInput').value;
    const responseContainer = document.getElementById('responseContainer');
    var loadingSpinner = null;
    if (types === undefined) {
        loadingSpinner = document.getElementById('loadingSpinner2');
    } else {
        loadingSpinner = document.getElementById('loadingSpinner');
    }
    responseContainer.innerHTML = '';

    loadingSpinner.style.display = 'block';
    button.style.color = window.getComputedStyle(loadingSpinner).backgroundColor;;
    button.classList.add('loading');
    button.disabled = true;

    try {
        let response;
        const requestOptions = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(types === undefined ? { domain } : { domain, types })
        };

        response = await fetch(types === undefined ? '/dns-query' : '/dns-requery', requestOptions);

        if (response && response.status === 429) {
            responseContainer.innerHTML = '<div class="error">Error: Ratelimited, wait before trying again!</div>';
            cleanupAfterRequest(loadingSpinner, button);
            return;
        }

        const data = await response.json();
        lastDomain = domain;

        if (data.error !== undefined) {
            responseContainer.innerHTML = `<div class="error">Error: ${data.error}</div>`;
            lastRecordTypes = [];
        } else {
            displayResults(data.comparison);
            lastRecordTypes = data.types;
        }

    } catch (error) {
        if (error.name === 'TypeError') {
            responseContainer.innerHTML = '<div class="error">Error: Network error or server did not respond!</div>';
        } else {
            responseContainer.innerHTML = `<div class="error">Error: ${error.message}</div>`;
        }
    }
    cleanupAfterRequest(loadingSpinner, button);
}

function cleanupAfterRequest(loadingSpinner, button) {
    loadingSpinner.style.display = 'none';
    button.style.color = "rgb(49, 50, 68)";
    button.classList.remove('loading');
    button.disabled = false;
}

function displayResults(comparison) {
    const responseContainer = document.getElementById('responseContainer');
    responseContainer.innerHTML = '';

    // Display matching records
    const matchingTable = createMatchingTable('Matching Records', comparison.matching);
    responseContainer.appendChild(matchingTable);

    // Display outliers
    if (Object.keys(comparison.outliers).length > 0) {
        const outliersTable = createOutliersTable('Outliers', comparison.outliers);
        responseContainer.appendChild(outliersTable);
    }
}

function getRemainingTime(targetTimestamp) {
    const now = new Date().getTime();
    const targetTime = new Date(targetTimestamp).getTime();
    const remainingTime = targetTime - now;
  
    if (remainingTime <= 0) return "0s";
  
    const hours = Math.floor((remainingTime / (1000 * 60 * 60)) % 24);
    const minutes = Math.floor((remainingTime / (1000 * 60)) % 60);
    const seconds = Math.floor((remainingTime / 1000) % 60);
  
    var formattedTime = String(seconds) + "s";
    if (minutes > 0) {
        formattedTime = String(minutes) + "m" + formattedTime
        if (hours > 0) {
            formattedTime = String(hours) + "h" + formattedTime
        }
    }
  
    return formattedTime;
  }

function createMatchingTable(title, data) {
    const table = document.createElement('table');
    table.innerHTML = `
                <tr>
                    <th colspan="5">${title}</th>
                </tr>
                <tr>
                    <th>Record Type</th>
                    <th>Data</th>
                    <th>Owner</th>
                    <th>Match Status</th>
                </tr>
            `;

    for (const [recordType, recordInfo] of Object.entries(data)) {
        const row = table.insertRow();
        row.innerHTML = `
                    <td>${recordType}</td>
                    <td>${recordInfo.data.join(', <br>')}</td>
                    <td>${recordInfo.owner}</td>
                    <td>${recordInfo.full_match ? 'Full Match' : `Partial Match (${recordInfo.agreeing_nameservers.length}/${recordInfo.total_nameservers} nameservers)`}</td>
                `; // <td>${getRemainingTime(recordInfo.expiry * 1000)}</td>
        if (!recordInfo.full_match) {
            row.classList.add('partial-match');
        }
    }

    return table;
}

function createOutliersTable(title, data) {
    const table = document.createElement('table');
    table.innerHTML = `
                <tr>
                    <th colspan="5">${title}</th>
                </tr>
                <tr>
                    <th>Record Type</th>
                    <th>Nameservers</th>
                    <th>Data</th>
                    <th>TTL</th>
                    <th>Owner</th>
                </tr>
            `;

    for (const [recordType, outliers] of Object.entries(data)) {
        for (const [nameservers, recordDetails] of Object.entries(outliers)) {
            const row = table.insertRow();
            row.innerHTML = `
                        <td>${recordType}</td>
                        <td>${nameservers}</td>
                        <td>${recordDetails.data.join(', <br>')}</td>
                        <td>${getRemainingTime(recordDetails.expiry * 1000)}</td>
                        <td>${recordDetails.owner}</td>
                    `;
        }
    }

    return table;
}