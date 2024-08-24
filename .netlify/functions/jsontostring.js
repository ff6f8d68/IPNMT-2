const fetch = require('node-fetch');

exports.handler = async function(event, context) {
    const url = event.queryStringParameters.url;

    if (!url) {
        return {
            statusCode: 400,
            body: 'Please provide a URL parameter with the key "url".'
        };
    }

    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();

        // Convert JSON to "key = value" format
        const formattedData = Object.entries(data)
                                    .map(([key, value]) => `${key} = ${value}`)
                                    .join('\n');

        // Return the formatted data as plain text
        return {
            statusCode: 200,
            headers: { 'Content-Type': 'text/plain' },
            body: formattedData
        };
    } catch (error) {
        return {
            statusCode: 500,
            body: `Error fetching JSON data: ${error.message}`
        };
    }
};
