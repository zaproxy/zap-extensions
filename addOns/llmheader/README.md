# LLM Header Analyzer

This ZAP add-on analyzes HTTP request headers using an LLM (Large Language Model) to detect potential security weaknesses.

## Features

*   **Header Analysis**: Sends request headers to an LLM for security analysis.
*   **Privacy Safe**: Automatically anonymizes sensitive headers (Authorization, Cookies, etc.) before sending.
*   **Flexible Modes**:
    *   **Manual**: Analyze specific requests via the context menu.
    *   **Automatic (Sampled)**: Analyze a percentage of requests automatically.
    *   **Automatic (All)**: Analyze all requests (use with caution).
*   **Dual Backend**:
    *   **Local Bridge**: Connect to a local Python script acting as a bridge to any LLM.
    *   **Direct Gemini API**: Connect directly to Google's Gemini API.
*   **Alerting**: Automatically creates ZAP alerts for detected issues.

## Setup

1.  **Build the Add-on**:
    ```bash
    ./gradlew :addOns:llmheader:copyZapAddOn
    ```
2.  **Install**: The add-on will be copied to the ZAP plugin directory. Restart ZAP.
3.  **Configure**: Go to `Tools` -> `Options` -> `LLM Header Analyzer`.
    *   Enable the extension.
    *   Choose your mode (Manual is recommended for testing).
    *   Set up your backend (Local Bridge URL or Gemini API Key).

## Local Bridge Setup (Optional)

If you prefer not to send data directly to Gemini or want to use a different model (e.g., local Llama), you can use a simple Python bridge.

```python
from flask import Flask, request, jsonify
# Import your LLM library here

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    headers = data.get('headers')
    
    # Call your LLM here with the headers
    # Expected return format:
    # [
    #   {
    #     "issue": "Missing Security Header",
    #     "severity": "Medium",
    #     "confidence": "High",
    #     "recommendation": "Add X-Content-Type-Options: nosniff"
    #   }
    # ]
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(port=5000)
```

## Privacy Warning

By default, this add-on anonymizes common sensitive headers. However, please review the `HeaderAnonymizer.java` class and the options to ensure it meets your privacy requirements before sending data to external APIs.

## Disclaimer

LLM-generated alerts may contain false positives. All alerts are created with **Low Confidence** by default and should be verified manually.
