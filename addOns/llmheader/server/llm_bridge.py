import os
from flask import Flask, request, jsonify
import google.generativeai as genai

app = Flask(__name__)

# Configure Gemini
# You can set the API key here or pass it from ZAP headers if you implemented that,
# but for this simple bridge, we'll expect it in the environment or request.
# The ZAP extension sends the key in the JSON body as 'geminiKey'.

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    headers = data.get('headers', {})
    api_key = data.get('geminiKey')
    model_name = data.get('geminiModel', 'gemini-1.5-pro')

    if not api_key:
        return jsonify({'error': 'Missing Gemini API Key'}), 400

    genai.configure(api_key=api_key)
    
    # Construct the prompt
    prompt = f"""
    Analyze the following HTTP response headers for security vulnerabilities.
    Focus on missing security headers, misconfigurations, and information leakage.
    
    Headers:
    {headers}
    
    Format your response as a JSON list of objects, where each object has:
    - "issue": Short title of the vulnerability.
    - "severity": "High", "Medium", "Low", or "Info".
    - "description": Brief explanation.
    - "recommendation": How to fix it.
    
    Return ONLY the JSON.
    """

    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)
        
        # Simple cleanup to ensure we get just the JSON part if the model chats
        text = response.text
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
            
        return jsonify({'analysis': text.strip()})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting LLM Bridge Server on port 5000...")
    app.run(port=5000)
