# src/risk_analysis.py
import openai

# Set your OpenAI API key
openai.api_key = "openai_api_key"

def refine_risk_with_llm(threat_description):
    """
    Use GPT-4 to refine likelihood and impact scores based on threat description.
    Args:
        threat_description (str): Description of the threat.
    Returns:
        tuple: Refined likelihood and impact scores.
    """
    prompt = f"""
    Analyze the following threat description and provide likelihood and impact scores (1-5):
    Threat Description: {threat_description}
    Format your response as: likelihood=X, impact=Y
    """
    
    response = openai.Completion.create(
        engine="gpt-4",  # Use GPT-4 model
        prompt=prompt,
        max_tokens=50,
        n=1,
        stop=None,
        temperature=0.7,
    )
    
    # Extract likelihood and impact from the response
    result = response.choices[0].text.strip()
    likelihood = int(result.split("likelihood=")[1].split(",")[0])
    impact = int(result.split("impact=")[1])
    
    return likelihood, impact

# Example usage
threat_description = "SQL Injection vulnerability in the customer database."
likelihood, impact = refine_risk_with_llm(threat_description)
risk_score = calculate_risk(likelihood, impact)
print(f"Refined Likelihood: {likelihood}, Refined Impact: {impact}, Risk Score: {risk_score}")