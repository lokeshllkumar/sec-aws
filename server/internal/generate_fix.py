from openai import OpenAI
from utils import openai_api_key

def generate_fix(fix_request: str) -> str:
    prompt = f"""
        Provide a detailed fix for the following AWS security issue:\n{fix_request}.\n
        A relevant security fix has been provided for context.
        The response should be clear, actionable, and follow best security practices.
    """

    client = OpenAI(api_key = openai_api_key)

    try:
        response = client.chat.completions.create(
            model = "gpt-4o-mini",
            messages = [
                {"role": "system", "content": "You are an AWS security expert providing security fixes for security issues."},
                {"role": "user", "content": prompt}
            ]
        )
        
        fix = response["choices"][0]["message"]["content"].strip()
        return fix
    except Exception as e:
        return ""