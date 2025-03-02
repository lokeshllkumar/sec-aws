from dotenv import load_dotenv
import os

load_dotenv(dotenv_path = "../../.env")
openai_api_key = os.getenv("OPENAI_API_KEY")