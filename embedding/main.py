from internal.embedding import generate_embeddings
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI()

class EmbeddingRequest(BaseModel):
    text: str

class EmbeddingResponse(BaseModel):
    embeddings: list

@app.post("/embeddings")
def gen_embeddings(request: EmbeddingRequest) -> EmbeddingResponse:
    """
    Generate embeddings for the provided text.
    """
    embeddings = generate_embeddings(request.text)
    return EmbeddingResponse(embeddings = embeddings)

if __name__ == "__main__":
    uvicorn.run(app, host = "0.0.0.0", port = "8000")