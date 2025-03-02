from internal.embedding import generate_embedding
from internal.generate_fix import generate_fix
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI()

class EmbeddingRequest(BaseModel):
    inp: str

class EmbeddingResponse(BaseModel):
    embedding: list

class FixRequest(BaseModel):
    context: str

class FixResponse(BaseModel):
    fix: str

@app.post("/embedding")
def gen_embedding(request: EmbeddingRequest):
    embedding = generate_embedding(request.inp)
    return EmbeddingResponse(embedding = embedding)

@app.post("/fix")
def gen_fix(request: FixRequest):
    fix = generate_fix(request.context)
    return FixResponse(fix = fix)

if __name__ == "__main__":
    uvicorn.run(app, host = "0.0.0.0", port = "8000")