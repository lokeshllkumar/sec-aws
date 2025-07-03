from sentence_transformers import SentenceTransformer

def generate_embeddings(input: str):
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    embeddings = model.encode(input, show_progress_bar = True).tolist()
    return embeddings