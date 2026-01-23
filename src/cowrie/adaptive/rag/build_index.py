
import json
import os
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors

DOCS_FILE = "src/cowrie/adaptive/rag/mitre_documents.json"
INDEX_FILE = "src/cowrie/adaptive/rag/vector_index.pkl"

class SimpleRAGIndex:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(stop_words='english')
        self.nn_model = NearestNeighbors(n_neighbors=5, metric='cosine')
        self.documents = []

    def build(self, documents):
        self.documents = documents
        texts = [doc['name'] + " " + doc['text'] for doc in documents]
        
        print("Vectorizing documents...")
        embeddings = self.vectorizer.fit_transform(texts)
        
        print("Fitting NearestNeighbors...")
        self.nn_model.fit(embeddings)
        print("Index built successfully.")

    def save(self, filepath):
        with open(filepath, 'wb') as f:
            pickle.dump(self, f)
        print(f"Index saved to {filepath}")

    @staticmethod
    def load(filepath):
        with open(filepath, 'rb') as f:
            return pickle.load(f)

    def query(self, query_text, k=3):
        query_vec = self.vectorizer.transform([query_text])
        distances, indices = self.nn_model.kneighbors(query_vec, n_neighbors=k)
        
        results = []
        for i in range(len(indices[0])):
            idx = indices[0][i]
            dist = distances[0][i]
            doc = self.documents[idx]
            results.append({
                "doc": doc,
                "distance": dist
            })
        return results

def build_index():
    if not os.path.exists(DOCS_FILE):
        print(f"Error: {DOCS_FILE} not found. Run mitre_parser.py first.")
        return

    with open(DOCS_FILE, 'r') as f:
        documents = json.load(f)

    index = SimpleRAGIndex()
    index.build(documents)
    index.save(INDEX_FILE)

if __name__ == "__main__":
    build_index()
