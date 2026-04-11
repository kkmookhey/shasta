# Test file for rag_no_access_control.yaml rules

# --- LangChain ---
# ruleid: code-rag-no-access-control-similarity-search
results = store.similarity_search("query text")

# ok: code-rag-no-access-control-similarity-search
results = store.similarity_search("query text", filter={"tenant_id": tid})

# ruleid: code-rag-no-access-control-similarity-search
retriever = store.as_retriever()

# ok: code-rag-no-access-control-similarity-search
retriever = store.as_retriever(search_kwargs={"filter": {"user": uid}})

# --- Pinecone ---
# ruleid: code-rag-no-access-control-pinecone
results = index.query(vector=embedding, top_k=10)

# ok: code-rag-no-access-control-pinecone
results = index.query(vector=embedding, top_k=10, filter={"tenant": tid})

# ok: code-rag-no-access-control-pinecone
results = index.query(vector=embedding, top_k=10, namespace="tenant-123")

# --- Chroma ---
# ruleid: code-rag-no-access-control-chroma
results = collection.query(query_texts=["search term"])

# ok: code-rag-no-access-control-chroma
results = collection.query(query_texts=["search term"], where={"user_id": uid})

# --- Qdrant ---
# ruleid: code-rag-no-access-control-qdrant
results = client.search(collection_name="docs", query_vector=vec)

# ok: code-rag-no-access-control-qdrant
results = client.search(collection_name="docs", query_vector=vec, query_filter=f)

# --- Weaviate ---
# ruleid: code-rag-no-access-control-weaviate
results = collection.query.near_text(query="search term")

# ok: code-rag-no-access-control-weaviate
results = collection.query.near_text(query="search term", filters=f)
