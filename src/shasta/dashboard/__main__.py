"""Entry point for running the Shasta dashboard."""

import uvicorn

from shasta.dashboard.app import app

if __name__ == "__main__":
    print("Shasta Dashboard starting at http://127.0.0.1:8080")
    uvicorn.run(app, host="127.0.0.1", port=8080)
