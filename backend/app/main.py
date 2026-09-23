from fastapi import FastAPI

app = FastAPI(title="SPECTRA Backend", version="0.1.0")


@app.get("/health")
async def health() -> dict[str, str]:
    """Minimal health endpoint for the backend foundation."""
    return {"status": "ok"}
