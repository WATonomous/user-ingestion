import fastapi
from fastapi import Request, Response

def main(request: Request):
    return Response(content=f"Hello, World! FastAPI version: {fastapi.__version__}", status_code=200)
