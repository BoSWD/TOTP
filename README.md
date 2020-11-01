# TOTP Microservice Scaffolding

This is an educational microservice that implements a basic TOTP 2fa logic, made with FastAPI. 


## Running

```uvicorn main:app --reload```

Note: you need `uvicorn` installed to run it this way.

Also you can use swagger client to interact with API:
```http://127.0.0.1:8000/docs```

## Testing

TOTP module contains unit tests and microservice tests:

```
pytest
```

Note: you need `pytest` installed to run it in this way.
