from string import Template

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
import jwt
from utils import EMAIL_VERIFICATION_KEY, process_token, send_verification_email

async def handle_get(request: Request):
    # extract token from query params
    token = request.query_params.get("token")

    if not token:
        return JSONResponse(
            status_code=401, content={"error": "Missing token in the query params"}
        )

    # Validate the JWT
    try:
        jwt.decode(token, EMAIL_VERIFICATION_KEY, algorithms="HS256")
    except jwt.InvalidTokenError:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})

    return HTMLResponse(
        status_code=200,
        content=Template(
            """
            <!DOCTYPE html>
            <html>
            <body>
                <h1>Verify email address</h1>
                <button id="verify-btn">Click to verify email</button>
                <p id="status"></p>

                <script>
                const btn = document.getElementById("verify-btn");
                const status = document.getElementById("status");

                btn.addEventListener("click", async () => {
                    btn.disabled = true;
                    status.innerText = "Verifying...";

                    const token = "$token";

                    try {
                        const response = await fetch("", {
                            method: "POST",
                            headers: {
                            "Content-Type": "application/json"
                            },
                            body: JSON.stringify({ token })
                        });

                        if (response.ok) {
                            status.innerText = "Email verified successfully!";
                            status.style.color = "green";
                        } else {
                            status.innerText = "Verification failed!" + response.text;
                            status.style.color = "red";
                        }
                    } catch (error) {
                        status.innerText = "Network or server error: " + error;
                        status.style.color = "red";
                    }
                });
                </script>
            </body>
            </html>
        """
        ).substitute(token=token),
    )


async def handle_post(request: Request):
    try:
        reqbody = await request.json()
    except ValueError as e:
        return JSONResponse(
            status_code=400, content={"error": "Invalid payload", "details": str(e)}
        )

    if "data" in reqbody:
        return await send_verification_email(reqbody["data"])

    if "token" in reqbody:
        return await process_token(reqbody["token"])

    return JSONResponse(
        status_code=400,
        content={
            "error": "Invalid payload",
            "details": "No handler found for this payload",
        },
    )

async def main(request: Request):
    if request.method == "GET":
        return await handle_get(request)
    elif request.method == "POST":
        return await handle_post(request)
    else:
        raise HTTPException(
            status_code=HTTPStatus.METHOD_NOT_ALLOWED,
            detail=f"Method {request.method} not allowed",
        )
