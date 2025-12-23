from fastapi import Response, status
from fastapi.responses import JSONResponse

"""
A collection of responses used in the application. In a real system there should not be different responses for
unsuccessful login attempts. This is just for the sake of the experiment.
"""

LOGIN_SUCCESS = Response(status_code=status.HTTP_200_OK, content="Login successful")
INVALID_CREDENTIALS = Response(status_code=status.HTTP_401_UNAUTHORIZED, content="Invalid credentials")
USERNAME_NOT_FOUND = Response(status_code=status.HTTP_404_NOT_FOUND, content="Username not found")
INVALID_TOKEN = Response(status_code=status.HTTP_403_FORBIDDEN, content="Invalid token")
INVALID_GROUP_SEED = Response(status_code=status.HTTP_404_NOT_FOUND, content="Invalid group seed")
TOO_MANY_REQUESTS = Response(status_code=status.HTTP_429_TOO_MANY_REQUESTS, content="Too many requests")
ACCOUNT_LOCKED = Response(status_code=status.HTTP_423_LOCKED, content="Account locked")
#sending a json response so client will be able to process data
CAPTCHA_REQUIRED = JSONResponse(
    status_code=403,
    content={
        "message": "Too many failed attempts. CAPTCHA required.",
        "captcha_required": True
    }
)
