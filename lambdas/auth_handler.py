# auth_handler.py
import os
import json
import uuid
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta

import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource("dynamodb")

USERS_TABLE_NAME = os.environ["USERS_TABLE"]
AUTH_JWT_SECRET = os.environ["AUTH_JWT_SECRET"]
AUTH_JWT_EXP_DAYS = int(os.environ.get("AUTH_JWT_EXP_DAYS", "7"))

users_table = dynamodb.Table(USERS_TABLE_NAME)


def _resp(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE"
        },
        "body": json.dumps(body),
    }



def _parse_body(event):
    try:
        return json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return None


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _create_token(user):
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "role": user.get("role", "tourist"),
        "exp": datetime.now(timezone.utc) + timedelta(days=AUTH_JWT_EXP_DAYS),
        "iat": datetime.now(timezone.utc),
    }
    token = jwt.encode(payload, AUTH_JWT_SECRET, algorithm="HS256")
    # pyjwt v2 devuelve str
    return token


def _get_user_by_email(email):
    res = users_table.query(
        IndexName="email-index",
        KeyConditionExpression=Key("email").eq(email),
    )
    items = res.get("Items", [])
    return items[0] if items else None


def register_user(event, context):
    """
    POST /auth/register
    body: { email, username, password, role? }
    """
    body = _parse_body(event)
    if body is None:
        return _resp(400, {"error": "Invalid JSON"})

    email = (body.get("email") or "").strip().lower()
    username = (body.get("username") or "").strip()
    password = body.get("password")
    role = (body.get("role") or "tourist").strip()

    if not email or not username or not password:
        return _resp(400, {"error": "email, username y password son obligatorios"})

    # check if exists
    if _get_user_by_email(email):
        return _resp(409, {"error": "User already exists"})

    user_id = str(uuid.uuid4())
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    item = {
        "id": user_id,
        "email": email,
        "username": username,
        "password_hash": password_hash,
        "role": role,
        "createdAt": _now_iso(),
    }

    users_table.put_item(Item=item)

    token = _create_token(item)

    return _resp(
        201,
        {
            "id": user_id,
            "email": email,
            "username": username,
            "role": role,
            "access": token,
        },
    )


def login_user(event, context):
    """
    POST /auth/login
    body: { email, password }
    """
    body = _parse_body(event)
    if body is None:
        return _resp(400, {"error": "Invalid JSON"})

    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return _resp(400, {"error": "email y password son obligatorios"})

    user = _get_user_by_email(email)
    if not user:
        return _resp(401, {"error": "Invalid credentials"})

    stored_hash = user.get("password_hash", "")
    if not stored_hash:
        return _resp(401, {"error": "Invalid credentials"})

    ok = bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    if not ok:
        return _resp(401, {"error": "Invalid credentials"})

    token = _create_token(user)

    return _resp(
        200,
        {
            "access": token,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "username": user["username"],
                "role": user.get("role", "tourist"),
            },
        },
    )


def _get_user_from_token(headers):
    auth = (headers or {}).get("Authorization") or (headers or {}).get("authorization")
    if not auth or not auth.startswith("Bearer "):
        return None

    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, AUTH_JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    res = users_table.get_item(Key={"id": user_id})
    return res.get("Item")


def me(event, context):
    """
    GET /auth/me
    Authorization: Bearer <token>
    """
    headers = event.get("headers") or {}
    user = _get_user_from_token(headers)
    if not user:
        return _resp(401, {"error": "Unauthorized"})

    return _resp(
        200,
        {
            "id": user["id"],
            "email": user["email"],
            "username": user["username"],
            "role": user.get("role", "tourist"),
            "createdAt": user.get("createdAt"),
        },
    )
