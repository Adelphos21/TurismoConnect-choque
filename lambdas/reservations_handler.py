# reservations_handler.py
import os
import json
import uuid
from decimal import Decimal
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key
import jwt

dynamodb = boto3.resource("dynamodb")

RESERVATIONS_TABLE_NAME = os.environ["RESERVATIONS_TABLE"]
GUIDES_TABLE_NAME = os.environ["GUIDES_TABLE"]
AUTH_JWT_SECRET = os.environ["AUTH_JWT_SECRET"]

reservas_table = dynamodb.Table(RESERVATIONS_TABLE_NAME)
guides_table = dynamodb.Table(GUIDES_TABLE_NAME)


# ---------- helpers CORS / Decimals / JWT ----------

def response(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET,PUT,DELETE"
        },
        "body": json.dumps(body)
    }


def clean_decimals(obj):
    if isinstance(obj, list):
        return [clean_decimals(i) for i in obj]
    if isinstance(obj, dict):
        return {k: clean_decimals(v) for k, v in obj.items()}
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    return obj


def _resp(status, body):
    return response(status, clean_decimals(body))


def _parse_body(event):
    try:
        return json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return None


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _get_jwt_payload(headers):
    auth = (headers or {}).get("Authorization") or (headers or {}).get("authorization")
    if not auth or not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1]
    try:
        return jwt.decode(token, AUTH_JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def _require_jwt(event):
    headers = event.get("headers") or {}
    payload = _get_jwt_payload(headers)
    if not payload:
        return None, _resp(401, {"error": "unauthorized"})
    return payload, None


def _is_guide_owner_of_reservation(payload, reserva_item):
    """Verifica si el usuario autenticado (role=guide) es dueño del guide_id de esta reserva."""
    if payload.get("role") != "guide":
        return False

    guide_id = reserva_item.get("guide_id")
    if not guide_id:
        return False

    try:
        res = guides_table.get_item(Key={"id": guide_id})
        guide = res.get("Item")
    except Exception as e:
        print("Error leyendo guía en _is_guide_owner_of_reservation:", e)
        return False

    if not guide:
        return False

    return guide.get("user_id") == payload.get("sub")


# ---------- Lambdas ----------

def create_reserva(event, context):
    payload, err = _require_jwt(event)
    if err:
        return err

    user_id = payload.get("sub")
    if not user_id:
        return _resp(401, {"error": "unauthorized"})

    body = _parse_body(event)
    if body is None:
        return _resp(400, {"error": "Invalid JSON"})

    guide_id = body.get("guide_id")
    fecha_servicio = body.get("fecha_servicio")
    duracion_horas = body.get("duracion_horas")
    precio_total = body.get("precio_total")
    comentario = body.get("comentario") or ""

    if not (guide_id and fecha_servicio and duracion_horas is not None and precio_total is not None):
        return _resp(400, {"error": "Campos requeridos: guide_id, fecha_servicio, duracion_horas, precio_total"})

    reserva_id = str(uuid.uuid4())
    now_iso = _now_iso()

    item = {
        "id": reserva_id,
        "user_id": user_id,                      # 👈 del JWT
        "guide_id": guide_id,
        "fecha_reserva": now_iso,
        "fecha_servicio": fecha_servicio,
        "duracion_horas": Decimal(str(duracion_horas)),
        "precio_total": Decimal(str(precio_total)),
        "estado": "pendiente",
        "comentario": comentario,
        "fecha_creacion": now_iso,
    }

    try:
        reservas_table.put_item(Item=item)
    except Exception as e:
        print("Error al crear reserva:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    return _resp(201, item)


def get_reserva(event, context):
    params = event.get("pathParameters") or {}
    reserva_id = params.get("id")
    if not reserva_id:
        return _resp(400, {"error": "Falta id"})

    try:
        res = reservas_table.get_item(Key={"id": reserva_id})
        item = res.get("Item")
    except Exception as e:
        print("Error get_reserva:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    if not item:
        return _resp(404, {"error": "not_found", "message": "Reserva no encontrada"})

    return _resp(200, item)


def list_reservas_usuario(event, context):
    payload, err = _require_jwt(event)
    if err:
        return err

    user_id_token = payload.get("sub")

    params = event.get("pathParameters") or {}
    user_id_path = params.get("user_id")

    # No dejar que un usuario vea reservas de otro
    if user_id_path and user_id_path != user_id_token:
        return _resp(403, {"error": "forbidden", "message": "No puedes ver reservas de otro usuario"})

    user_id = user_id_path or user_id_token

    try:
        res = reservas_table.query(
            IndexName="user_id-index",
            KeyConditionExpression=Key("user_id").eq(user_id)
        )
        items = res.get("Items", [])
    except Exception as e:
        print("Error list_reservas_usuario:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    return _resp(200, items)


def list_reservas_guia(event, context):
    payload, err = _require_jwt(event)
    if err:
        return err

    params = event.get("pathParameters") or {}
    guide_id = params.get("guide_id")
    if not guide_id:
        return _resp(400, {"error": "Falta guide_id"})

    # Verificar que este guide_id pertenece al usuario autenticado (si es guía)
    try:
        res_guide = guides_table.get_item(Key={"id": guide_id})
        guide = res_guide.get("Item")
    except Exception as e:
        print("Error leyendo guía en list_reservas_guia:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    if not guide:
        return _resp(404, {"error": "not_found", "message": "Guía no encontrado"})

    if guide.get("user_id") != payload.get("sub"):
        return _resp(403, {"error": "forbidden", "message": "No puedes ver reservas de otro guía"})

    try:
        res = reservas_table.query(
            IndexName="guide_id-index",
            KeyConditionExpression=Key("guide_id").eq(guide_id)
        )
        items = res.get("Items", [])
    except Exception as e:
        print("Error list_reservas_guia:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    return _resp(200, items)


def confirm_reserva(event, context):
    payload, err = _require_jwt(event)
    if err:
        return err

    params = event.get("pathParameters") or {}
    reserva_id = params.get("id")
    if not reserva_id:
        return _resp(400, {"error": "Falta id"})

    try:
        res = reservas_table.get_item(Key={"id": reserva_id})
        reserva = res.get("Item")
    except Exception as e:
        print("Error leyendo reserva en confirm_reserva:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    if not reserva:
        return _resp(404, {"error": "not_found", "message": "Reserva no encontrada"})

    # Solo el guía dueño de este guide_id puede confirmar
    if not _is_guide_owner_of_reservation(payload, reserva):
        return _resp(403, {"error": "forbidden", "message": "Solo el guía puede confirmar esta reserva"})

    try:
        reservas_table.update_item(
            Key={"id": reserva_id},
            UpdateExpression="SET #estado = :estado",
            ExpressionAttributeNames={"#estado": "estado"},
            ExpressionAttributeValues={":estado": "confirmado"},
        )
    except Exception as e:
        print("Error confirm_reserva:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    reserva["estado"] = "confirmado"
    return _resp(200, reserva)


def cancel_reserva(event, context):
    payload, err = _require_jwt(event)
    if err:
        return err

    params = event.get("pathParameters") or {}
    reserva_id = params.get("id")
    if not reserva_id:
        return _resp(400, {"error": "Falta id"})

    try:
        res = reservas_table.get_item(Key={"id": reserva_id})
        reserva = res.get("Item")
    except Exception as e:
        print("Error leyendo reserva en cancel_reserva:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    if not reserva:
        return _resp(404, {"error": "not_found", "message": "Reserva no encontrada"})

    user_id = payload.get("sub")
    es_turista_dueno = (user_id == reserva.get("user_id"))
    es_guia_dueno = _is_guide_owner_of_reservation(payload, reserva)

    if not (es_turista_dueno or es_guia_dueno):
        return _resp(403, {"error": "forbidden", "message": "No puedes cancelar esta reserva"})

    try:
        reservas_table.update_item(
            Key={"id": reserva_id},
            UpdateExpression="SET #estado = :estado",
            ExpressionAttributeNames={"#estado": "estado"},
            ExpressionAttributeValues={":estado": "cancelado"},
        )
    except Exception as e:
        print("Error cancel_reserva:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    reserva["estado"] = "cancelado"
    return _resp(200, reserva)
