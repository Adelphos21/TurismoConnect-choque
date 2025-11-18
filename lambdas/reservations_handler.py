# reservations_handler.py
import os
import json
import uuid
from decimal import Decimal
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource("dynamodb")
RES_TABLE_NAME = os.environ["RESERVATIONS_TABLE"]
res_table = dynamodb.Table(RES_TABLE_NAME)


def _decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError


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


def create_reserva(event, context):
    body = _parse_body(event)
    if body is None:
        return _resp(400, {"error": "Invalid JSON"})

    required_fields = ["user_id", "guide_id", "fecha_servicio", "duracion_horas", "precio_total"]
    if any(body.get(f) is None for f in required_fields):
        return _resp(400, {"error": "Campos obligatorios faltantes"})

    now = datetime.now(timezone.utc).isoformat()
    reserva_id = str(uuid.uuid4())

    item = {
        "id": reserva_id,
        "user_id": body["user_id"],
        "guide_id": body["guide_id"],
        "fecha_reserva": now,
        "fecha_servicio": body["fecha_servicio"],
        "duracion_horas": Decimal(str(body["duracion_horas"])),
        "precio_total": Decimal(str(body["precio_total"])),
        "estado": "pendiente",
        "comentario": body.get("comentario") or "",
        "fecha_creacion": now,
    }

    try:
        res_table.put_item(Item=item)
    except Exception as e:
        print("Error al crear reserva:", e)
        return _resp(500, {"error": "Error al crear la reserva"})

    return _resp(201, item)


def get_reserva(event, context):
    reserva_id = (event.get("pathParameters") or {}).get("id")
    if not reserva_id:
        return _resp(400, {"error": "Falta id"})

    resp = res_table.get_item(Key={"id": reserva_id})
    item = resp.get("Item")
    if not item:
        return _resp(404, {"error": "Reserva no encontrada"})

    return _resp(200, item)


def confirm_reserva(event, context):
    reserva_id = (event.get("pathParameters") or {}).get("id")
    if not reserva_id:
        return _resp(400, {"error": "Falta id"})

    try:
        resp = res_table.update_item(
            Key={"id": reserva_id},
            UpdateExpression="SET #estado = :estado",
            ExpressionAttributeNames={"#estado": "estado"},
            ExpressionAttributeValues={":estado": "confirmado"},
            ReturnValues="ALL_NEW",
        )
    except Exception as e:
        print("Error al confirmar reserva:", e)
        return _resp(500, {"error": "Error al confirmar la reserva"})

    if "Attributes" not in resp:
        return _resp(404, {"error": "Reserva no encontrada"})

    return _resp(200, resp["Attributes"])


def cancel_reserva(event, context):
    reserva_id = (event.get("pathParameters") or {}).get("id")
    if not reserva_id:
        return _resp(400, {"error": "Falta id"})

    try:
        resp = res_table.update_item(
            Key={"id": reserva_id},
            UpdateExpression="SET #estado = :estado",
            ExpressionAttributeNames={"#estado": "estado"},
            ExpressionAttributeValues={":estado": "cancelado"},
            ReturnValues="ALL_NEW",
        )
    except Exception as e:
        print("Error al cancelar reserva:", e)
        return _resp(500, {"error": "Error al cancelar la reserva"})

    if "Attributes" not in resp:
        return _resp(404, {"error": "Reserva no encontrada"})

    return _resp(200, resp["Attributes"])


def list_reservas_usuario(event, context):
    user_id = (event.get("pathParameters") or {}).get("user_id")
    if not user_id:
        return _resp(400, {"error": "Falta user_id"})

    try:
        resp = res_table.query(
            IndexName="user_id-index",
            KeyConditionExpression=Key("user_id").eq(user_id),
        )
    except Exception as e:
        print("Error listando reservas por usuario:", e)
        return _resp(500, {"error": "Error al listar reservas"})
    return _resp(200, resp.get("Items", []))


def list_reservas_guia(event, context):
    guide_id = (event.get("pathParameters") or {}).get("guide_id")
    if not guide_id:
        return _resp(400, {"error": "Falta guide_id"})

    try:
        resp = res_table.query(
            IndexName="guide_id-index",
            KeyConditionExpression=Key("guide_id").eq(guide_id),
        )
    except Exception as e:
        print("Error listando reservas por guía:", e)
        return _resp(500, {"error": "Error al listar reservas"})
    return _resp(200, resp.get("Items", []))
