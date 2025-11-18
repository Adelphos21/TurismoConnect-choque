# guides_handler.py
import os
import json
import uuid
from decimal import Decimal
from datetime import datetime, timezone, timedelta

import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource("dynamodb")

GUIDES_TABLE_NAME = os.environ["GUIDES_TABLE"]
AVAIL_TABLE_NAME = os.environ["GUIDE_AVAILABILITY_TABLE"]
PRICES_TABLE_NAME = os.environ["GUIDE_PRICES_TABLE"]
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")

guides_table = dynamodb.Table(GUIDES_TABLE_NAME)
avail_table = dynamodb.Table(AVAIL_TABLE_NAME)
prices_table = dynamodb.Table(PRICES_TABLE_NAME)


def _decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError


def _resp(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=_decimal_default),
    }


def _parse_body(event):
    try:
        return json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return None


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _to_slot_id(date_str: str, start: str, end: str) -> str:
    return f"{date_str}#{start}#{end}"


def _map_guide_item_to_get_response(item):
    languages = item.get("languages") or []
    return {
        "id": item["id"],
        "nombres": item.get("nombres"),
        "apellidos": item.get("apellidos"),
        "city": item.get("city"),
        "country": item.get("country"),
        "bio": item.get("bio"),
        "certification": item.get("certification"),
        "ratingAvg": float(item.get("ratingAvg", 0)),
        "languages": [
            {"code": l.get("code"), "name": l.get("name")} for l in languages
        ],
    }


def _map_guide_item_to_search_response(item):
    languages = item.get("languages") or []
    return {
        "id": item["id"],
        "fullName": f"{item.get('nombres', '')} {item.get('apellidos', '')}".strip(),
        "city": item.get("city"),
        "ratingAvg": float(item.get("ratingAvg", 0)),
        "certification": item.get("certification"),
        "languages": [l.get("code") for l in languages],
    }


def _require_internal_token(headers):
    token = (headers or {}).get("X-Internal-Token") or (headers or {}).get("x-internal-token")
    return token and INTERNAL_TOKEN and token == INTERNAL_TOKEN


# ------------- GUIDES -------------


def create_guide(event, context):
    body = _parse_body(event)
    if body is None:
        return _resp(400, {"error": "Invalid JSON"})

    required = ["nombres", "apellidos", "dni", "bio", "city", "country", "certification", "languages", "correo"]
    if any(body.get(f) in (None, "") for f in required):
        return _resp(400, {"error": "Campos obligatorios faltantes"})

    dni = body["dni"]
    correo = body["correo"]

    # Conflicto simple por scan
    scan = guides_table.scan()
    for item in scan.get("Items", []):
        if item.get("dni") == dni:
            return _resp(409, {"error": "CONFLICT", "message": "Ya existe un usuario con este DNI"})
        if item.get("correo") == correo:
            return _resp(409, {"error": "CONFLICT", "message": "Ya existe un usuario registrado con este correo"})

    guide_id = str(uuid.uuid4())
    languages = body.get("languages") or []
    lang_list = [{"code": l.get("code"), "name": l.get("name")} for l in languages]

    item = {
        "id": guide_id,
        "dni": dni,
        "nombres": body["nombres"],
        "apellidos": body["apellidos"],
        "correo": correo,
        "bio": body["bio"],
        "city": body["city"],
        "country": body["country"],
        "ratingAvg": Decimal("0"),
        "ratingCount": Decimal("0"),
        "createdAt": _now_iso(),
        "certification": bool(body["certification"]),
        "languages": lang_list,
    }

    try:
        guides_table.put_item(Item=item)
    except Exception as e:
        print("Error al crear guía:", e)
        return _resp(400, {"error": "SYSTEM_ERROR", "message": f"Error al crear el guía: {str(e)}"})

    return _resp(201, {"id": guide_id, "message": "Guía creado exitosamente"})


def edit_guide(event, context):
    params = event.get("pathParameters") or {}
    guide_id = params.get("id")
    if not guide_id:
        return _resp(400, {"error": "Falta id"})

    body = _parse_body(event)
    if body is None:
        return _resp(400, {"error": "Invalid JSON"})

    update_expr = []
    expr_names = {}
    expr_values = {}

    if body.get("bio"):
        update_expr.append("#bio = :bio")
        expr_names["#bio"] = "bio"
        expr_values[":bio"] = body["bio"]

    if body.get("city"):
        update_expr.append("#city = :city")
        expr_names["#city"] = "city"
        expr_values[":city"] = body["city"]

    if body.get("languages"):
        lang_list = [
            {"code": l.get("code"), "name": l.get("name")}
            for l in body.get("languages", [])
        ]
        update_expr.append("#languages = :languages")
        expr_names["#languages"] = "languages"
        expr_values[":languages"] = lang_list

    if not update_expr:
        return _resp(200, {"message": "Nada que actualizar"})

    try:
        guides_table.update_item(
            Key={"id": guide_id},
            UpdateExpression="SET " + ", ".join(update_expr),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
            ReturnValues="UPDATED_NEW",
        )
    except Exception as e:
        print("Error al actualizar guía:", e)
        return _resp(400, {"error": str(e) or "Ocurrió un error inesperado"})

    return _resp(200, {"message": "Perfil de guia modificado correctamente"})


def get_guide(event, context):
    params = event.get("pathParameters") or {}
    guide_id = params.get("id")
    if not guide_id:
        return _resp(400, {"error": "Falta id"})

    try:
        res = guides_table.get_item(Key={"id": guide_id})
        item = res.get("Item")
    except Exception as e:
        print("Error get_guide:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    if not item:
        return _resp(404, {"error": "not_found", "message": "Guia no encontrado!"})

    return _resp(200, _map_guide_item_to_get_response(item))


def search_guides(event, context):
    qs = event.get("queryStringParameters") or {}
    city = qs.get("city")
    date_str = qs.get("date")  # YYYY-MM-DD
    language = qs.get("language")
    cert_str = qs.get("certification")

    certification = None
    if cert_str is not None:
        certification = cert_str.lower() == "true"

    try:
        scan = guides_table.scan()
        items = scan.get("Items", [])
    except Exception as e:
        print("Error scan guides:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    city_lower = city.lower() if city else None
    language_lower = language.lower() if language else None

    filtered = []
    for item in items:
        if city_lower:
            if not item.get("city"):
                continue
            if city_lower not in item["city"].lower():
                continue

        if certification is not None:
            if bool(item.get("certification")) != certification:
                continue

        if language_lower:
            langs = item.get("languages") or []
            codes = [l.get("code", "") for l in langs]
            names = [l.get("name", "") for l in langs]
            match_lang = any(language_lower in c.lower() for c in codes) or any(
                language_lower in n.lower() for n in names
            )
            if not match_lang:
                continue

        filtered.append(item)

    results = []
    for item in filtered:
        dto = _map_guide_item_to_search_response(item)

        if date_str:
            res_av = avail_table.query(
                KeyConditionExpression=Key("guide_id").eq(item["id"])
            )
            slots = [
                s
                for s in res_av.get("Items", [])
                if s.get("date") == date_str and s.get("status") == "FREE"
            ]
            if slots:
                slots.sort(key=lambda x: x.get("startTime", "00:00"))
                s0 = slots[0]
                dto["nextAvailable"] = {
                    "startTime": s0["startTime"],
                    "endTime": s0["endTime"],
                    "status": s0["status"],
                }

        prices = prices_table.query(
            KeyConditionExpression=Key("guide_id").eq(item["id"])
        )
        plist = prices.get("Items", [])
        if plist:
            plist.sort(key=lambda x: x.get("createdAt", 0))
            p = plist[-1]
            dto["hourlyRate"] = {
                "currency": p.get("currency"),
                "hourlyRate": float(p.get("hourlyRate", 0)),
            }

        results.append(dto)

    return _resp(200, results)


# ------------- AVAILABILITY -------------


def get_availability(event, context):
    params = event.get("pathParameters") or {}
    guide_id = params.get("id")
    if not guide_id:
        return _resp(400, {"error": "Falta id"})

    qs = event.get("queryStringParameters") or {}
    date_str = qs.get("date")
    if not date_str:
        return _resp(400, {"error": "Falta date"})

    try:
        res = avail_table.query(
            KeyConditionExpression=Key("guide_id").eq(guide_id)
        )
        items = res.get("Items", [])
    except Exception as e:
        print("Error get_availability:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    slots = []
    for s in items:
        if s.get("date") == date_str:
            slots.append(
                {
                    "startTime": s["startTime"],
                    "endTime": s["endTime"],
                    "status": s["status"],
                }
            )

    return _resp(200, slots)


def hold_slot(event, context):
    params = event.get("pathParameters") or {}
    guide_id = params.get("id")
    if not guide_id:
        return _resp(400, {"error": "Missing guide id"})

    body = _parse_body(event)
    if body is None:
        return _resp(400, {"error": "Invalid JSON"})

    date_str = body.get("date")
    start = body.get("startTime")
    end = body.get("endTime")
    hold_minutes = body.get("holdMinutes") or 15

    if not (date_str and start and end):
        return _resp(400, {"error": "Missing fields"})

    try:
        hold_minutes = int(hold_minutes)
    except ValueError:
        return _resp(400, {"error": "holdMinutes must be a number"})

    slot_id = _to_slot_id(date_str, start, end)

    try:
        res = avail_table.get_item(Key={"guide_id": guide_id, "slot_id": slot_id})
        item = res.get("Item")
        if not item:
            return _resp(400, {"ok": False})

        if item.get("status") != "FREE":
            return _resp(400, {"ok": False})

        until = datetime.now(timezone.utc) + timedelta(minutes=hold_minutes)

        avail_table.update_item(
            Key={"guide_id": guide_id, "slot_id": slot_id},
            UpdateExpression="SET #status = :held, heldUntil = :untilIso",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":held": "HELD",
                ":untilIso": until.isoformat(),
            },
        )
    except Exception as e:
        print("Error hold_slot:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    return _resp(200, {"ok": True, "heldUntil": until.isoformat()})


def book_slot(event, context):
    headers = event.get("headers") or {}
    if not _require_internal_token(headers):
        return _resp(401, {"error": "unauthorized"})

    params = event.get("pathParameters") or {}
    qs = event.get("queryStringParameters") or {}
    guide_id = params.get("id")
    date_str = qs.get("date")
    start = qs.get("start")
    end = qs.get("end")

    if not (guide_id and date_str and start and end):
        return _resp(400, {"error": "Missing params"})

    slot_id = _to_slot_id(date_str, start, end)
    try:
        res = avail_table.get_item(Key={"guide_id": guide_id, "slot_id": slot_id})
        item = res.get("Item")
        if not item:
            return _resp(400, {"error": "slot_unavailable"})

        if item.get("status") == "BOOKED":
            return _resp(400, {"error": "slot_unavailable"})

        avail_table.update_item(
            Key={"guide_id": guide_id, "slot_id": slot_id},
            UpdateExpression="SET #status = :booked",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":booked": "BOOKED"},
        )
    except Exception as e:
        print("Error book_slot:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    return _resp(200, {})


def free_slot(event, context):
    headers = event.get("headers") or {}
    if not _require_internal_token(headers):
        return _resp(401, {"error": "unauthorized"})

    params = event.get("pathParameters") or {}
    qs = event.get("queryStringParameters") or {}
    guide_id = params.get("id")
    date_str = qs.get("date")
    start = qs.get("start")
    end = qs.get("end")

    if not (guide_id and date_str and start and end):
        return _resp(400, {"error": "Missing params"})

    slot_id = _to_slot_id(date_str, start, end)
    try:
        res = avail_table.get_item(Key={"guide_id": guide_id, "slot_id": slot_id})
        item = res.get("Item")
        if not item:
            return _resp(400, {"error": "cannot_free"})

        avail_table.update_item(
            Key={"guide_id": guide_id, "slot_id": slot_id},
            UpdateExpression="SET #status = :free",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":free": "FREE"},
        )
    except Exception as e:
        print("Error free_slot:", e)
        return _resp(500, {"error": "internal_error", "message": str(e)})

    return _resp(200, {})
