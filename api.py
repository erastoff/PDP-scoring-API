#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import datetime
import logging
import hashlib
import re
import uuid
from argparse import ArgumentParser  # from optparse import OptionParser
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler


from scoring import get_score, get_interests


SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field:
    def __init__(self, value=None, required=True, nullable=False):
        self.field_name = __class__
        self.value = value
        self.required = required
        self.nullable = nullable

    def __get__(self, instance, owner):
        return getattr(instance, "value", None)

    def __set__(self, instance, value):
        self.validate(value)
        self.value = value

    def validate(self, value):
        if not self.nullable and value is None:
            raise ValueError(f"{self.field_name} must not be None")

        if self.required and not value:
            raise ValueError(f"{self.field_name} is required")


class CharField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        super().validate(value)
        if not isinstance(value, str) and self.required:
            raise ValueError(f"{self.field_name} must be a string")


class ArgumentsField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        super().validate(value)
        if not isinstance(value, dict) and self.required:
            raise ValueError("Field must be a dictionary")


class EmailField(CharField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        super().validate(value)
        if not re.match(r"[^@]+@[^@]+\.[^@]+", value) and self.required:
            raise ValueError("Invalid email format")


class PhoneField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        super().validate(value)
        if (
            not re.match(r"\+\d{1,3}\(\d{3}\)\d{3}-\d{2}-\d{2}", value)
            and self.required
        ):
            raise ValueError("Invalid phone format")


class DateField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        super().validate(value)
        if self.required:
            try:
                datetime.strptime(value, "%d.%m.%Y")
            except ValueError:
                raise ValueError("Invalid date format")


class BirthDayField(DateField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        super().validate(value)
        # Дополнительные проверки, если необходимо


class GenderField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        super().validate(value)
        if value not in GENDERS.values() and self.required:
            raise ValueError("Invalid gender value")


class ClientIDsField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        super().validate(value)
        if self.required and (
            not isinstance(value, list)
            or not all(isinstance(client_id, int) for client_id in value)
        ):
            raise ValueError("Field must be a list of integers")


class RequestValidator:
    def validate(self, request_instance, data):
        for field_name, field_instance in request_instance.__class__.__dict__.items():
            if isinstance(field_instance, Field):
                field_value = data.get(field_name)
                try:
                    field_instance.validate(field_value)
                except ValueError as e:
                    raise ValueError(f"Validation error for field '{field_name}': {e}")


class ClientsInterestsRequest(RequestValidator):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def validate(self, **kwargs):
        super().validate(**kwargs)


class OnlineScoreRequest(RequestValidator):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self, request_instance, data):
        super().validate(request_instance, data)
        # for field_name, field_instance in request_instance.__class__.__dict__.items():
        #     print("DATA PRINT: ", data.get(field_name))


class MethodRequest(RequestValidator):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    def validate(self, **kwargs):
        super().validate(**kwargs)


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(
            datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
        ).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    if request["body"]["method"] == "online_score":
        score = get_score(store, **request["body"]["arguments"])
        response, code = {"score": score}, HTTPStatus.OK
    elif request["body"]["method"] == "clients_interests":
        response = {}
        for item in request["body"]["arguments"]["client_ids"]:
            response[f"client{item}"] = get_interests(store, item)
        code = HTTPStatus.OK
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {"method": method_handler}
    store = None

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, HTTPStatus.OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers["Content-Length"])).decode(
                "utf-8"
            )
            request = json.loads(data_string)
        except Exception as e:
            print(e)
            code = HTTPStatus.BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    # Получаем класс валидатора по имени метода
                    validator_class = RequestValidator
                    if validator_class:
                        request_instance = MethodRequest()
                        validator = validator_class()
                        # Выполняем валидацию
                        validator.validate(request_instance, request)
                    else:
                        raise ValueError(f"Unknown method '{path}'")
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers}, context, self.store
                    )
                except ValueError as e:
                    print(e)
                    logging.error(f"Validation error: {e}")
                    code = HTTPStatus.UNPROCESSABLE_ENTITY
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = HTTPStatus.INTERNAL_SERVER_ERROR
            else:
                code = HTTPStatus.NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode("utf-8"))
        return


if __name__ == "__main__":
    op = ArgumentParser()
    op.add_argument("-p", "--port", action="store", type=int, default=8080)
    op.add_argument("-l", "--log", action="store", default="./logs")
    args = op.parse_args()

    logging.basicConfig(
        filename=args.log,
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )

    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        print("server is ready")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
