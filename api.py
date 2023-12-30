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
        if value is None:
            if not self.nullable:
                # raise ValueError(f"{self.field_name} must not be None")
                return False, f"{self.field_name} must not be None"
            else:
                return None, OK
        if self.required and not value:
            # raise ValueError(f"{self.field_name} is required")
            return False, f"{self.field_name} is required"

        return True, OK


class CharField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        parent_result = super().validate(value)
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        # print(parent_result, type(parent_result))
        if not parent_result:
            return parent_result[0], parent_result[1]
        if not value or not isinstance(value, str):
            # raise ValueError(f"{self.field_name} must be a string")
            return False, f"{self.field_name} must be a str"
        return True, OK


class ArgumentsField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        parent_result = super().validate(value)
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if not value or not isinstance(value, dict):
            # raise ValueError("Field must be a dictionary")
            return False, f"{self.field_name} must be a dict"
        return True, OK


class EmailField(CharField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        parent_result = super().validate(value)
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if not value or not re.match(r"[^@]+@[^@]+\.[^@]+", value):
            # raise ValueError("Invalid email format")
            return False, f"{self.field_name} must have appropriate email format"
        return True, OK


class PhoneField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        parent_result = super().validate(value)
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if not value or not re.match(r"^7\d{10}$", str(value)):
            # raise ValueError("Invalid phone format")
            return False, f"{self.field_name} must have appropriate phone format"
        return True, OK


class DateField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        parent_result = super().validate(value)
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if value:
            try:
                datetime.datetime.strptime(value, "%d.%m.%Y")
                return True, OK
            except ValueError:
                # raise ValueError("Invalid date format")
                return False, f"{self.field_name} must have appropriate date format"
        return True, OK


class BirthDayField(DateField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        parent_result = super().validate(value)
        return parent_result[0], parent_result[1]
        # is_valid, error_message = super().validate(value)
        # if is_valid:
        #     return True, OK
        # else:
        #     return False, f"{self.field_name} must have appropriate date format"


class GenderField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        parent_result = super().validate(value)
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if value and value not in GENDERS:
            # raise ValueError("Invalid gender value")
            return False, f"{self.field_name} must have value in (0, 1, 2)"
        return True, OK


class ClientIDsField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = __class__

    def validate(self, value):
        parent_result = super().validate(value)
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if not value or (
            not isinstance(value, list)
            or not all(isinstance(client_id, int) for client_id in value)
        ):
            # raise ValueError("Field must be a list of integers")
            return False, f"{self.field_name} must be a list with integer"
        return True, OK


class RequestValidator:
    def validate(self, request_instance, data):
        is_fields_valid = {}
        for field_name, field_instance in request_instance.__class__.__dict__.items():
            if isinstance(field_instance, Field):
                field_value = data.get(field_name)
                is_valid, error = field_instance.validate(field_value)
                if is_valid == False:
                    raise ValueError(error)
                is_fields_valid[field_name] = is_valid, error
        return is_fields_valid


class ClientsInterestsRequest(RequestValidator):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def validate(self, request_instance, data):
        super().validate(request_instance, data)
        # is_field_valid = super().validate(request_instance, data)
        # print(is_field_valid)
        # for key, value in is_field_valid.items():
        #     is_valid, error = value
        #     if is_valid == False:
        #         raise ValueError(error)


class OnlineScoreRequest(RequestValidator):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self, request_instance, data):
        is_field_valid = super().validate(request_instance, data)
        if (
            (is_field_valid["phone"][0] and is_field_valid["email"][0])
            or (is_field_valid["first_name"][0] and is_field_valid["last_name"][0])
            or (is_field_valid["gender"][0] and is_field_valid["birthday"][0])
        ):
            return True

        else:
            raise ValueError(
                "Appropriate pair of arguments must be provided for 'online_score' method"
            )


class MethodRequest(RequestValidator):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=False)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    def validate(self, request_instance, data):
        super().validate(request_instance, data)
        # is_fields_valid = super().validate(request_instance, data)
        #
        # for key, value in is_fields_valid.items():
        #     is_valid, error = value
        #     # print(is_valid, error)
        #     if is_valid == False:
        #         raise ValueError(error)
        # return True


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
    # if request == {}:
    if request["body"]["method"] == "online_score":
        try:
            request_instance = OnlineScoreRequest()
            validator = OnlineScoreRequest()
            validator.validate(request_instance, request["body"]["arguments"])
            # print("ONLINE_SCORE_VALID!!! : ", request["body"]["arguments"])
        except ValueError as e:
            logging.error(f"Validation error: {e}")
            code = INVALID_REQUEST
            response = None
            return response, code
        score = get_score(store, **request["body"]["arguments"])
        response, code = {"score": score}, HTTPStatus.OK
    elif request["body"]["method"] == "clients_interests":
        try:
            request_instance = ClientsInterestsRequest()
            validator = ClientsInterestsRequest()
            validator.validate(request_instance, request["body"]["arguments"])
        except ValueError as e:
            logging.error(f"Validation error: {e}")
            code = INVALID_REQUEST
            response = None
            return response, code
        response = {}
        for item in request["body"]["arguments"]["client_ids"]:
            response[f"client{item}"] = get_interests(store, item)
        code = OK
    return response, code
    # else:
    #     logging.exception("Empty request was given")
    #     code = INVALID_REQUEST
    #     response = None
    #     return response, code


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
            # print(e)
            code = BAD_REQUEST
        # if not request:
        #     print(request, type(request))

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    request_instance = MethodRequest()
                    validator = MethodRequest()
                    validator.validate(request_instance, request)
                    # is_mr_valid = validator.validate(request_instance, request)
                    # # print(is_mr_valid)
                    # for key, value in is_mr_valid.items():
                    #     is_valid, error = value
                    #     # print(is_valid, error)
                    #     if not is_valid:
                    #         raise ValueError(error)
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers}, context, self.store
                    )
                except ValueError as e:
                    logging.error(f"Validation error: {e}")
                    code = INVALID_REQUEST
                # try:
                #     # Получаем класс валидатора по имени метода
                #     validator_class = RequestValidator
                #     if validator_class:
                #         request_instance = MethodRequest()
                #         validator = validator_class()
                #         # Выполняем валидацию
                #         validator.validate(request_instance, request)
                #     else:
                #         raise ValueError(f"Unknown method '{path}'")
                #     response, code = self.router[path](
                #         {"body": request, "headers": self.headers}, context, self.store
                #     )
                # except ValueError as e:
                #     print(e)
                #     logging.error(f"Validation error: {e}")
                #     code = INVALID_REQUEST
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND
        else:
            logging.exception("Empty request was given")
            code = INVALID_REQUEST

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
