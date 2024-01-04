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
        self.field_name = self.__class__
        self.value = value
        self.required = required
        self.nullable = nullable

    def __get__(self, instance, owner):
        # print("INSIDE FIELD VALUE: ", getattr(instance, "value", None))
        # print("INSIDE FIELD VALUE: ", self.value)
        return getattr(instance, "value", None)
        # return self.value

    def __set__(self, instance, value):
        self.validate()
        instance.value = value
        # print(self.field_name.__str__())
        # setattr(instance, self.field_name.__str__(), value)

    # def __str__(self):
    #     return str(self.value)

    # def validate(self):
    def validate(self):
        if self.value is None:
            if not self.nullable:
                # raise ValueError(f"{self.field_name} must not be None")
                return False, f"{self.field_name} must not be None"
            else:
                return None, OK
        # if self.required and not self.value:
        if self.required and not self.value:
            # raise ValueError(f"{self.field_name} is required")
            return False, f"{self.field_name} is required"
        # print("FIELD RETURNED TRUE")
        return True, OK


class CharField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = self.__class__

    def validate(self):
        parent_result = super().validate()
        # print("VALUE IN CHARFIELD: ", self.value)
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        # print(parent_result, type(parent_result))
        # if not parent_result:
        #     return parent_result[0], parent_result[1]
        if not self.value or not isinstance(self.value, str):
            # raise ValueError(f"{self.field_name} must be a string")
            return False, f"{self.field_name} must be a str"
        return True, OK


class ArgumentsField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = self.__class__

    def validate(self):
        parent_result = super().validate()
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if not self.value or not isinstance(self.value, dict):
            # raise ValueError("Field must be a dictionary")
            return False, f"{self.field_name} must be a dict"
        return True, OK


class EmailField(CharField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = self.__class__

    def validate(self):
        parent_result = super().validate()
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if not self.value or not re.match(r"[^@]+@[^@]+\.[^@]+", self.value):
            # raise ValueError("Invalid email format")
            return False, f"{self.field_name} must have appropriate email format"
        return True, OK


class PhoneField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = self.__class__

    def validate(self):
        parent_result = super().validate()
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if not self.value or not re.match(r"^7\d{10}$", str(self.value)):
            # raise ValueError("Invalid phone format")
            return False, f"{self.field_name} must have appropriate phone format"
        return True, OK


class DateField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = self.__class__

    def validate(self):
        parent_result = super().validate()
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if self.value:
            try:
                datetime.datetime.strptime(self.value, "%d.%m.%Y")
                return True, OK
            except ValueError:
                # raise ValueError("Invalid date format")
                return False, f"{self.field_name} must have appropriate date format"
        return True, OK


class BirthDayField(DateField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = self.__class__

    def validate(self):
        parent_result = super().validate()
        return parent_result[0], parent_result[1]
        # is_valid, error_message = super().validate(value)
        # if is_valid:
        #     return True, OK
        # else:
        #     return False, f"{self.field_name} must have appropriate date format"


class GenderField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = self.__class__

    def validate(self):
        parent_result = super().validate()
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if self.value and self.value not in GENDERS:
            # raise ValueError("Invalid gender value")
            return False, f"{self.field_name} must have value in (0, 1, 2)"
        return True, OK


class ClientIDsField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.field_name = self.__class__

    def validate(self):
        parent_result = super().validate()
        if not parent_result[0]:
            return parent_result[0], parent_result[1]
        if not self.value or (
            not isinstance(self.value, list)
            or not all(isinstance(client_id, int) for client_id in self.value)
        ):
            # raise ValueError("Field must be a list of integers")
            return False, f"{self.field_name} must be a list with integer"
        return True, OK


class RequestValidator:
    def validate(self, request_instance, data):
        is_fields_valid = {}
        # print(request_instance.__class__.__dict__.items())
        for field_name, field_instance in request_instance.__class__.__dict__.items():
            if isinstance(field_instance, Field):
                # print("FIELD_NAME: ", field_name, "FIELD_INSTANCE: ", field_instance)
                # print("Required? ", field_instance.required)  # OK
                # field_value = data.get(field_name)
                # print("SET ATTR: ", field_name, data.get(field_name))

                # setattr(field_instance, "value", data.get(field_name))
                field_instance.value = data.get(field_name)
                # field_instance.value = data.get(field_name)

                # print("SET: ", type(field_instance))
                # print("SET Value: ", field_instance.value)

                # print(field_instance.value)
                # print("SHOW ATTR: ", field_name, field_instance.value)
                # print(field_instance.value, field_instance.__dict__)  # OK

                # res = getattr(self, field_name + "_1")
                # print("GET ATTR: ", res)
                # field_instance.value = data.get(field_name)

                request_instance._fields[field_name] = field_instance.value
                setattr(request_instance, field_name, field_instance)

                # print(
                #     "GET BEFORE VAL: ",
                #     getattr(getattr(request_instance, field_name), "value"),
                # )
                # print("GET Value: ", getattr(self, field_name).value)
                # print("GET: ", self.__dict__)
                # print("GET ATTR: ", field_name, getattr(self, field_name).value)
                # print("GET ATTR: ", field_name, self.__getattribute__(field_name).value)
                is_valid, error = field_instance.validate()
                # try:
                #     print(
                #         "GET PREVIOUS ARG: ",
                #         getattr(getattr(request_instance, "login"), "value"),
                #     )
                # finally:
                #     pass

                if is_valid == False:
                    raise ValueError(error)
                is_fields_valid[field_name] = is_valid, error
        # print(
        #     self.account.value,
        #     self.login.value,
        #     self.token.value,
        # )
        # print(is_fields_valid)
        # print(self.__dict__)
        # for field_name, field_instance in request_instance.__class__.__dict__.items():
        #     print("VALUES: ", field_instance.value)
        # print("SELF DICT ", self.__dict__)
        # print("SELF.LOGIN ", self.login)

        ###################
        # print(field_name, field_value)
        # setattr(self, field_name, field_value)
        ###################
        # for item, obj in self.__class__.__dict__.items():
        #     if isinstance(obj, Field):
        #         print(item, obj.value)
        # print(getattr(obj, "item))
        return is_fields_valid


class ClientsInterestsRequest(RequestValidator):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self):
        self._fields = {}

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

    def __init__(self):
        self._fields = {}

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

    def __init__(self):
        self._fields = {}

    @property
    def is_admin(self):
        # for item, obj in self.__class__.__dict__.items():
        #     # print(item, obj, getattr(self, item))
        #     # print("OBJ VALUE: ", obj.value)
        #     if item == "login" and obj.value == ADMIN_LOGIN:
        #         return True
        # return False
        return self._fields["login"] == ADMIN_LOGIN

    # def check_auth(self, request):
    #     return check_auth(request)

    # def add_attributes_from_request(self, request):
    #     for attr in ["account", "login", "token", "arguments", "method"]:
    #         setattr(self, attr, request.get(attr))

    def validate(self, data):
        # is_fields_valid = super().validate(request_instance, data)
        super().validate(self, data)
        # for field_name, field_instance in self.__class__.__dict__.items():
        #     if isinstance(field_instance, Field):
        #         print(field_name, field_instance)
        # print(
        #     self.account,
        #     self.login,
        #     self.token,
        # )
        # self.add_attributes_from_request(data)
        # for item, obj in self.__class__.__dict__.items():
        #     if isinstance(obj, Field):
        #         pass
        # print(item, obj.value)
        # print("LOGIN VALUE: ", getattr(self, "login").value)
        # print(self.account.value)
        # print(self.login.value)
        # print(self.token.value)
        # print(self.arguments.value)
        # print(self.method.value)
        # is_admin_value = self.is_admin
        # print("IS ADMIN: ", is_admin_value)

        # is_field_valid, request_instance = super().validate(request_instance, data)
        # print("IS FIELD VALID: ", is_field_valid)
        # print("REQUEST INSTANCE: ", request_instance)
        # print("DICT", request_instance.__dict__)
        # print("USER IS ADMIN?", request_instance.is_admin)

        # self.add_attributes_from_request(data)
        # print(data)
        # self.add_attributes_from_request(data)

        # is_fields_valid = super().validate(request_instance, data)
        #
        # for key, value in is_fields_valid.items():
        #     is_valid, error = value
        #     # print(is_valid, error)
        #     if is_valid == False:
        #         raise ValueError(error)
        # return True

    # def __getattribute__(self, name):
    #     # Если атрибут существует, вернуть его значение
    #     if hasattr(self, name):
    #         print("HAS")
    #         return super().__getattribute__(name)
    #
    #     # Если атрибут заканчивается на "_value", вернуть его значение
    #     if hasattr(getattr(self, name), "value"):
    #         return getattr(self, name).value
    #     else:
    #         raise AttributeError(
    #             f"'{self.__class__.__name__}' object has no attribute '{original_name}'"
    #         )
    #     return super().__getattribute__(name)


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(
            bytes(datetime.datetime.now().strftime("%Y%m%d%H"), "utf-8")
            + bytes(ADMIN_SALT, "utf-8")  # ADMIN_SALT
        ).hexdigest()
    else:
        # print(request.account, request.login, SALT)
        digest = hashlib.sha512(
            bytes(request._fields["account"] + request._fields["login"] + SALT, "utf-8")
        ).hexdigest()
    # print("DIGEST: ", digest)
    # print("TOKEN", request._fields["token"])
    # print(digest == request._fields["token"])
    if digest == request._fields["token"]:
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
                    # request_instance = MethodRequest()
                    # request_instance.login = "42"
                    # print(request_instance.__dict__)
                    validator = MethodRequest()
                    # validator.validate(request_instance, request)
                    validator.validate(request)
                    # is_mr_valid = validator.validate(request_instance, request)
                    # # print(is_mr_valid)
                    # for key, value in is_mr_valid.items():
                    #     is_valid, error = value
                    #     # print(is_valid, error)
                    #     if not is_valid:
                    #         raise ValueError(error)

                    # request_instance.add_attributes_from_request(request)
                    # print(
                    #     validator.__dict__,
                    # )
                    # print("LOGIN", validator.login)
                    # for item, obj in validator.__class__.__dict__.items():
                    #     if isinstance(obj, Field):
                    #         # print("GETATTR: ", getattr(validator, item).value) # not OK
                    #         print("ITEM LOOPING: ", item, obj.value)  # OK
                    #
                    # print(
                    #     "VALIDATOR HAS ATTR: login :",
                    #     hasattr(validator.login, "value"),
                    #     "ITS VALUE: ",
                    #     validator.login.value,
                    # )

                    # if validator.is_admin:
                    #     print(validator.is_admin, "IS_ADMIN")
                    # else:
                    #     print(validator.is_admin, "NOT_IS_ADMIN")

                    # print("FIELDS:")
                    # print(validator._fields["login"])
                    # print(validator._fields["token"])

                    if not check_auth(validator):
                        raise PermissionError("Forbidden")

                    response, code = self.router[path](
                        {"body": request, "headers": self.headers}, context, self.store
                    )
                except ValueError as e:
                    logging.error(f"Validation error: {e}")
                    code = INVALID_REQUEST
                except PermissionError as e:
                    logging.error(f"Authentication error: {e}")
                    code = FORBIDDEN
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
                    # print(e)
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
