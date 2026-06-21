"""Ekitten Final differential compatibility fixture.

Run this file directly before and after obfuscation.  A successful execution
prints one deterministic JSON line; any compatibility regression raises an
AssertionError and exits with a non-zero status.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import pickle
import re
import sys
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Iterator, get_type_hints


__all__ = ["run_compatibility_suite"]

UNICODE_TEXT = "gattino-è-東京-🐈"
BYTE_VALUE = b"\x00\x01\xfe\xff"
INTEGER_VALUE = 42
NEGATIVE_VALUE = -17
FLOAT_VALUE = 3.25
INTEGER_BOUNDARIES = (
    0,
    1,
    -1,
    9223372036854775807,
    -9223372036854775808,
    100000000000000000000000000000000000000000000000001,
)
BOOLEAN_VALUE = True
STRING_BOUNDARIES = (
    "",
    "single:' double:\" backslash:\\\\",
    "line-one\nline-two\ttabbed",
    "nul:\x00:end",
    "gattino-è-東京-🐈",
    "long-value-" * 64,
)


class CompatibilityFailure(AssertionError):
    """A single original/obfuscated semantic check failed."""


class CheckBook:
    def __init__(self) -> None:
        self.names: list[str] = []

    def equal(self, name: str, actual: Any, expected: Any) -> None:
        if actual != expected:
            raise CompatibilityFailure(
                f"{name}: expected {expected!r}, received {actual!r}"
            )
        self.names.append(name)

    def true(self, name: str, condition: Any) -> None:
        self.equal(name, bool(condition), True)


def labelled(label: str):
    """Decorator factory used to exercise closures and functools.wraps."""

    def decorate(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            result = function(*args, **kwargs)
            return f"{label}:{result}"

        return wrapper

    return decorate


@labelled("decorated")
def signature_case(
    first: int,
    /,
    second: int = 2,
    *extra: int,
    scale: int = 1,
    **named: int,
) -> int:
    subtotal = first + second + sum(extra) + sum(named.values())
    return subtotal * scale


def make_counter(start: int = 0):
    """Return a closure that exercises a nonlocal binding."""

    current = start

    def increment(step: int = 1) -> int:
        nonlocal current
        current += step
        return current

    return increment


def generator_case(limit: int) -> Iterator[int]:
    for number in range(limit):
        if number % 2 == 0:
            yield number * number


@contextmanager
def managed_events(events: list[str]):
    events.append("enter")
    try:
        yield "resource"
    finally:
        events.append("exit")


class PositiveValue:
    """Descriptor exercising __set_name__, __get__ and __set__."""

    def __set_name__(self, owner, name: str) -> None:
        self.storage_name = "_" + name

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        return getattr(instance, self.storage_name)

    def __set__(self, instance, value: int) -> None:
        if value <= 0:
            raise ValueError("value must be positive")
        setattr(instance, self.storage_name, value)


class BaseMessage:
    def message(self) -> str:
        return "base"


class ChildMessage(BaseMessage):
    def message(self) -> str:
        prefix = super().message()
        return prefix + ":child"


class SecretBox:
    def __init__(self, secret: str) -> None:
        self.__secret = secret

    def reveal(self) -> str:
        return self.__secret


class SlottedValue:
    __slots__ = ("value",)

    def __init__(self, value: int) -> None:
        self.value = value


class Registered(type):
    created: list[str] = []

    def __new__(mcls, name, bases, namespace):
        result = super().__new__(mcls, name, bases, namespace)
        if name != "RegistryMember":
            return result
        mcls.created.append(name)
        return result


class RegistryMember(metaclass=Registered):
    pass


class Colour(Enum):
    RED = 1
    BLUE = 2


class MatrixValue:
    def __init__(self, value: int) -> None:
        self.value = value

    def __matmul__(self, other: MatrixValue) -> int:
        return self.value * 100 + other.value


@dataclass(order=True)
class Record:
    identifier: int
    name: str
    tags: list[str] = field(default_factory=list)


@dataclass
class Product:
    price: int
    quantity: int = 1

    total = PositiveValue()

    def __post_init__(self) -> None:
        self.total = self.price * self.quantity

    @property
    def summary(self) -> str:
        formatted = f"{self.quantity}x@{self.price}={self.total}"
        return formatted

    @classmethod
    def from_pair(cls, pair: tuple[int, int]) -> Product:
        return cls(*pair)

    @staticmethod
    def tax(value: int) -> int:
        return value // 5


class AsyncResource:
    async def __aenter__(self) -> str:
        await asyncio.sleep(0)
        return "async-resource"

    async def __aexit__(self, exc_type, exc, traceback) -> bool:
        await asyncio.sleep(0)
        return False


async def async_numbers(limit: int):
    for number in range(limit):
        await asyncio.sleep(0)
        yield number + 1


async def async_case() -> tuple[str, list[int]]:
    values: list[int] = []
    async with AsyncResource() as resource:
        async for value in async_numbers(3):
            values.append(value)
    return resource, values


def pattern_case(value: Any) -> str:
    match value:
        case {"kind": "cat", "age": age} if age >= 3:
            return f"adult-cat:{age}"
        case [first, second]:
            return f"pair:{first + second}"
        case 0:
            return "zero"
        case _:
            return "other"


def dynamic_scope_case() -> tuple[int, int, bool, list[str]]:
    reflected_local = 7
    evaluated = eval("reflected_local + 5")
    namespace: dict[str, int] = {}
    exec("created_value = 9", {}, namespace)
    local_names = sorted(locals())
    return (
        evaluated,
        namespace["created_value"],
        "dynamic_scope_case" in globals(),
        local_names,
    )


def chained_exception_case() -> tuple[str, str, str]:
    try:
        int("not-an-integer")
    except ValueError as original:
        try:
            raise RuntimeError("wrapped-error") from original
        except RuntimeError as wrapped:
            cause = wrapped.__cause__
            return type(wrapped).__name__, str(wrapped), type(cause).__name__
    raise AssertionError("unreachable")


def try_finally_case() -> list[str]:
    events: list[str] = []
    try:
        events.append("body")
        return events
    finally:
        events.append("finally")


def annotated_case(value: int, prefix: str = "n") -> list[str]:
    return [f"{prefix}:{value}"]


def comprehension_case(values: list[int]) -> tuple[list[int], dict[int, int], set[int]]:
    doubled = [item * 2 for item in values if item % 2]
    mapping = {item: item**2 for item in values}
    unique = {item % 3 for item in values}
    return doubled, mapping, unique


def assignment_expression_case(values: list[int]) -> int:
    if (length := len(values)) > 2:
        return length
    return 0


def vm_operations_case(left: int, right: int, flag: bool) -> tuple[Any, ...]:
    return (
        left + right,
        left - right,
        left * right,
        left / right,
        left // right,
        left % right,
        left**right,
        left << right,
        left >> right,
        left | right,
        left ^ right,
        left & right,
        +left,
        -left,
        ~left,
        not flag,
    )


def vm_matrix_case(left: MatrixValue, right: MatrixValue) -> int:
    return left @ right


def run_compatibility_suite(check_docstring: bool = True) -> dict[str, Any]:
    checks = CheckBook()

    if check_docstring:
        checks.equal("module-docstring", __doc__.splitlines()[0], "Ekitten Final differential compatibility fixture.")
    checks.equal("unicode", UNICODE_TEXT, "gattino-è-東京-🐈")
    checks.equal(
        "string-boundaries",
        STRING_BOUNDARIES,
        (
            "",
            "single:' double:\" backslash:\\\\",
            "line-one\nline-two\ttabbed",
            "nul:\x00:end",
            "gattino-è-東京-🐈",
            "long-value-" * 64,
        ),
    )
    checks.equal("bytes", BYTE_VALUE.hex(), "0001feff")
    checks.equal("integer", INTEGER_VALUE + NEGATIVE_VALUE, 25)
    checks.equal(
        "integer-boundaries",
        INTEGER_BOUNDARIES,
        (
            0,
            1,
            -1,
            9223372036854775807,
            -9223372036854775808,
            100000000000000000000000000000000000000000000000001,
        ),
    )
    checks.equal("integer-slice", list(range(10))[1:8:3], [1, 4, 7])
    checks.equal("integer-bitwise", (1 << 12) | 5, 4101)
    checks.true("boolean-not-integer", BOOLEAN_VALUE is True)
    checks.equal("float", FLOAT_VALUE * 2, 6.5)
    checks.equal(
        "signature-and-decorator",
        signature_case(1, 2, 3, 4, scale=2, bonus=5),
        "decorated:30",
    )

    counter = make_counter(10)
    checks.equal("closure-nonlocal", [counter(), counter(4)], [11, 15])
    checks.equal("generator", list(generator_case(7)), [0, 4, 16, 36])

    events: list[str] = []
    with managed_events(events) as resource:
        events.append(resource)
    checks.equal("context-manager", events, ["enter", "resource", "exit"])

    product = Product.from_pair((7, 3))
    checks.equal("descriptor-property", product.summary, "3x@7=21")
    checks.equal("classmethod", product, Product(7, 3))
    checks.equal("staticmethod", Product.tax(50), 10)
    checks.equal("inheritance-super", ChildMessage().message(), "base:child")
    checks.equal("name-mangling", SecretBox("hidden").reveal(), "hidden")
    checks.equal("slots", SlottedValue(8).value, 8)
    checks.equal("metaclass", Registered.created, ["RegistryMember"])
    checks.equal("enum", Colour.RED.name + ":" + str(Colour.BLUE.value), "RED:2")

    record = Record(3, "Milo", ["cat", "orange"])
    checks.equal(
        "dataclass",
        asdict(record),
        {"identifier": 3, "name": "Milo", "tags": ["cat", "orange"]},
    )
    restored = pickle.loads(pickle.dumps(record, protocol=pickle.HIGHEST_PROTOCOL))
    checks.equal("pickle", restored, record)

    async_resource, async_values = asyncio.run(async_case())
    checks.equal("async-context-manager", async_resource, "async-resource")
    checks.equal("async-generator", async_values, [1, 2, 3])

    checks.equal(
        "pattern-mapping",
        pattern_case({"kind": "cat", "age": 4}),
        "adult-cat:4",
    )
    checks.equal("pattern-sequence", pattern_case([2, 5]), "pair:7")
    checks.equal("pattern-literal", pattern_case(0), "zero")

    evaluated, created, global_found, local_names = dynamic_scope_case()
    checks.equal("eval", evaluated, 12)
    checks.equal("exec", created, 9)
    checks.true("globals", global_found)
    checks.true("locals", "reflected_local" in local_names)

    checks.equal(
        "exception-chaining",
        chained_exception_case(),
        ("RuntimeError", "wrapped-error", "ValueError"),
    )
    checks.equal("try-finally", try_finally_case(), ["body", "finally"])

    hints = get_type_hints(annotated_case)
    checks.equal("annotation-value", hints["value"], int)
    checks.equal("annotation-return", hints["return"], list[str])
    checks.equal("f-string", annotated_case(6, prefix="value"), ["value:6"])

    checks.equal(
        "comprehensions",
        comprehension_case([0, 1, 2, 3]),
        ([2, 6], {0: 0, 1: 1, 2: 4, 3: 9}, {0, 1, 2}),
    )
    increment = lambda value: value + 1
    checks.equal("lambda", increment(8), 9)
    checks.equal("assignment-expression", assignment_expression_case([1, 2, 3]), 3)
    checks.equal(
        "vm-operators",
        vm_operations_case(7, 2, True),
        (9, 5, 14, 3.5, 3, 1, 49, 28, 1, 7, 5, 2, 7, -7, -8, False),
    )
    checks.equal(
        "vm-matrix-operator",
        vm_matrix_case(MatrixValue(4), MatrixValue(9)),
        409,
    )

    checks.equal("regex", re.findall(r"[A-Z]+", "AA-bb-CCC"), ["AA", "CCC"])
    encoded_json = json.dumps(
        {"unicode": UNICODE_TEXT, "number": INTEGER_VALUE},
        ensure_ascii=False,
        sort_keys=True,
    )
    checks.equal(
        "json",
        encoded_json,
        '{"number": 42, "unicode": "gattino-è-東京-🐈"}',
    )
    checks.equal("dunder-all", __all__, ["run_compatibility_suite"])

    name_digest = hashlib.sha256("|".join(checks.names).encode("utf-8")).hexdigest()
    return {
        "digest": name_digest,
        "status": "ok",
        "tests": len(checks.names),
    }


def main() -> int:
    allowed_arguments = {"--allow-stripped-docstrings"}
    unknown_arguments = set(sys.argv[1:]) - allowed_arguments
    if unknown_arguments:
        raise SystemExit("Unknown test arguments: " + ", ".join(sorted(unknown_arguments)))
    summary = run_compatibility_suite(
        check_docstring="--allow-stripped-docstrings" not in sys.argv[1:]
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
