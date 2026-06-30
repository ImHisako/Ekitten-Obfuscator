#!/usr/bin/env python3
"""Ekitten - compatibility-first Python source obfuscator.

The protected payload uses a memory-safe Python port of the MARX-P/CTR design
found in BlazingOpossum.  AES is not used.

BlazingOpossum is an experimental, unaudited cipher.  It is useful here as an
obfuscation and integrity layer, but it must not be presented as a replacement
for a standardized, independently reviewed cryptographic primitive.  Because a
standalone generated program must contain everything needed to execute, a
determined runtime analyst can ultimately recover its plaintext and key.
"""

from __future__ import annotations

import argparse
import ast
import base64
import builtins
import copy
import hashlib
import hmac
import json
import marshal
import os
import random
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import tokenize
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple


__version__ = "1.6.0"


class EkittenError(Exception):
    """Base exception for expected Ekitten failures."""


class SourceTransformError(EkittenError):
    """Raised when source parsing or transformation fails."""


class IntegrityError(EkittenError):
    """Raised when a BlazingOpossum authentication tag is invalid."""


class VerificationError(EkittenError):
    """Raised when original and protected programs behave differently."""


@dataclass(frozen=True)
class Profile:
    name: str
    literal_obfuscation: bool
    integer_obfuscation: bool
    local_renaming: bool
    encryption_layers: int
    decoy_chunks: int


PROFILES: Mapping[str, Profile] = {
    "compatible": Profile("compatible", False, False, False, 1, 0),
    "balanced": Profile("balanced", True, True, False, 3, 2),
    "maximum": Profile("maximum", True, True, True, 5, 5),
}


@dataclass(frozen=True)
class ObfuscationConfig:
    profile: str = "balanced"
    seed: Optional[int] = None
    encryption_layers: Optional[int] = None
    runtime_hardening: bool = False
    code_object_hardening: bool = False
    vm_obfuscation: bool = False
    cfg_obfuscation: bool = False
    anti_tamper: bool = False

    def resolved_profile(self) -> Profile:
        if self.profile not in PROFILES:
            raise EkittenError("Unknown profile: {0}".format(self.profile))
        base = PROFILES[self.profile]
        layers = base.encryption_layers if self.encryption_layers is None else self.encryption_layers
        if not 1 <= layers <= 12:
            raise EkittenError("Encryption layers must be between 1 and 12")
        return Profile(
            base.name,
            base.literal_obfuscation,
            base.integer_obfuscation,
            base.local_renaming,
            layers,
            base.decoy_chunks,
        )


@dataclass(frozen=True)
class ObfuscationResult:
    source: str
    profile: str
    encryption_layers: int
    source_sha256: str
    transformed_sha256: str
    output_sha256: str
    applied_passes: Tuple[str, ...]
    runtime_mode: str
    skipped_passes: Tuple[str, ...] = ()


class BuildEntropy:
    """Separate polymorphic randomness from key material generation."""

    def __init__(self, seed: Optional[int]) -> None:
        self.seed = seed
        rng_seed = seed if seed is not None else int.from_bytes(secrets.token_bytes(32), "little")
        self.random = random.Random(rng_seed)
        self._counter = 0

    def bytes(self, length: int, label: str) -> bytes:
        if self.seed is None:
            return secrets.token_bytes(length)

        output = bytearray()
        while len(output) < length:
            material = "EkittenFinal|{0}|{1}|{2}".format(
                self.seed, label, self._counter
            ).encode("utf-8")
            output.extend(hashlib.sha256(material).digest())
            self._counter += 1
        return bytes(output[:length])

    def identifier(self, used: Set[str]) -> str:
        alphabet = "Il1O0abcdef"
        while True:
            candidate = "_" + "".join(self.random.choice(alphabet) for _ in range(26))
            if candidate not in used and candidate.isidentifier():
                used.add(candidate)
                return candidate


class BlazingOpossum:
    """Memory-safe scalar port of the repository's MARX-P/CTR prototype.

    The C# prototype reads a 32-byte vector from a 16-byte IV while initializing
    its tag accumulator.  This port defines that previously undefined operation
    as ``IV || IV`` so encryption is deterministic and memory-safe.  The Python
    port is therefore self-consistent but not byte-compatible with output that
    depended on the C# out-of-bounds read.
    """

    BLOCK_SIZE = 16
    KEY_SIZE = 32
    IV_SIZE = 16
    TAG_SIZE = 16
    ROUNDS = 20
    MASK32 = 0xFFFFFFFF
    PRIME_MUL = 0x9E3779B9
    PRIME_ADD = 0xBB67AE85
    INITIAL_STATE = (
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    )

    def __init__(self, key: bytes) -> None:
        if len(key) != self.KEY_SIZE:
            raise ValueError("BlazingOpossum keys must be exactly 32 bytes")
        self._round_keys = self._expand_key(key)

    @classmethod
    def _rotl32(cls, value: int, shift: int) -> int:
        value &= cls.MASK32
        return ((value << shift) | (value >> (32 - shift))) & cls.MASK32

    @staticmethod
    def _shuffle_lanes(values: Sequence[int], order: Sequence[int]) -> List[int]:
        return [
            values[order[0]],
            values[order[1]],
            values[order[2]],
            values[order[3]],
            values[4 + order[0]],
            values[4 + order[1]],
            values[4 + order[2]],
            values[4 + order[3]],
        ]

    @classmethod
    def _expand_key(cls, key: bytes) -> Tuple[Tuple[int, ...], ...]:
        key_vector = list(struct.unpack("<8I", key))
        state = list(cls.INITIAL_STATE)
        round_keys: List[Tuple[int, ...]] = []
        for _ in range(cls.ROUNDS + 2):
            mixed = [
                ((state[index] * cls.PRIME_MUL) + key_vector[index]) & cls.MASK32
                for index in range(8)
            ]
            permuted = cls._shuffle_lanes(mixed, (1, 0, 3, 2))
            state = [
                cls._rotl32(state[index] ^ permuted[index], 7)
                for index in range(8)
            ]
            round_keys.append(tuple(state))
            key_vector = [
                (value + cls.PRIME_ADD) & cls.MASK32 for value in key_vector
            ]
        return tuple(round_keys)

    def _keystream_pair(self, iv: bytes, counter: int) -> bytes:
        iv_low, iv_high = struct.unpack("<QQ", iv)
        first = (iv_low + counter) & 0xFFFFFFFFFFFFFFFF
        second = (iv_low + counter + 1) & 0xFFFFFFFFFFFFFFFF
        state = [
            (iv_high >> 32) & self.MASK32,
            iv_high & self.MASK32,
            (first >> 32) & self.MASK32,
            first & self.MASK32,
            (iv_high >> 32) & self.MASK32,
            iv_high & self.MASK32,
            (second >> 32) & self.MASK32,
            second & self.MASK32,
        ]

        for round_index in range(self.ROUNDS):
            key = self._round_keys[round_index]
            state = [
                ((state[index] * self.PRIME_MUL) + key[index]) & self.MASK32
                for index in range(8)
            ]
            state = self._shuffle_lanes(state, (3, 2, 0, 1))
            state = [value ^ self._rotl32(value, 13) for value in state]
            state = [(value + self.PRIME_ADD) & self.MASK32 for value in state]

        final_key = self._round_keys[self.ROUNDS]
        state = [state[index] ^ final_key[index] for index in range(8)]
        return struct.pack("<8I", *state)

    def _crypt(self, iv: bytes, data: bytes) -> bytes:
        if len(iv) != self.IV_SIZE:
            raise ValueError("BlazingOpossum IVs must be exactly 16 bytes")
        result = bytearray(len(data))
        counter = 0
        for offset in range(0, len(data), 32):
            chunk = data[offset : offset + 32]
            stream = self._keystream_pair(iv, counter)
            result[offset : offset + len(chunk)] = bytes(
                value ^ stream[index] for index, value in enumerate(chunk)
            )
            counter += 2
        return bytes(result)

    def _tag(self, iv: bytes, ciphertext: bytes) -> bytes:
        accumulator = list(struct.unpack("<8I", iv + iv))
        full_length = len(ciphertext) - (len(ciphertext) % 32)

        for offset in range(0, full_length, 32):
            block = struct.unpack("<8I", ciphertext[offset : offset + 32])
            accumulator = [
                accumulator[index] ^ block[index] for index in range(8)
            ]
            accumulator = [
                self._rotl32(
                    ((value * self.PRIME_MUL) + self.PRIME_ADD) & self.MASK32,
                    11,
                )
                for value in accumulator
            ]

        remainder = ciphertext[full_length:]
        if remainder:
            tail = bytearray(struct.pack("<8I", *accumulator))
            for index, value in enumerate(remainder):
                tail[index] ^= value
            accumulator = list(struct.unpack("<8I", bytes(tail)))

        for round_index in range(4):
            key = self._round_keys[round_index]
            accumulator = [
                (((accumulator[index] + key[index]) & self.MASK32) * self.PRIME_MUL)
                & self.MASK32
                for index in range(8)
            ]
            shuffled = self._shuffle_lanes(accumulator, (1, 0, 3, 2))
            accumulator = [
                accumulator[index] ^ shuffled[index] for index in range(8)
            ]

        folded = [accumulator[index] ^ accumulator[index + 4] for index in range(4)]
        return struct.pack("<4I", *folded)

    def encrypt(self, iv: bytes, plaintext: bytes) -> bytes:
        ciphertext = self._crypt(iv, plaintext)
        return ciphertext + self._tag(iv, ciphertext)

    def decrypt(self, iv: bytes, encrypted: bytes) -> bytes:
        if len(encrypted) < self.TAG_SIZE:
            raise IntegrityError("BlazingOpossum payload is too short")
        ciphertext = encrypted[: -self.TAG_SIZE]
        received_tag = encrypted[-self.TAG_SIZE :]
        expected_tag = self._tag(iv, ciphertext)
        if not hmac.compare_digest(received_tag, expected_tag):
            raise IntegrityError("BlazingOpossum integrity check failed")
        return self._crypt(iv, ciphertext)


def _collect_source_names(tree: ast.AST) -> Set[str]:
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.alias):
            names.add(node.asname or node.name.split(".")[0])
    return names


class _ScopedNameRewriter(ast.NodeTransformer):
    def __init__(self, mapping: Mapping[str, str]) -> None:
        self.mapping = mapping

    def visit_Name(self, node: ast.Name) -> ast.AST:
        replacement = self.mapping.get(node.id)
        if replacement is not None:
            node.id = replacement
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.AST:
        if node.name in self.mapping:
            node.name = self.mapping[node.name]
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        return node

    def visit_Lambda(self, node: ast.Lambda) -> ast.AST:
        return node


class ConservativeLocalRenamer(ast.NodeTransformer):
    """Rename only locals in simple functions without dynamic scope access."""

    DYNAMIC_NAMES = {
        "eval",
        "exec",
        "globals",
        "locals",
        "vars",
        "dir",
        "compile",
        "inspect",
    }
    DYNAMIC_ATTRIBUTES = {"f_locals", "currentframe", "_getframe", "getargvalues"}

    def __init__(self, entropy: BuildEntropy, used_names: Set[str]) -> None:
        self.entropy = entropy
        self.used_names = used_names
        self.renamed_symbols = 0

    def _safe_mapping(self, node: ast.AST, arguments: ast.arguments) -> Dict[str, str]:
        descendants = list(ast.walk(node))
        nested_scope_types: Tuple[type, ...] = (
            ast.Lambda,
            ast.ListComp,
            ast.SetComp,
            ast.DictComp,
            ast.GeneratorExp,
            ast.ClassDef,
        )
        for child in descendants:
            if child is node:
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return {}
            if isinstance(child, nested_scope_types):
                return {}
            if isinstance(child, (ast.Global, ast.Nonlocal)):
                return {}
            if isinstance(child, ast.Name) and child.id in self.DYNAMIC_NAMES:
                return {}
            if isinstance(child, ast.Attribute) and child.attr in self.DYNAMIC_ATTRIBUTES:
                return {}
            match_type = getattr(ast, "Match", None)
            if match_type is not None and isinstance(child, match_type):
                return {}

        argument_names = {
            item.arg
            for item in (
                list(arguments.posonlyargs)
                + list(arguments.args)
                + list(arguments.kwonlyargs)
            )
        }
        if arguments.vararg is not None:
            argument_names.add(arguments.vararg.arg)
        if arguments.kwarg is not None:
            argument_names.add(arguments.kwarg.arg)

        candidates: Set[str] = set()
        for child in descendants:
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                candidates.add(child.id)
            elif isinstance(child, ast.ExceptHandler) and child.name:
                candidates.add(child.name)

        candidates.difference_update(argument_names)
        candidates = {
            name for name in candidates if not (name.startswith("__") and name.endswith("__"))
        }
        return {
            name: self.entropy.identifier(self.used_names)
            for name in sorted(candidates)
        }

    def _visit_function(self, node: ast.AST, arguments: ast.arguments) -> ast.AST:
        for statement in node.body:  # type: ignore[attr-defined]
            self.visit(statement)
        mapping = self._safe_mapping(node, arguments)
        if mapping:
            self.renamed_symbols += len(mapping)
            rewriter = _ScopedNameRewriter(mapping)
            node.body = [rewriter.visit(statement) for statement in node.body]  # type: ignore[attr-defined]
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        return self._visit_function(node, node.args)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        return self._visit_function(node, node.args)


class DocstringStripper(ast.NodeTransformer):
    """Remove runtime docstrings for the explicitly incompatible hardening mode."""

    @staticmethod
    def _strip(body: List[ast.stmt], require_body: bool) -> List[ast.stmt]:
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        if require_body and not body:
            body = [ast.Pass()]
        return body

    def visit_Module(self, node: ast.Module) -> ast.AST:
        node.body = self._strip(node.body, require_body=False)
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.body = self._strip(node.body, require_body=True)
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.body = self._strip(node.body, require_body=True)
        return self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.body = self._strip(node.body, require_body=True)
        return self.generic_visit(node)


def _protected_literal_roots(
    tree: ast.AST,
    protect_joined_strings: bool = True,
) -> Set[int]:
    protected: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr):
                value = body[0].value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    protected.add(id(value))

        if protect_joined_strings and isinstance(node, ast.JoinedStr):
            protected.add(id(node))
        if isinstance(node, ast.arg) and node.annotation is not None:
            protected.add(id(node.annotation))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            protected.add(id(node.returns))
        if isinstance(node, ast.AnnAssign):
            protected.add(id(node.annotation))

        type_alias = getattr(ast, "TypeAlias", None)
        if type_alias is not None and isinstance(node, type_alias):
            protected.add(id(node))

        match_type = getattr(ast, "Match", None)
        if match_type is not None and isinstance(node, match_type):
            for case in node.cases:
                protected.add(id(case.pattern))
    return protected


class StringObfuscator(ast.NodeTransformer):
    """Polymorphic UTF-8 string reconstruction with randomized dispatch."""

    STRATEGIES = (
        "rolling-add",
        "rolling-xor",
        "reverse-xor",
        "rotate-xor",
        "affine-byte",
        "even-odd-shuffle",
    )

    def __init__(
        self,
        string_helper: str,
        entropy: BuildEntropy,
        protected_roots: Set[int],
    ) -> None:
        self.string_helper = string_helper
        self.entropy = entropy
        self.protected_roots = protected_roots
        self.tokens = self._generate_tokens()
        self.strategy_counts: Dict[str, int] = {
            strategy: 0 for strategy in self.STRATEGIES
        }

    def _generate_tokens(self) -> Tuple[int, ...]:
        tokens: Set[int] = set()
        while len(tokens) < len(self.STRATEGIES):
            tokens.add(self.entropy.random.randint(1 << 20, (1 << 31) - 1))
        return tuple(sorted(tokens))

    def visit(self, node: ast.AST) -> ast.AST:
        if id(node) in self.protected_roots:
            return node
        return super().visit(node)

    def _encode(self, raw: bytes, strategy: int) -> Tuple[Tuple[int, ...], int, int]:
        key = self.entropy.random.randint(1, 255)
        if strategy == 0:
            encoded = tuple(
                (value + key + index * 17) & 0xFF
                for index, value in enumerate(raw)
            )
            return encoded, key, 0
        if strategy == 1:
            encoded = tuple(
                value ^ ((key + index * 29) & 0xFF)
                for index, value in enumerate(raw)
            )
            return encoded, key, 0
        if strategy == 2:
            encoded = tuple(value ^ key for value in reversed(raw))
            return encoded, key, 0
        if strategy == 3:
            shift = self.entropy.random.randint(1, 7)
            encoded = tuple(
                ((((value ^ key) << shift) | ((value ^ key) >> (8 - shift))) & 0xFF)
                for value in raw
            )
            return encoded, key, shift
        if strategy == 4:
            multiplier = self.entropy.random.choice((3, 5, 7, 11, 13, 17, 19, 23, 29, 31))
            inverse = pow(multiplier, -1, 256)
            encoded = tuple(
                (value * multiplier + key + index) & 0xFF
                for index, value in enumerate(raw)
            )
            return encoded, key, inverse
        mixed = raw[::2] + raw[1::2]
        encoded = tuple(
            value ^ ((key + index * 13) & 0xFF)
            for index, value in enumerate(mixed)
        )
        return encoded, key, len(raw)

    def _build_call(self, value: str) -> ast.Call:
        raw = value.encode("utf-8")
        strategy = self.entropy.random.randrange(len(self.STRATEGIES))
        encoded, key, auxiliary = self._encode(raw, strategy)
        self.strategy_counts[self.STRATEGIES[strategy]] += 1
        return ast.Call(
            func=ast.Name(id=self.string_helper, ctx=ast.Load()),
            args=[
                ast.Constant(value=self.tokens[strategy]),
                ast.Tuple(
                    elts=[ast.Constant(value=item) for item in encoded],
                    ctx=ast.Load(),
                ),
                ast.Constant(value=key),
                ast.Constant(value=auxiliary),
            ],
            keywords=[],
        )

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        values: List[ast.expr] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
                formatted = ast.FormattedValue(
                    value=self._build_call(value.value),
                    conversion=-1,
                    format_spec=None,
                )
                values.append(ast.copy_location(formatted, value))
            elif isinstance(value, ast.FormattedValue):
                value.value = self.visit(value.value)  # type: ignore[assignment]
                values.append(value)
            else:
                values.append(value)
        node.values = values
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, str) and node.value:
            return ast.copy_location(self._build_call(node.value), node)
        return node

    @property
    def string_count(self) -> int:
        return sum(self.strategy_counts.values())

    def helper_source(self) -> str:
        branches = {
            0: """    if token == {token}:
        buffer = bytearray((value - key - index * 17) & 255 for index, value in enumerate(data))
        return finish(buffer)""",
            1: """    if token == {token}:
        buffer = bytearray(value ^ ((key + index * 29) & 255) for index, value in enumerate(data))
        return finish(buffer)""",
            2: """    if token == {token}:
        buffer = bytearray(value ^ key for value in reversed(data))
        return finish(buffer)""",
            3: """    if token == {token}:
        buffer = bytearray(((((value >> auxiliary) | (value << (8 - auxiliary))) & 255) ^ key) for value in data)
        return finish(buffer)""",
            4: """    if token == {token}:
        buffer = bytearray(((value - key - index) * auxiliary) & 255 for index, value in enumerate(data))
        return finish(buffer)""",
            5: """    if token == {token}:
        mixed = bytearray(value ^ ((key + index * 13) & 255) for index, value in enumerate(data))
        split = (auxiliary + 1) // 2
        result = bytearray(auxiliary)
        result[::2] = mixed[:split]
        result[1::2] = mixed[split:]
        try:
            return finish(result)
        finally:
            for index in range(len(mixed)):
                mixed[index] = 0""",
        }
        rendered = [
            branches[index].format(token=self.tokens[index])
            for index in range(len(self.STRATEGIES))
        ]
        self.entropy.random.shuffle(rendered)
        return (
            "def {0}(token, data, key, auxiliary):\n".format(self.string_helper)
            + "    def finish(buffer):\n"
            + "        try:\n"
            + "            return bytes(buffer).decode('utf-8')\n"
            + "        finally:\n"
            + "            for index in range(len(buffer)):\n"
            + "                buffer[index] = 0\n"
            + "\n".join(rendered)
            + "\n    raise RuntimeError('invalid string reconstruction token')\n"
        )


class IntObfuscator(ast.NodeTransformer):
    """Polymorphic integer reconstruction with per-build dispatch tokens."""

    STRATEGIES = (
        "xor-mask",
        "additive-delta",
        "affine-quotient",
        "bitwise-complement",
        "xor-offset",
        "quotient-remainder",
    )

    def __init__(
        self,
        helper_name: str,
        entropy: BuildEntropy,
        protected_roots: Set[int],
    ) -> None:
        self.helper_name = helper_name
        self.entropy = entropy
        self.protected_roots = protected_roots
        self.tokens = self._generate_tokens()
        self.strategy_counts: Dict[str, int] = {
            strategy: 0 for strategy in self.STRATEGIES
        }

    def _generate_tokens(self) -> Tuple[int, ...]:
        tokens: Set[int] = set()
        while len(tokens) < len(self.STRATEGIES):
            tokens.add(self.entropy.random.randint(1 << 20, (1 << 31) - 1))
        return tuple(sorted(tokens))

    def visit(self, node: ast.AST) -> ast.AST:
        if id(node) in self.protected_roots:
            return node
        return super().visit(node)

    def _encode(self, value: int, strategy: int) -> Tuple[int, int, int]:
        if strategy == 0:
            key = self.entropy.random.getrandbits(64) | 1
            return value ^ key, key, 0
        if strategy == 1:
            delta = self.entropy.random.randint(257, (1 << 31) - 1)
            return value + delta, delta, 0
        if strategy == 2:
            multiplier = self.entropy.random.choice((3, 5, 7, 11, 13, 17, 19, 23, 29, 31))
            offset = self.entropy.random.randint(257, (1 << 20) - 1)
            return value * multiplier + offset, offset, multiplier
        if strategy == 3:
            return ~value, 0, 0
        if strategy == 4:
            key = self.entropy.random.getrandbits(64) | 1
            offset = self.entropy.random.randint(257, (1 << 24) - 1)
            return (value + offset) ^ key, key, offset
        divisor = self.entropy.random.choice((3, 5, 7, 11, 13, 17, 19, 23, 29, 31))
        quotient, remainder = divmod(value, divisor)
        return quotient, remainder, divisor

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if not isinstance(node.value, int) or isinstance(node.value, bool):
            return node
        strategy = self.entropy.random.randrange(len(self.STRATEGIES))
        left, right, extra = self._encode(node.value, strategy)
        self.strategy_counts[self.STRATEGIES[strategy]] += 1
        call = ast.Call(
            func=ast.Name(id=self.helper_name, ctx=ast.Load()),
            args=[
                ast.Constant(value=self.tokens[strategy]),
                ast.Constant(value=left),
                ast.Constant(value=right),
                ast.Constant(value=extra),
            ],
            keywords=[],
        )
        return ast.copy_location(call, node)

    @property
    def integer_count(self) -> int:
        return sum(self.strategy_counts.values())

    def helper_source(self) -> str:
        expressions = (
            "left ^ right",
            "left - right",
            "(left - right) // extra",
            "~left",
            "(left ^ right) - extra",
            "left * extra + right",
        )
        branches = [
            "    if token == {0}:\n        return {1}".format(token, expression)
            for token, expression in zip(self.tokens, expressions)
        ]
        self.entropy.random.shuffle(branches)
        return (
            "def {0}(token, left, right, extra):\n".format(self.helper_name)
            + "\n".join(branches)
            + "\n    raise RuntimeError('invalid integer reconstruction token')\n"
        )


@dataclass(frozen=True)
class _VMTemplate:
    helper_name: str
    kind: str
    push_token: int
    operator_tokens: Mapping[type, int]
    unary_tokens: Mapping[type, int]


class VMObfuscator(ast.NodeTransformer):
    """Virtualize conservative expression trees with per-scope VM templates."""

    OPERATORS: Tuple[Tuple[type, str, str], ...] = (
        (ast.Add, "add", "left + right"),
        (ast.Sub, "sub", "left - right"),
        (ast.Mult, "mul", "left * right"),
        (ast.Div, "div", "left / right"),
        (ast.FloorDiv, "floor-div", "left // right"),
        (ast.Mod, "mod", "left % right"),
        (ast.Pow, "pow", "left ** right"),
        (ast.LShift, "left-shift", "left << right"),
        (ast.RShift, "right-shift", "left >> right"),
        (ast.BitOr, "bit-or", "left | right"),
        (ast.BitXor, "bit-xor", "left ^ right"),
        (ast.BitAnd, "bit-and", "left & right"),
        (ast.MatMult, "matrix-mul", "left @ right"),
    )
    UNARY_OPERATORS: Tuple[Tuple[type, str, str], ...] = (
        (ast.UAdd, "unary-positive", "+value"),
        (ast.USub, "unary-negative", "-value"),
        (ast.Invert, "bit-invert", "~value"),
        (ast.Not, "logical-not", "not value"),
    )

    def __init__(
        self,
        entropy: BuildEntropy,
        protected_roots: Set[int],
        used_names: Set[str],
    ) -> None:
        self.entropy = entropy
        self.protected_roots = protected_roots
        self.used_names = used_names
        self.templates: List[_VMTemplate] = []
        self.current_template: Optional[_VMTemplate] = None
        self.expression_count = 0
        self.instruction_count = 0
        self.used_operators: Set[str] = set()
        self.generated_program_roots: Set[int] = set()
        self.template_counts: Dict[str, int] = {
            "stack": 0,
            "register": 0,
            "table": 0,
        }

    def _new_token(self, used: Set[int]) -> int:
        while True:
            token = self.entropy.random.randint(1 << 20, (1 << 31) - 1)
            if token not in used:
                return token

    def _new_template(self) -> _VMTemplate:
        used_tokens: Set[int] = set()
        push_token = self._new_token(used_tokens)
        used_tokens.add(push_token)
        operator_tokens: Dict[type, int] = {}
        for operator_type, _, _ in self.OPERATORS:
            token = self._new_token(used_tokens)
            used_tokens.add(token)
            operator_tokens[operator_type] = token
        unary_tokens: Dict[type, int] = {}
        for operator_type, _, _ in self.UNARY_OPERATORS:
            token = self._new_token(used_tokens)
            used_tokens.add(token)
            unary_tokens[operator_type] = token
        kind = self.entropy.random.choice(("stack", "register", "table"))
        template = _VMTemplate(
            helper_name=self.entropy.identifier(self.used_names),
            kind=kind,
            push_token=push_token,
            operator_tokens=operator_tokens,
            unary_tokens=unary_tokens,
        )
        self.templates.append(template)
        self.template_counts[kind] += 1
        return template

    def _template_for_current_scope(self) -> _VMTemplate:
        if self.current_template is None:
            self.current_template = self._new_template()
        return self.current_template

    def visit(self, node: ast.AST) -> ast.AST:
        if id(node) in self.protected_roots:
            return node
        return super().visit(node)

    def _visit_function_scope(
        self,
        node: ast.AST,
    ) -> ast.AST:
        previous_template = self.current_template
        self.current_template = None
        self.generic_visit(node)
        self.current_template = previous_template
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        return self._visit_function_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        return self._visit_function_scope(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        new_body: List[ast.stmt] = []
        for statement in node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                new_body.append(self.visit(statement))  # type: ignore[arg-type]
            else:
                new_body.append(statement)
        node.body = new_body
        return node

    def _operator_entry(self, operator: ast.operator) -> Optional[Tuple[type, str, str]]:
        for entry in self.OPERATORS:
            if isinstance(operator, entry[0]):
                return entry
        return None

    def _unary_entry(self, operator: ast.unaryop) -> Optional[Tuple[type, str, str]]:
        for entry in self.UNARY_OPERATORS:
            if isinstance(operator, entry[0]):
                return entry
        return None

    def _is_virtualizable(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return isinstance(node.ctx, ast.Load)
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (int, float, complex, str, bytes, bool))
        if isinstance(node, ast.BinOp):
            return (
                self._operator_entry(node.op) is not None
                and self._is_virtualizable(node.left)
                and self._is_virtualizable(node.right)
            )
        if isinstance(node, ast.UnaryOp):
            return (
                self._unary_entry(node.op) is not None
                and self._is_virtualizable(node.operand)
            )
        return False

    def _compile_expression(
        self,
        node: ast.AST,
        template: _VMTemplate,
        program: List[Tuple[int, int]],
        thunks: List[ast.Lambda],
    ) -> None:
        if isinstance(node, (ast.Name, ast.Constant)):
            index = len(thunks)
            thunks.append(
                ast.Lambda(
                    args=ast.arguments(
                        posonlyargs=[],
                        args=[],
                        vararg=None,
                        kwonlyargs=[],
                        kw_defaults=[],
                        kwarg=None,
                        defaults=[],
                    ),
                    body=node,  # type: ignore[arg-type]
                )
            )
            program.append((template.push_token, index))
            return
        if isinstance(node, ast.UnaryOp):
            self._compile_expression(node.operand, template, program, thunks)
            unary_entry = self._unary_entry(node.op)
            if unary_entry is None:
                raise SourceTransformError("Unsupported VM unary operator")
            program.append((template.unary_tokens[unary_entry[0]], 0))
            self.used_operators.add(unary_entry[1])
            return
        if not isinstance(node, ast.BinOp):
            raise SourceTransformError("Unsupported VM expression node")
        self._compile_expression(node.left, template, program, thunks)
        self._compile_expression(node.right, template, program, thunks)
        entry = self._operator_entry(node.op)
        if entry is None:
            raise SourceTransformError("Unsupported VM operator")
        token = template.operator_tokens[entry[0]]
        program.append((token, 0))
        self.used_operators.add(entry[1])

    def _compile_register_expression(
        self,
        node: ast.AST,
        template: _VMTemplate,
        program: List[Tuple[int, ...]],
        thunks: List[ast.Lambda],
        next_register: List[int],
    ) -> int:
        def allocate_register() -> int:
            register = next_register[0]
            next_register[0] += 1
            return register

        if isinstance(node, (ast.Name, ast.Constant)):
            thunk_index = len(thunks)
            register = allocate_register()
            thunks.append(
                ast.Lambda(
                    args=ast.arguments(
                        posonlyargs=[],
                        args=[],
                        vararg=None,
                        kwonlyargs=[],
                        kw_defaults=[],
                        kwarg=None,
                        defaults=[],
                    ),
                    body=node,  # type: ignore[arg-type]
                )
            )
            program.append((template.push_token, thunk_index, register))
            return register
        if isinstance(node, ast.UnaryOp):
            source_register = self._compile_register_expression(
                node.operand,
                template,
                program,
                thunks,
                next_register,
            )
            target_register = allocate_register()
            unary_entry = self._unary_entry(node.op)
            if unary_entry is None:
                raise SourceTransformError("Unsupported VM unary operator")
            program.append(
                (
                    template.unary_tokens[unary_entry[0]],
                    source_register,
                    target_register,
                )
            )
            self.used_operators.add(unary_entry[1])
            return target_register
        if not isinstance(node, ast.BinOp):
            raise SourceTransformError("Unsupported VM expression node")
        left_register = self._compile_register_expression(
            node.left,
            template,
            program,
            thunks,
            next_register,
        )
        right_register = self._compile_register_expression(
            node.right,
            template,
            program,
            thunks,
            next_register,
        )
        target_register = allocate_register()
        entry = self._operator_entry(node.op)
        if entry is None:
            raise SourceTransformError("Unsupported VM operator")
        program.append(
            (
                template.operator_tokens[entry[0]],
                left_register,
                right_register,
                target_register,
            )
        )
        self.used_operators.add(entry[1])
        return target_register

    def _virtualize(self, node: ast.AST) -> ast.AST:
        if not self._is_virtualizable(node):
            return self.generic_visit(node)
        template = self._template_for_current_scope()
        thunks: List[ast.Lambda] = []
        if template.kind == "register":
            register_program: List[Tuple[int, ...]] = []
            self._compile_register_expression(
                node,
                template,
                register_program,
                thunks,
                [0],
            )
            program_entries = register_program
        else:
            stack_program: List[Tuple[int, int]] = []
            self._compile_expression(node, template, stack_program, thunks)
            program_entries = stack_program
        program_node = ast.Tuple(
            elts=[
                ast.Tuple(
                    elts=[ast.Constant(value=item) for item in entry],
                    ctx=ast.Load(),
                )
                for entry in program_entries
            ],
            ctx=ast.Load(),
        )
        self.generated_program_roots.add(id(program_node))
        self.expression_count += 1
        self.instruction_count += len(program_entries)
        call = ast.Call(
            func=ast.Name(id=template.helper_name, ctx=ast.Load()),
            args=[
                program_node,
                ast.Tuple(elts=thunks, ctx=ast.Load()),
            ],
            keywords=[],
        )
        return ast.copy_location(call, node)

    def visit_BinOp(self, node: ast.BinOp) -> ast.AST:
        return self._virtualize(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        return self._virtualize(node)

    def helper_source(self) -> str:
        return "\n".join(self._helper_source(template) for template in self.templates)

    def _helper_source(self, template: _VMTemplate) -> str:
        if template.kind == "register":
            return self._register_helper_source(template)
        if template.kind == "table":
            return self._table_helper_source(template)
        return self._stack_helper_source(template)

    def _stack_helper_source(self, template: _VMTemplate) -> str:
        branches: List[str] = [
            """        if opcode == {0}:
            stack.append(thunks[argument]())""".format(template.push_token)
        ]
        for operator_type, _, expression in self.OPERATORS:
            branches.append(
                """        if opcode == {0}:
            right = stack.pop()
            left = stack.pop()
            stack.append({1})""".format(
                    template.operator_tokens[operator_type], expression
                )
            )
        for operator_type, _, expression in self.UNARY_OPERATORS:
            branches.append(
                """        if opcode == {0}:
            value = stack.pop()
            stack.append({1})""".format(
                    template.unary_tokens[operator_type], expression
                )
            )
        self.entropy.random.shuffle(branches)
        rendered = "\n            continue\n".join(branches)
        return """def {helper}(program, thunks):
    stack = []
    for opcode, argument in program:
{branches}
            continue
        raise RuntimeError('invalid VM opcode')
    if len(stack) != 1:
        raise RuntimeError('invalid VM stack state')
    return stack[0]
""".format(helper=template.helper_name, branches=rendered)

    def _table_helper_source(self, template: _VMTemplate) -> str:
        functions: List[str] = [
            """    def op_push(argument):
        stack.append(thunks[argument]())"""
        ]
        entries: List[Tuple[int, str]] = [(template.push_token, "op_push")]
        for index, (operator_type, name, expression) in enumerate(self.OPERATORS):
            function_name = "op_{0}_{1}".format(index, name.replace("-", "_"))
            functions.append(
                """    def {name}(argument):
        right = stack.pop()
        left = stack.pop()
        stack.append({expression})""".format(
                    name=function_name,
                    expression=expression,
                )
            )
            entries.append((template.operator_tokens[operator_type], function_name))
        for index, (operator_type, name, expression) in enumerate(self.UNARY_OPERATORS):
            function_name = "op_u{0}_{1}".format(index, name.replace("-", "_"))
            functions.append(
                """    def {name}(argument):
        value = stack.pop()
        stack.append({expression})""".format(
                    name=function_name,
                    expression=expression,
                )
            )
            entries.append((template.unary_tokens[operator_type], function_name))
        self.entropy.random.shuffle(entries)
        table_entries = ", ".join(
            "{0}: {1}".format(token, function_name)
            for token, function_name in entries
        )
        return """def {helper}(program, thunks):
    stack = []
{functions}
    handlers = {{{table_entries}}}
    for opcode, argument in program:
        handler = handlers.get(opcode)
        if handler is None:
            raise RuntimeError('invalid VM opcode')
        handler(argument)
    handlers.clear()
    if len(stack) != 1:
        raise RuntimeError('invalid VM stack state')
    return stack[0]
""".format(
            helper=template.helper_name,
            functions="\n".join(functions),
            table_entries=table_entries,
        )

    def _register_helper_source(self, template: _VMTemplate) -> str:
        branches: List[str] = [
            """        if opcode == {0}:
            registers[entry[2]] = thunks[entry[1]]()""".format(
                template.push_token
            )
        ]
        for operator_type, _, expression in self.OPERATORS:
            branches.append(
                """        if opcode == {0}:
            left = registers[entry[1]]
            right = registers[entry[2]]
            registers[entry[3]] = {1}""".format(
                    template.operator_tokens[operator_type],
                    expression,
                )
            )
        for operator_type, _, expression in self.UNARY_OPERATORS:
            branches.append(
                """        if opcode == {0}:
            value = registers[entry[1]]
            registers[entry[2]] = {1}""".format(
                    template.unary_tokens[operator_type],
                    expression,
                )
            )
        self.entropy.random.shuffle(branches)
        rendered = "\n            continue\n".join(branches)
        return """def {helper}(program, thunks):
    registers = {{}}
    last_register = None
    for entry in program:
        opcode = entry[0]
        last_register = entry[-1]
{branches}
            continue
        raise RuntimeError('invalid VM opcode')
    if last_register is None or last_register not in registers:
        raise RuntimeError('invalid VM register state')
    result = registers[last_register]
    registers.clear()
    return result
""".format(helper=template.helper_name, branches=rendered)


class ConservativeCFGObfuscator(ast.NodeTransformer):
    """Turn tiny straight-line functions into a tokenized state dispatcher."""

    MAX_STATEMENTS = 5
    SENSITIVE_TYPES: Tuple[type, ...] = (
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.If,
        ast.Raise,
        ast.Yield,
        ast.YieldFrom,
        ast.Await,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
        ast.Call,
        ast.Global,
        ast.Nonlocal,
    )
    DYNAMIC_NAMES = ConservativeLocalRenamer.DYNAMIC_NAMES | {
        "__import__",
        "getattr",
        "setattr",
        "delattr",
        "pickle",
    }

    def __init__(self, entropy: BuildEntropy, used_names: Set[str]) -> None:
        self.entropy = entropy
        self.used_names = used_names
        self.function_count = 0
        self.block_count = 0
        self.skipped_reasons: Dict[str, int] = {}

    def _skip(self, reason: str) -> None:
        self.skipped_reasons[reason] = self.skipped_reasons.get(reason, 0) + 1

    @staticmethod
    def _is_docstring(statement: ast.stmt) -> bool:
        return (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        )

    def _simple_expression(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return True
        if isinstance(node, ast.Name):
            return isinstance(node.ctx, ast.Load)
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Tuple):
            return all(self._simple_expression(item) for item in node.elts)
        if isinstance(node, ast.List):
            return all(self._simple_expression(item) for item in node.elts)
        if isinstance(node, ast.UnaryOp):
            return self._simple_expression(node.operand)
        if isinstance(node, ast.BinOp):
            return self._simple_expression(node.left) and self._simple_expression(node.right)
        return False

    def _simple_statement(self, statement: ast.stmt, is_final: bool) -> bool:
        for child in ast.walk(statement):
            if isinstance(child, self.SENSITIVE_TYPES):
                return False
            if isinstance(child, ast.Name) and child.id in self.DYNAMIC_NAMES:
                return False
            match_type = getattr(ast, "Match", None)
            if match_type is not None and isinstance(child, match_type):
                return False
        if is_final:
            return isinstance(statement, ast.Return) and self._simple_expression(statement.value)
        if isinstance(statement, ast.Assign):
            return (
                all(isinstance(target, ast.Name) for target in statement.targets)
                and self._simple_expression(statement.value)
            )
        if isinstance(statement, ast.AnnAssign):
            return (
                isinstance(statement.target, ast.Name)
                and statement.value is not None
                and self._simple_expression(statement.value)
            )
        if isinstance(statement, ast.Expr):
            return self._simple_expression(statement.value)
        return False

    def _eligible_body(self, node: ast.FunctionDef) -> Optional[Tuple[List[ast.stmt], List[ast.stmt]]]:
        prefix: List[ast.stmt] = []
        body = list(node.body)
        if body and self._is_docstring(body[0]):
            prefix.append(body[0])
            body = body[1:]
        if len(body) < 2 or len(body) > self.MAX_STATEMENTS:
            self._skip("function-size-out-of-budget")
            return None
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._skip("nested-scope")
                return None
        for index, statement in enumerate(body):
            if not self._simple_statement(statement, index == len(body) - 1):
                self._skip("sensitive-or-nonlinear-statement")
                return None
        return prefix, body

    def _token(self, used: Set[int]) -> int:
        while True:
            token = self.entropy.random.randint(1 << 20, (1 << 31) - 1)
            if token not in used:
                used.add(token)
                return token

    @staticmethod
    def _name(identifier: str, context: ast.expr_context) -> ast.Name:
        return ast.Name(id=identifier, ctx=context)

    def _state_assign(self, state_name: str, token: int) -> ast.Assign:
        return ast.Assign(
            targets=[self._name(state_name, ast.Store())],
            value=ast.Constant(value=token),
        )

    def _build_dispatcher(
        self,
        core_body: List[ast.stmt],
        state_name: str,
        result_name: str,
    ) -> List[ast.stmt]:
        used_tokens: Set[int] = set()
        tokens = [self._token(used_tokens) for _ in range(len(core_body) + 1)]
        cases: List[ast.stmt] = []
        for index, statement in enumerate(core_body):
            case_body: List[ast.stmt] = []
            if index == len(core_body) - 1:
                final_return = statement
                if not isinstance(final_return, ast.Return):
                    raise SourceTransformError("CFG block does not end in return")
                case_body.append(
                    ast.Assign(
                        targets=[self._name(result_name, ast.Store())],
                        value=final_return.value
                        if final_return.value is not None
                        else ast.Constant(value=None),
                    )
                )
            else:
                case_body.append(statement)
            case_body.extend(
                [
                    self._state_assign(state_name, tokens[index + 1]),
                    ast.Continue(),
                ]
            )
            cases.append(
                ast.If(
                    test=ast.Compare(
                        left=self._name(state_name, ast.Load()),
                        ops=[ast.Eq()],
                        comparators=[ast.Constant(value=tokens[index])],
                    ),
                    body=case_body,
                    orelse=[],
                )
            )
        cases.append(
            ast.If(
                test=ast.Compare(
                    left=self._name(state_name, ast.Load()),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=tokens[-1])],
                ),
                body=[ast.Return(value=self._name(result_name, ast.Load()))],
                orelse=[],
            )
        )
        cases.append(
            ast.Raise(
                exc=ast.Call(
                    func=ast.Name(id="RuntimeError", ctx=ast.Load()),
                    args=[ast.Constant(value="invalid Ekitten CFG state")],
                    keywords=[],
                ),
                cause=None,
            )
        )
        self.block_count += len(tokens)
        return [
            self._state_assign(state_name, tokens[0]),
            ast.Assign(
                targets=[self._name(result_name, ast.Store())],
                value=ast.Constant(value=None),
            ),
            ast.While(test=ast.Constant(value=True), body=cases, orelse=[]),
        ]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        self.generic_visit(node)
        eligible = self._eligible_body(node)
        if eligible is None:
            return node
        prefix, core_body = eligible
        state_name = self.entropy.identifier(self.used_names)
        result_name = self.entropy.identifier(self.used_names)
        node.body = prefix + self._build_dispatcher(core_body, state_name, result_name)
        self.function_count += 1
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        return node


def _safe_injection_index(module: ast.Module) -> int:
    index = 0
    if (
        module.body
        and isinstance(module.body[0], ast.Expr)
        and isinstance(module.body[0].value, ast.Constant)
        and isinstance(module.body[0].value.value, str)
    ):
        index = 1
    while (
        index < len(module.body)
        and isinstance(module.body[index], ast.ImportFrom)
        and module.body[index].module == "__future__"
    ):
        index += 1
    return index


@dataclass(frozen=True)
class SourceTransformResult:
    source: str
    applied_passes: Tuple[str, ...]
    skipped_passes: Tuple[str, ...]


def transform_source(
    source: str,
    profile: Profile,
    entropy: BuildEntropy,
    filename: str,
    code_object_hardening: bool = False,
    vm_obfuscation: bool = False,
    cfg_obfuscation: bool = False,
) -> SourceTransformResult:
    try:
        tree = ast.parse(source, filename=filename, type_comments=True)
        compile(tree, filename, "exec", dont_inherit=True)
    except (SyntaxError, ValueError) as error:
        raise SourceTransformError("Input cannot be parsed: {0}".format(error)) from error

    applied: List[str] = ["parse-and-compile-validation"]
    skipped: List[str] = []
    if not (
        profile.literal_obfuscation
        or profile.integer_obfuscation
        or profile.local_renaming
        or code_object_hardening
        or vm_obfuscation
        or cfg_obfuscation
    ):
        return SourceTransformResult(source, tuple(applied), tuple(skipped))

    used_names = _collect_source_names(tree)
    string_helper = entropy.identifier(used_names)
    integer_helper = entropy.identifier(used_names)
    protected = _protected_literal_roots(tree, protect_joined_strings=not code_object_hardening)
    integer_transformer: Optional[IntObfuscator] = None
    string_transformer: Optional[StringObfuscator] = None
    vm_transformer: Optional[VMObfuscator] = None
    cfg_transformer: Optional[ConservativeCFGObfuscator] = None
    helper_sources: List[str] = []

    def validate(pass_id: str) -> None:
        ast.fix_missing_locations(tree)
        try:
            compile(tree, filename, "exec", dont_inherit=True)
        except (SyntaxError, ValueError, RecursionError) as error:
            raise SourceTransformError(
                "{0} produced an invalid AST: {1}".format(pass_id, error)
            ) from error

    def run_pass(pass_id: str, operation) -> None:
        nonlocal tree, protected, helper_sources
        snapshot_tree = copy.deepcopy(tree)
        snapshot_protected = set(protected)
        snapshot_helpers = list(helper_sources)
        snapshot_applied = list(applied)
        try:
            reports = operation()
            validate(pass_id)
            applied.extend(reports)
        except SourceTransformError as error:
            tree = snapshot_tree
            protected = snapshot_protected
            helper_sources = snapshot_helpers
            applied[:] = snapshot_applied
            skipped.append("{0}: {1}".format(pass_id, error))
        except Exception as error:
            tree = snapshot_tree
            protected = snapshot_protected
            helper_sources = snapshot_helpers
            applied[:] = snapshot_applied
            skipped.append("{0}: {1}".format(pass_id, error))

    if code_object_hardening:
        def apply_docstring_stripping() -> Tuple[str, ...]:
            nonlocal tree
            tree = DocstringStripper().visit(tree)  # type: ignore[assignment]
            return ("code-object-docstring-stripping",)

        run_pass("code-object-docstring-stripping", apply_docstring_stripping)

    if profile.local_renaming:
        def apply_local_renaming() -> Tuple[str, ...]:
            nonlocal tree
            renamer = ConservativeLocalRenamer(entropy, used_names)
            tree = renamer.visit(tree)  # type: ignore[assignment]
            if renamer.renamed_symbols:
                return (
                    "scope-aware-local-renaming:{0}-symbols".format(
                        renamer.renamed_symbols
                    ),
                )
            skipped.append("scope-aware-local-renaming: no statically safe local scopes")
            return ()

        run_pass("scope-aware-local-renaming", apply_local_renaming)

    if cfg_obfuscation:
        def apply_cfg_obfuscation() -> Tuple[str, ...]:
            nonlocal tree, cfg_transformer
            cfg_transformer = ConservativeCFGObfuscator(entropy, used_names)
            tree = cfg_transformer.visit(tree)  # type: ignore[assignment]
            if cfg_transformer.function_count:
                return (
                    "conservative-cfg-obfuscation:{0}-functions:{1}-blocks".format(
                        cfg_transformer.function_count,
                        cfg_transformer.block_count,
                    ),
                )
            reasons = ",".join(
                "{0}={1}".format(reason, count)
                for reason, count in sorted(cfg_transformer.skipped_reasons.items())
            )
            skipped.append(
                "conservative-cfg-obfuscation: no eligible straight-line functions"
                + (": " + reasons if reasons else "")
            )
            return ()

        run_pass("conservative-cfg-obfuscation", apply_cfg_obfuscation)

    protected = _protected_literal_roots(
        tree,
        protect_joined_strings=not code_object_hardening,
    )

    if vm_obfuscation:
        def apply_vm_obfuscation() -> Tuple[str, ...]:
            nonlocal tree, protected, vm_transformer
            vm_transformer = VMObfuscator(entropy, protected, used_names)
            tree = vm_transformer.visit(tree)  # type: ignore[assignment]
            protected.update(vm_transformer.generated_program_roots)
            helper_source = vm_transformer.helper_source()
            if helper_source:
                helper_sources.append(helper_source)
            if not vm_transformer.expression_count:
                skipped.append("multi-template-vm-obfuscation: no eligible expressions")
                return ()
            template_report = ",".join(
                "{0}={1}".format(kind, count)
                for kind, count in sorted(vm_transformer.template_counts.items())
                if count
            )
            return (
                "multi-template-vm-obfuscation:{0}-expressions:{1}-instructions:{2}:{3}".format(
                    vm_transformer.expression_count,
                    vm_transformer.instruction_count,
                    ",".join(sorted(vm_transformer.used_operators)),
                    template_report,
                ),
            )

        run_pass("multi-template-vm-obfuscation", apply_vm_obfuscation)

    if profile.integer_obfuscation:
        def apply_integer_obfuscation() -> Tuple[str, ...]:
            nonlocal tree, integer_transformer
            integer_transformer = IntObfuscator(integer_helper, entropy, protected)
            tree = integer_transformer.visit(tree)  # type: ignore[assignment]
            helper_sources.append(integer_transformer.helper_source())
            if not integer_transformer.integer_count:
                skipped.append("polymorphic-int-obfuscation: no eligible integer constants")
                return ()
            used_strategies = [
                name
                for name, count in integer_transformer.strategy_counts.items()
                if count
            ]
            return (
                "polymorphic-int-obfuscation:{0}:{1}".format(
                    integer_transformer.integer_count,
                    ",".join(used_strategies),
                ),
            )

        run_pass("polymorphic-int-obfuscation", apply_integer_obfuscation)

    if profile.literal_obfuscation:
        def apply_string_obfuscation() -> Tuple[str, ...]:
            nonlocal tree, string_transformer
            string_transformer = StringObfuscator(string_helper, entropy, protected)
            tree = string_transformer.visit(tree)  # type: ignore[assignment]
            helper_sources.append(string_transformer.helper_source())
            if not string_transformer.string_count:
                skipped.append("polymorphic-string-obfuscation: no eligible string literals")
                return ()
            used_string_strategies = [
                name
                for name, count in string_transformer.strategy_counts.items()
                if count
            ]
            return (
                "polymorphic-string-obfuscation:{0}:{1}".format(
                    string_transformer.string_count,
                    ",".join(used_string_strategies),
                ),
            )

        run_pass("polymorphic-string-obfuscation", apply_string_obfuscation)

    helper_source = "\n".join(helper_sources)
    if helper_source:
        helper_nodes = ast.parse(helper_source).body
        insertion_index = _safe_injection_index(tree)
        tree.body[insertion_index:insertion_index] = helper_nodes
        ast.fix_missing_locations(tree)

    try:
        transformed = ast.unparse(tree) + "\n"
        compile(transformed, filename, "exec", dont_inherit=True)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise SourceTransformError("Transformed source is invalid: {0}".format(error)) from error

    if any(item != "parse-and-compile-validation" for item in applied):
        applied.append("atomic-pass-rollback-validation")
    applied.append("ast-normalization")
    return SourceTransformResult(transformed, tuple(applied), tuple(skipped))


LOADER_TEMPLATE = r'''#!/usr/bin/env python3
# EKITTEN_SELF_SEAL=@@SELF_SEAL@@
# Generated by Ekitten Final. BlazingOpossum protected payload.
def @@BOOT@@():
    import base64 as @@B64@@, builtins as @@BUILTINS@@, hashlib as @@HASH@@, hmac as @@HMAC@@, marshal as @@MARSHAL@@, struct as @@STRUCT@@, sys as @@SYS@@, zlib as @@ZLIB@@
    @@MASK@@ = 0xffffffff
    @@PMUL@@ = 0x9e3779b9
    @@PADD@@ = 0xbb67ae85
    @@INIT@@ = (0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
    def @@WIPE@@(v):
        if type(v) is bytearray:
            for i in range(len(v)):v[i]=0
    def @@GUARD@@(v,m,n):
        return type(v) is type(len) and getattr(v,'__module__',None)==m and getattr(v,'__name__',None)==n
@@ANTI_TAMPER@@
    def @@ROTL@@(v,n):
        v &= @@MASK@@
        return ((v << n) | (v >> (32-n))) & @@MASK@@
    def @@SHUF@@(v,o):
        return [v[o[0]],v[o[1]],v[o[2]],v[o[3]],v[4+o[0]],v[4+o[1]],v[4+o[2]],v[4+o[3]]]
    def @@EXPAND@@(k):
        q=list(@@STRUCT@@.unpack('<8I',k));s=list(@@INIT@@);r=[]
        for _ in range(22):
            m=[(s[i]*@@PMUL@@+q[i])&@@MASK@@ for i in range(8)]
            p=@@SHUF@@(m,(1,0,3,2));s=[@@ROTL@@(s[i]^p[i],7) for i in range(8)]
            r.append(tuple(s));q=[(x+@@PADD@@)&@@MASK@@ for x in q]
        return r
    def @@PAIR@@(iv,c,r):
        lo,hi=@@STRUCT@@.unpack('<QQ',iv);a=(lo+c)&0xffffffffffffffff;b=(lo+c+1)&0xffffffffffffffff
        s=[hi>>32,hi&@@MASK@@,a>>32,a&@@MASK@@,hi>>32,hi&@@MASK@@,b>>32,b&@@MASK@@]
        for n in range(20):
            s=[(s[i]*@@PMUL@@+r[n][i])&@@MASK@@ for i in range(8)];s=@@SHUF@@(s,(3,2,0,1))
            s=[x^@@ROTL@@(x,13) for x in s];s=[(x+@@PADD@@)&@@MASK@@ for x in s]
        s=[s[i]^r[20][i] for i in range(8)]
        return @@STRUCT@@.pack('<8I',*s)
    def @@CRYPT@@(iv,d,r):
        out=bytearray(len(d));c=0
        for off in range(0,len(d),32):
            z=d[off:off+32];k=@@PAIR@@(iv,c,r);out[off:off+len(z)]=bytes(x^k[i] for i,x in enumerate(z));c+=2
        return out
    def @@TAG@@(iv,d,r):
        a=list(@@STRUCT@@.unpack('<8I',iv+iv));n=len(d)-len(d)%32
        for off in range(0,n,32):
            b=@@STRUCT@@.unpack('<8I',d[off:off+32]);a=[a[i]^b[i] for i in range(8)]
            a=[@@ROTL@@((x*@@PMUL@@+@@PADD@@)&@@MASK@@,11) for x in a]
        if n<len(d):
            t=bytearray(@@STRUCT@@.pack('<8I',*a))
            for i,x in enumerate(d[n:]):t[i]^=x
            a=list(@@STRUCT@@.unpack('<8I',bytes(t)))
        for q in range(4):
            a=[(((a[i]+r[q][i])&@@MASK@@)*@@PMUL@@)&@@MASK@@ for i in range(8)];p=@@SHUF@@(a,(1,0,3,2));a=[a[i]^p[i] for i in range(8)]
        return @@STRUCT@@.pack('<4I',*(a[i]^a[i+4] for i in range(4)))
    def @@DEC@@(key,iv,data):
        if len(data)<16:raise RuntimeError('Ekitten payload is truncated')
        r=@@EXPAND@@(key);c,t=data[:-16],data[-16:]
        try:
            if not @@HMAC@@.compare_digest(t,@@TAG@@(iv,c,r)):raise RuntimeError('Ekitten integrity check failed')
            return @@CRYPT@@(iv,c,r)
        finally:
            for i in range(len(r)):r[i]=(0,0,0,0,0,0,0,0)
    @@CHUNKS@@ = @@CHUNK_DATA@@
    @@RECORDS@@ = @@ROUND_DATA@@
    @@PAYLOAD@@ = bytearray(b''.join(@@B64@@.b85decode(x[1]) for x in sorted((x for x in @@CHUNKS@@ if x[0]>=0),key=lambda x:x[0])))
    for @@REC@@ in reversed(@@RECORDS@@):
        @@LEFT@@,@@RIGHT@@,@@IV@@=map(bytearray.fromhex,@@REC@@);@@KEY@@=bytearray(x^y for x,y in zip(@@LEFT@@,@@RIGHT@@));@@PREVIOUS@@=@@PAYLOAD@@
        @@PAYLOAD@@=@@DEC@@(@@KEY@@,@@IV@@,@@PREVIOUS@@);@@WIPE@@(@@PREVIOUS@@);@@WIPE@@(@@KEY@@);@@WIPE@@(@@LEFT@@);@@WIPE@@(@@RIGHT@@);@@WIPE@@(@@IV@@)
    @@RECORDS@@.clear();@@CHUNKS@@.clear()
    if not @@HMAC@@.compare_digest(@@HASH@@.sha256(@@PAYLOAD@@).hexdigest(),@@DIGEST@@):raise RuntimeError('Ekitten payload digest mismatch')
    @@ZDECOMP@@=@@ZLIB@@.decompress
    if not @@GUARD@@(@@ZDECOMP@@,'zlib','decompress'):raise RuntimeError('Ekitten runtime hook detected: zlib.decompress')
@@RUNTIME_GUARD@@
@@CODE_LOAD@@
    @@SCOPE@@=globals();@@FUNCTION@@=type(lambda:None);@@SCOPE@@.pop('@@BOOT@@',None)
    @@ENTRY@@=@@FUNCTION@@(@@CODE@@,@@SCOPE@@,@@FILENAME@@);@@CODE@@=None;@@ENTRY@@();@@ENTRY@@=None
@@BOOT@@()
'''


def _loader_identifiers(entropy: BuildEntropy) -> Dict[str, str]:
    placeholders = (
        "BOOT B64 BUILTINS HASH HMAC MARSHAL STRUCT SYS ZLIB MASK PMUL PADD INIT "
        "WIPE GUARD ROTL SHUF EXPAND PAIR CRYPT TAG DEC CHUNKS RECORDS PAYLOAD "
        "REC LEFT RIGHT IV KEY PREVIOUS CODE SCOPE FUNCTION ENTRY COMPILER ZDECOMP MLOAD BUFFER"
        " OPEN FILE RAW LINES EXPECTED LINE ENDING FOUND INDEX PREFIX"
    ).split()
    used: Set[str] = set()
    return {name: entropy.identifier(used) for name in placeholders}


def _build_loader(
    encrypted: bytes,
    round_records: Sequence[Tuple[bytes, bytes, bytes]],
    compressed_digest: str,
    filename: str,
    entropy: BuildEntropy,
    decoy_count: int,
    runtime_hardening: bool,
    python_version: Tuple[int, int],
    anti_tamper: bool,
) -> str:
    pieces: List[Tuple[int, bytes]] = []
    cursor = 0
    index = 0
    while cursor < len(encrypted):
        size = entropy.random.randint(53, 197)
        piece = encrypted[cursor : cursor + size]
        pieces.append((index, base64.b85encode(piece)))
        cursor += len(piece)
        index += 1

    for decoy_index in range(decoy_count):
        decoy = entropy.bytes(entropy.random.randint(24, 96), "decoy-{0}".format(decoy_index))
        pieces.append((-1 - decoy_index, base64.b85encode(decoy)))
    entropy.random.shuffle(pieces)

    serialized_records = [
        (masked.hex(), mask.hex(), iv.hex())
        for masked, mask, iv in round_records
    ]
    replacements = _loader_identifiers(entropy)
    if runtime_hardening:
        runtime_guard = """    if tuple(@@SYS@@.version_info[:2])!=@@PY_VERSION@@:raise RuntimeError('Ekitten hardened payload requires Python @@PY_VERSION_TEXT@@')
    @@MLOAD@@=@@MARSHAL@@.loads
    if not @@GUARD@@(@@MLOAD@@,'marshal','loads'):raise RuntimeError('Ekitten runtime hook detected: marshal.loads')"""
        code_load = """    @@BUFFER@@=bytearray(@@ZDECOMP@@(@@PAYLOAD@@));@@WIPE@@(@@PAYLOAD@@)
    try:@@CODE@@=@@MLOAD@@(@@BUFFER@@)
    finally:@@WIPE@@(@@BUFFER@@)
    if type(@@CODE@@) is not type((lambda:None).__code__):raise RuntimeError('Ekitten hardened code object is invalid')"""
    else:
        runtime_guard = """    @@COMPILER@@=@@BUILTINS@@.compile
    if not @@GUARD@@(@@COMPILER@@,'builtins','compile'):raise RuntimeError('Ekitten runtime hook detected: compile')"""
        code_load = """    @@BUFFER@@=bytearray(@@ZDECOMP@@(@@PAYLOAD@@));@@WIPE@@(@@PAYLOAD@@)
    try:@@CODE@@=@@COMPILER@@(@@BUFFER@@,@@FILENAME@@,'exec',dont_inherit=True)
    finally:@@WIPE@@(@@BUFFER@@)"""
    if anti_tamper:
        anti_tamper_source = """    @@OPEN@@=@@BUILTINS@@.open
    if type(@@OPEN@@) is not type(len) or getattr(@@OPEN@@,'__name__',None)!='open' or getattr(@@OPEN@@,'__module__',None) not in ('io','_io'):raise RuntimeError('Ekitten runtime hook detected: open')
    @@FILE@@=globals().get('__file__')
    if not @@FILE@@:raise RuntimeError('Ekitten anti-tamper requires a file-backed module')
    with @@OPEN@@(@@FILE@@,'rb') as @@RAW@@:@@LINES@@=@@RAW@@.read().splitlines(keepends=True)
    @@PREFIX@@=b'# EKITTEN_SELF_SEAL=';@@EXPECTED@@=None;@@FOUND@@=False
    for @@INDEX@@,@@LINE@@ in enumerate(@@LINES@@):
        if @@LINE@@.startswith(@@PREFIX@@):
            @@EXPECTED@@=@@LINE@@[len(@@PREFIX@@):].strip().decode('ascii');@@ENDING@@=b'\\r\\n' if @@LINE@@.endswith(b'\\r\\n') else (b'\\n' if @@LINE@@.endswith(b'\\n') else b'')
            @@LINES@@[@@INDEX@@]=@@PREFIX@@+b'0'*64+@@ENDING@@;@@FOUND@@=True;break
    if not @@FOUND@@ or len(@@EXPECTED@@)!=64 or not @@HMAC@@.compare_digest(@@HASH@@.sha256(b''.join(@@LINES@@)).hexdigest(),@@EXPECTED@@):raise RuntimeError('Ekitten artifact integrity seal failed')"""
    else:
        anti_tamper_source = ""
    loader = LOADER_TEMPLATE.replace("@@RUNTIME_GUARD@@", runtime_guard).replace(
        "@@CODE_LOAD@@", code_load
    )
    loader = loader.replace("@@ANTI_TAMPER@@", anti_tamper_source)
    loader = loader.replace("@@PY_VERSION@@", repr(python_version))
    loader = loader.replace(
        "@@PY_VERSION_TEXT@@", "{0}.{1}".format(*python_version)
    )
    for placeholder, identifier in replacements.items():
        loader = loader.replace("@@{0}@@".format(placeholder), identifier)
    unresolved_identifiers = [
        placeholder
        for placeholder in replacements
        if "@@{0}@@".format(placeholder) in loader
    ]
    if unresolved_identifiers:
        raise EkittenError(
            "Internal loader identifiers were not resolved: {0}".format(
                ", ".join(unresolved_identifiers)
            )
        )
    loader = loader.replace("@@CHUNK_DATA@@", repr(pieces))
    loader = loader.replace("@@ROUND_DATA@@", repr(serialized_records))
    loader = loader.replace("@@DIGEST@@", repr(compressed_digest))
    loader = loader.replace("@@FILENAME@@", repr(filename))
    zero_seal = "0" * 64
    loader = loader.replace("@@SELF_SEAL@@", zero_seal)
    if anti_tamper:
        seal = hashlib.sha256(loader.encode("utf-8")).hexdigest()
        loader = loader.replace(
            "# EKITTEN_SELF_SEAL=" + zero_seal,
            "# EKITTEN_SELF_SEAL=" + seal,
            1,
        )
    compile(loader, filename, "exec", dont_inherit=True)
    return loader


def _sanitize_code_object(code: object) -> object:
    """Recursively reduce source-location metadata retained by CPython code."""

    code_type = type((lambda: None).__code__)
    if not isinstance(code, code_type):
        return code
    constants = tuple(
        _sanitize_code_object(value) if isinstance(value, code_type) else value
        for value in code.co_consts
    )
    replacements = {
        "co_consts": constants,
        "co_filename": "<ekitten-protected>",
        "co_firstlineno": 1,
    }
    if hasattr(code, "co_linetable"):
        replacements["co_linetable"] = b""
    try:
        return code.replace(**replacements)
    except TypeError:
        replacements.pop("co_linetable", None)
        return code.replace(**replacements)


class EkittenObfuscator:
    def __init__(self, config: ObfuscationConfig) -> None:
        if config.code_object_hardening and not config.runtime_hardening:
            raise EkittenError(
                "Code-object hardening requires --runtime-hardening"
            )
        self.config = config
        self.profile = config.resolved_profile()
        self.entropy = BuildEntropy(config.seed)

    def obfuscate(self, source: str, filename: str = "<ekitten-input>") -> ObfuscationResult:
        source_result = transform_source(
            source,
            self.profile,
            self.entropy,
            filename,
            code_object_hardening=self.config.code_object_hardening,
            vm_obfuscation=self.config.vm_obfuscation,
            cfg_obfuscation=self.config.cfg_obfuscation,
        )
        transformed = source_result.source
        transformed_bytes = transformed.encode("utf-8")
        if self.config.runtime_hardening:
            code_object = compile(
                transformed,
                filename,
                "exec",
                dont_inherit=True,
                optimize=0,
            )
            if self.config.code_object_hardening:
                code_object = _sanitize_code_object(code_object)
            runtime_payload = marshal.dumps(code_object)
            runtime_prefix = (
                "hardened-code-object" if self.config.code_object_hardening
                else "hardened-marshal"
            )
            runtime_mode = "{0}-{1}.{2}".format(
                runtime_prefix,
                sys.version_info.major,
                sys.version_info.minor,
            )
        else:
            runtime_payload = transformed_bytes
            runtime_mode = "portable-source"
        compressed = zlib.compress(runtime_payload, level=9)
        compressed_digest = hashlib.sha256(compressed).hexdigest()
        payload = compressed
        records: List[Tuple[bytes, bytes, bytes]] = []

        for layer in range(self.profile.encryption_layers):
            key = self.entropy.bytes(BlazingOpossum.KEY_SIZE, "key-{0}".format(layer))
            iv = self.entropy.bytes(BlazingOpossum.IV_SIZE, "iv-{0}".format(layer))
            mask = self.entropy.bytes(BlazingOpossum.KEY_SIZE, "mask-{0}".format(layer))
            masked = bytes(left ^ right for left, right in zip(key, mask))
            payload = BlazingOpossum(key).encrypt(iv, payload)
            records.append((masked, mask, iv))

        loader = _build_loader(
            payload,
            records,
            compressed_digest,
            filename,
            self.entropy,
            self.profile.decoy_chunks,
            self.config.runtime_hardening,
            (sys.version_info.major, sys.version_info.minor),
            self.config.anti_tamper,
        )
        applied = list(source_result.applied_passes)
        applied.extend(
            (
                "zlib-compression",
                "blazing-opossum-authenticated-layers:{0}".format(
                    self.profile.encryption_layers
                ),
                "masked-key-splitting",
                "permuted-base85-chunks",
                "isolated-self-cleaning-loader",
                "bootstrap-functiontype-execution-no-exec",
                "runtime-hook-guards",
                "runtime-buffer-zeroization-best-effort",
            )
        )
        if self.config.runtime_hardening:
            applied.append(runtime_mode)
            applied.append("runtime-source-reconstruction-disabled")
            if self.config.code_object_hardening:
                applied.append("recursive-code-object-metadata-sanitization")
                applied.append("f-string-literal-obfuscation")
        else:
            applied.append(runtime_mode)
        if self.profile.decoy_chunks:
            applied.append("decoy-chunks:{0}".format(self.profile.decoy_chunks))
        if self.config.anti_tamper:
            applied.append("full-artifact-canonical-sha256-seal")

        return ObfuscationResult(
            source=loader,
            profile=self.profile.name,
            encryption_layers=self.profile.encryption_layers,
            source_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
            transformed_sha256=hashlib.sha256(transformed_bytes).hexdigest(),
            output_sha256=hashlib.sha256(loader.encode("utf-8")).hexdigest(),
            applied_passes=tuple(applied),
            runtime_mode=runtime_mode,
            skipped_passes=source_result.skipped_passes,
        )


def _read_python_source(path: Path) -> str:
    try:
        with tokenize.open(str(path)) as source_file:
            return source_file.read()
    except (OSError, SyntaxError, UnicodeError) as error:
        raise EkittenError("Cannot read {0}: {1}".format(path, error)) from error


def _write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".{0}.".format(path.name), suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(str(temporary), str(path))
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def obfuscate_file(
    input_path: Path,
    output_path: Path,
    obfuscator: EkittenObfuscator,
) -> ObfuscationResult:
    source = _read_python_source(input_path)
    result = obfuscator.obfuscate(source, input_path.name)
    _write_atomic(output_path, result.source)
    return result


def obfuscate_package_tree(
    input_path: Path,
    output_path: Path,
    config: ObfuscationConfig,
) -> List[Tuple[Path, Path, ObfuscationResult]]:
    input_path = input_path.resolve()
    output_path = output_path.resolve()
    if _is_relative_to(output_path, input_path):
        raise EkittenError("Package output directory must not be inside the input tree")
    obfuscator = EkittenObfuscator(config)
    results: List[Tuple[Path, Path, ObfuscationResult]] = []
    for source_item in sorted(input_path.rglob("*")):
        relative_item = source_item.relative_to(input_path)
        destination_item = output_path / relative_item
        if source_item.is_dir():
            destination_item.mkdir(parents=True, exist_ok=True)
            continue
        if source_item.suffix == ".py":
            result = obfuscate_file(source_item, destination_item, obfuscator)
            results.append((source_item, destination_item, result))
        else:
            destination_item.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_item, destination_item)
    if not results:
        raise EkittenError("Package tree does not contain Python files: {0}".format(input_path))
    return results


def _run_program(path: Path, arguments: Sequence[str], timeout: float) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = "0"
    return subprocess.run(
        [sys.executable, str(path), *arguments],
        cwd=str(path.parent),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def verify_equivalence(
    original: Path,
    protected: Path,
    arguments: Sequence[str],
    timeout: float,
) -> None:
    try:
        first = _run_program(original, arguments, timeout)
        second = _run_program(protected, arguments, timeout)
    except subprocess.TimeoutExpired as error:
        raise VerificationError("Verification timed out: {0}".format(error)) from error

    differences: List[str] = []
    if first.returncode != second.returncode:
        differences.append(
            "exit code {0} != {1}".format(first.returncode, second.returncode)
        )
    if first.stdout != second.stdout:
        differences.append("stdout differs")
    if first.stderr != second.stderr:
        differences.append("stderr differs")
    if differences:
        raise VerificationError("Differential verification failed: " + ", ".join(differences))


def benchmark_equivalence(
    original: Path,
    protected: Path,
    arguments: Sequence[str],
    timeout: float,
    repeat: int,
) -> dict:
    if repeat < 1:
        raise EkittenError("Benchmark repeat count must be at least 1")

    def measure(path: Path) -> Tuple[List[float], int]:
        durations: List[float] = []
        last_returncode = 0
        for _ in range(repeat):
            started = time.perf_counter()
            completed = _run_program(path, arguments, timeout)
            durations.append(time.perf_counter() - started)
            last_returncode = completed.returncode
        return durations, last_returncode

    original_times, original_returncode = measure(original)
    protected_times, protected_returncode = measure(protected)
    original_size = original.stat().st_size
    protected_size = protected.stat().st_size
    return {
        "repeat": repeat,
        "original_returncode": original_returncode,
        "protected_returncode": protected_returncode,
        "original_size_bytes": original_size,
        "protected_size_bytes": protected_size,
        "size_ratio": protected_size / max(original_size, 1),
        "original_median_seconds": sorted(original_times)[len(original_times) // 2],
        "protected_median_seconds": sorted(protected_times)[len(protected_times) // 2],
        "original_worst_seconds": max(original_times),
        "protected_worst_seconds": max(protected_times),
        "memory_peak_bytes": None,
    }


def run_self_test() -> None:
    key = bytes(range(32))
    iv = bytes(range(16))
    samples = (b"", b"x", bytes(range(31)), bytes(range(32)), bytes(range(255)))
    cipher = BlazingOpossum(key)
    for sample in samples:
        encrypted = cipher.encrypt(iv, sample)
        if cipher.decrypt(iv, encrypted) != sample:
            raise EkittenError("BlazingOpossum round-trip self-test failed")

    tampered = bytearray(cipher.encrypt(iv, b"integrity"))
    tampered[0] ^= 1
    try:
        cipher.decrypt(iv, bytes(tampered))
    except IntegrityError:
        pass
    else:
        raise EkittenError("BlazingOpossum tamper self-test failed")

    integer_obfuscator = IntObfuscator(
        "_ekitten_integer_self_test",
        BuildEntropy(314159),
        set(),
    )
    integer_namespace: Dict[str, object] = {}
    exec(
        compile(
            integer_obfuscator.helper_source(),
            "<self-test-int-helper>",
            "exec",
            dont_inherit=True,
        ),
        integer_namespace,
        integer_namespace,
    )
    integer_decoder = integer_namespace["_ekitten_integer_self_test"]
    for integer_value in (
        0,
        1,
        -1,
        (1 << 63) - 1,
        -(1 << 63),
        10**100,
        -(10**100),
    ):
        for strategy_index, token in enumerate(integer_obfuscator.tokens):
            encoded_parts = integer_obfuscator._encode(
                integer_value, strategy_index
            )
            decoded_value = integer_decoder(  # type: ignore[operator]
                token, *encoded_parts
            )
            if decoded_value != integer_value:
                raise EkittenError(
                    "Integer obfuscator self-test failed for strategy {0}".format(
                        IntObfuscator.STRATEGIES[strategy_index]
                    )
                )

    string_obfuscator = StringObfuscator(
        "_ekitten_string_self_test",
        BuildEntropy(271828),
        set(),
    )
    string_namespace: Dict[str, object] = {}
    exec(
        compile(
            string_obfuscator.helper_source(),
            "<self-test-string-helper>",
            "exec",
            dont_inherit=True,
        ),
        string_namespace,
        string_namespace,
    )
    string_decoder = string_namespace["_ekitten_string_self_test"]
    for string_value in (
        "",
        "plain ASCII",
        "quote:' double:\" slash:\\ newline:\n",
        "gattino-è-東京-🐈",
        "nul:\x00:end",
        "long-" * 128,
    ):
        raw_string = string_value.encode("utf-8")
        for strategy_index, token in enumerate(string_obfuscator.tokens):
            encoded_string = string_obfuscator._encode(
                raw_string, strategy_index
            )
            decoded_string = string_decoder(  # type: ignore[operator]
                token, *encoded_string
            )
            if decoded_string != string_value:
                raise EkittenError(
                    "String obfuscator self-test failed for strategy {0}".format(
                        StringObfuscator.STRATEGIES[strategy_index]
                    )
                )

    sample_source = """\"\"\"sample docstring\"\"\"
from __future__ import annotations
def calculate(value: int = 3) -> str:
    temporary = value + 39
    return f\"answer={temporary}\"
print(calculate())
"""
    for profile_name in PROFILES:
        result = EkittenObfuscator(
            ObfuscationConfig(profile=profile_name, seed=12345)
        ).obfuscate(sample_source, "<self-test>")
        namespace = {"__name__": "__main__"}
        exec(
            compile(
                result.source,
                "<self-test-loader>",
                "exec",
                dont_inherit=True,
            ),
            namespace,
            namespace,
        )
    hardened_result = EkittenObfuscator(
        ObfuscationConfig(
            profile="maximum",
            seed=54321,
            runtime_hardening=True,
        )
    ).obfuscate(sample_source, "<self-test-hardened>")
    hardened_namespace = {"__name__": "__main__"}
    exec(
        compile(
            hardened_result.source,
            "<self-test-hardened-loader>",
            "exec",
            dont_inherit=True,
        ),
        hardened_namespace,
        hardened_namespace,
    )
    code_object_result = EkittenObfuscator(
        ObfuscationConfig(
            profile="maximum",
            seed=98765,
            runtime_hardening=True,
            code_object_hardening=True,
        )
    ).obfuscate(sample_source, "<self-test-code-object>")
    code_object_namespace = {"__name__": "__main__"}
    exec(
        compile(
            code_object_result.source,
            "<self-test-code-object-loader>",
            "exec",
            dont_inherit=True,
        ),
        code_object_namespace,
        code_object_namespace,
    )
    if code_object_namespace.get("__doc__") is not None:
        raise EkittenError("Code-object hardening did not strip module docstring")
    hardened_function = code_object_namespace["calculate"]
    if hardened_function.__code__.co_filename != "<ekitten-protected>":
        raise EkittenError("Code-object filename metadata was not sanitized")

    vm_result = EkittenObfuscator(
        ObfuscationConfig(
            profile="maximum",
            seed=24680,
            vm_obfuscation=True,
        )
    ).obfuscate(sample_source, "<self-test-vm>")
    if not any(
        item.startswith("multi-template-vm-obfuscation:")
        for item in vm_result.applied_passes
    ):
        raise EkittenError("VM obfuscation did not virtualize test expressions")
    vm_namespace = {"__name__": "__main__"}
    exec(
        compile(
            vm_result.source,
            "<self-test-vm-loader>",
            "exec",
            dont_inherit=True,
        ),
        vm_namespace,
        vm_namespace,
    )

    cfg_source = """def route(value):
    first = value + 2
    second = first * 5
    return second - value
"""
    cfg_result = EkittenObfuscator(
        ObfuscationConfig(
            profile="compatible",
            seed=112233,
            cfg_obfuscation=True,
        )
    ).obfuscate(cfg_source, "<self-test-cfg>")
    if not any(
        item.startswith("conservative-cfg-obfuscation:")
        for item in cfg_result.applied_passes
    ):
        raise EkittenError("CFG obfuscation did not virtualize test function")
    cfg_namespace = {"__name__": "__main__"}
    exec(
        compile(
            cfg_result.source,
            "<self-test-cfg-loader>",
            "exec",
            dont_inherit=True,
        ),
        cfg_namespace,
        cfg_namespace,
    )
    if cfg_namespace["route"](4) != 26:
        raise EkittenError("CFG obfuscation changed function semantics")

    with tempfile.TemporaryDirectory(prefix="ekitten-package-self-test-") as temporary_dir:
        root = Path(temporary_dir)
        source_parent = root / "source"
        protected_parent = root / "protected"
        package_input = source_parent / "samplepkg"
        package_output = protected_parent / "samplepkg"
        package_input.mkdir(parents=True)
        _write_atomic(package_input / "__init__.py", "NAME = 'samplepkg'\n")
        _write_atomic(
            package_input / "worker.py",
            "def value():\n    return 40 + 2\n",
        )
        _write_atomic(package_input / "data.txt", "resource-ok\n")
        _write_atomic(
            package_input / "__main__.py",
            "from importlib.resources import files\n"
            "from .worker import value\n"
            "print(str(value()) + ':' + files(__package__).joinpath('data.txt').read_text(encoding='utf-8').strip())\n",
        )
        obfuscate_package_tree(
            package_input,
            package_output,
            ObfuscationConfig(profile="compatible", seed=445566),
        )
        package_process = subprocess.run(
            [sys.executable, "-m", "samplepkg"],
            cwd=str(protected_parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10.0,
            check=False,
        )
        if package_process.returncode != 0 or package_process.stdout.strip() != b"42:resource-ok":
            raise EkittenError(
                "Package tree self-test failed: {0}".format(
                    package_process.stderr.decode("utf-8", errors="replace")
                )
            )

    anti_tamper_result = EkittenObfuscator(
        ObfuscationConfig(
            profile="maximum",
            seed=13579,
            anti_tamper=True,
        )
    ).obfuscate(sample_source, "<self-test-anti-tamper>")
    with tempfile.TemporaryDirectory(prefix="ekitten-self-test-") as temporary_dir:
        sealed_path = Path(temporary_dir) / "sealed.py"
        _write_atomic(sealed_path, anti_tamper_result.source)
        sealed_process = _run_program(sealed_path, (), 10.0)
        if sealed_process.returncode != 0 or b"answer=42" not in sealed_process.stdout:
            raise EkittenError("Anti-tamper sealed artifact did not execute")
        tampered_source = anti_tamper_result.source.replace(
            "# Generated by Ekitten Final.",
            "# Modified Ekitten artifact.",
            1,
        )
        _write_atomic(sealed_path, tampered_source)
        tampered_process = _run_program(sealed_path, (), 10.0)
        if (
            tampered_process.returncode == 0
            or b"artifact integrity seal failed" not in tampered_process.stderr
        ):
            raise EkittenError("Anti-tamper seal did not reject a modified file")

    function_type = type(lambda: None)

    def expect_hook_rejection(
        loader_source: str,
        owner: object,
        attribute: str,
        replacement: object,
        expected_message: str,
    ) -> None:
        loader_code = compile(
            loader_source,
            "<self-test-hook-loader>",
            "exec",
            dont_inherit=True,
        )
        original = getattr(owner, attribute)
        setattr(owner, attribute, replacement)
        try:
            namespace = {"__name__": "__main__", "__builtins__": builtins}
            function_type(loader_code, namespace, "<self-test-hook>")()
        except RuntimeError as error:
            if expected_message not in str(error):
                raise EkittenError(
                    "Unexpected runtime guard error: {0}".format(error)
                ) from error
        else:
            raise EkittenError(
                "Runtime hook guard did not reject {0}".format(attribute)
            )
        finally:
            setattr(owner, attribute, original)

    expect_hook_rejection(
        result.source,
        builtins,
        "compile",
        lambda *args, **kwargs: None,
        "runtime hook detected: compile",
    )
    expect_hook_rejection(
        result.source,
        zlib,
        "decompress",
        lambda *args, **kwargs: b"",
        "runtime hook detected: zlib.decompress",
    )
    expect_hook_rejection(
        hardened_result.source,
        marshal,
        "loads",
        lambda *args, **kwargs: None,
        "runtime hook detected: marshal.loads",
    )
    expect_hook_rejection(
        anti_tamper_result.source,
        builtins,
        "open",
        lambda *args, **kwargs: None,
        "runtime hook detected: open",
    )

    hardened_loader_code = compile(
        hardened_result.source,
        "<self-test-no-exec-loader>",
        "exec",
        dont_inherit=True,
    )
    original_exec = builtins.exec
    builtins.exec = lambda *args, **kwargs: (_ for _ in ()).throw(
        RuntimeError("hooked exec was called")
    )
    try:
        no_exec_namespace = {"__name__": "__main__", "__builtins__": builtins}
        function_type(
            hardened_loader_code,
            no_exec_namespace,
            "<self-test-no-exec>",
        )()
    finally:
        builtins.exec = original_exec


def _manifest(result: ObfuscationResult, input_path: Path, output_path: Path) -> dict:
    return {
        "tool": "Ekitten Final",
        "version": __version__,
        "input": str(input_path),
        "output": str(output_path),
        "profile": result.profile,
        "encryption_layers": result.encryption_layers,
        "source_sha256": result.source_sha256,
        "transformed_sha256": result.transformed_sha256,
        "output_sha256": result.output_sha256,
        "applied_passes": list(result.applied_passes),
        "skipped_passes": list(result.skipped_passes),
        "runtime_mode": result.runtime_mode,
        "code_object_hardening": result.runtime_mode.startswith(
            "hardened-code-object-"
        ),
        "vm_obfuscation": any(
            item.startswith("multi-template-vm-obfuscation:")
            for item in result.applied_passes
        ),
        "cfg_obfuscation": any(
            item.startswith("conservative-cfg-obfuscation:")
            for item in result.applied_passes
        ),
        "anti_tamper": "full-artifact-canonical-sha256-seal"
        in result.applied_passes,
        "python_build_abi": "{0}.{1}".format(
            sys.version_info.major, sys.version_info.minor
        ),
        "cipher": "BlazingOpossum MARX-P/CTR Python port (experimental)",
        "aes_used": False,
    }


def _package_manifest(
    results: Sequence[Tuple[Path, Path, ObfuscationResult]],
    input_path: Path,
    output_path: Path,
    config: ObfuscationConfig,
) -> dict:
    aggregate = hashlib.sha256()
    modules = []
    applied: Set[str] = set()
    skipped: Set[str] = set()
    for source_path, destination_path, result in results:
        aggregate.update(str(source_path.relative_to(input_path)).encode("utf-8"))
        aggregate.update(result.output_sha256.encode("ascii"))
        applied.update(result.applied_passes)
        skipped.update(result.skipped_passes)
        modules.append(
            {
                "input": str(source_path),
                "output": str(destination_path),
                "source_sha256": result.source_sha256,
                "transformed_sha256": result.transformed_sha256,
                "output_sha256": result.output_sha256,
                "applied_passes": list(result.applied_passes),
                "skipped_passes": list(result.skipped_passes),
                "runtime_mode": result.runtime_mode,
            }
        )
    return {
        "tool": "Ekitten Final",
        "version": __version__,
        "input": str(input_path),
        "output": str(output_path),
        "package_tree": True,
        "modules": modules,
        "module_count": len(modules),
        "profile": config.profile,
        "aggregate_output_sha256": aggregate.hexdigest(),
        "applied_passes": sorted(applied),
        "skipped_passes": sorted(skipped),
        "python_build_abi": "{0}.{1}".format(
            sys.version_info.major,
            sys.version_info.minor,
        ),
        "aes_used": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Obfuscate a Python script with conservative AST passes and an "
            "authenticated BlazingOpossum payload."
        )
    )
    parser.add_argument("input", nargs="?", type=Path, help="Python source file or package directory")
    parser.add_argument("-o", "--output", type=Path, help="Generated Python file or package directory")
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        default="balanced",
        help="Protection/compatibility profile (default: balanced)",
    )
    parser.add_argument(
        "--layers",
        type=int,
        help="Override BlazingOpossum layer count (1-12)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Reproducible build seed; omit for fresh cryptographic randomness",
    )
    parser.add_argument(
        "--runtime-hardening",
        action="store_true",
        help=(
            "Avoid runtime source reconstruction and compile/exec by embedding "
            "a version-locked marshalled code object"
        ),
    )
    parser.add_argument(
        "--code-object-hardening",
        action="store_true",
        help=(
            "Strip docstrings, obfuscate f-string literals and sanitize code "
            "metadata; requires --runtime-hardening and changes introspection"
        ),
    )
    parser.add_argument(
        "--vm-obfuscation",
        action="store_true",
        help=(
            "Virtualize conservative arithmetic expression trees with "
            "per-scope polymorphic VM templates"
        ),
    )
    parser.add_argument(
        "--cfg-obfuscation",
        action="store_true",
        help=(
            "Virtualize tiny straight-line function bodies with a conservative "
            "state dispatcher"
        ),
    )
    parser.add_argument(
        "--anti-tamper",
        action="store_true",
        help=(
            "Seal the complete generated file and verify it before payload "
            "decryption; requires file-backed execution"
        ),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Write a JSON build manifest without keys or plaintext",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run original and generated scripts and compare exit/stdout/stderr",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Measure subprocess runtime and output size for original/protected files",
    )
    parser.add_argument(
        "--benchmark-repeat",
        type=int,
        default=5,
        help="Benchmark repetitions per file (default: 5)",
    )
    parser.add_argument(
        "--verify-arg",
        action="append",
        default=[],
        help="Argument passed to both programs during --verify (repeatable)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Verification timeout per process in seconds",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal cipher, integrity and loader checks",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.self_test:
            run_self_test()
            print("Ekitten Final self-test: OK")
            return 0
        if arguments.input is None:
            parser.error("input is required unless --self-test is used")

        input_path = arguments.input.resolve()
        if not input_path.exists():
            raise EkittenError("Input path does not exist: {0}".format(input_path))
        output_path = (
            arguments.output.resolve()
            if arguments.output is not None
            else (
                input_path.with_name(input_path.name + "-ekitten")
                if input_path.is_dir()
                else input_path.with_name(input_path.stem + "-ekitten.py")
            )
        )
        if input_path == output_path:
            raise EkittenError("Input and output paths must be different")

        config = ObfuscationConfig(
            profile=arguments.profile,
            seed=arguments.seed,
            encryption_layers=arguments.layers,
            runtime_hardening=arguments.runtime_hardening,
            code_object_hardening=arguments.code_object_hardening,
            vm_obfuscation=arguments.vm_obfuscation,
            cfg_obfuscation=arguments.cfg_obfuscation,
            anti_tamper=arguments.anti_tamper,
        )
        if input_path.is_dir():
            if arguments.verify or arguments.benchmark:
                raise EkittenError(
                    "--verify/--benchmark for package trees requires an explicit fixture; "
                    "run the generated package entry point separately"
                )
            package_results = obfuscate_package_tree(input_path, output_path, config)
            if arguments.manifest is not None:
                manifest_path = arguments.manifest.resolve()
                manifest_text = json.dumps(
                    _package_manifest(
                        package_results,
                        input_path,
                        output_path,
                        config,
                    ),
                    indent=2,
                    sort_keys=True,
                ) + "\n"
                _write_atomic(manifest_path, manifest_text)
            print("Protected package tree: {0}".format(output_path))
            print("Python modules protected: {0}".format(len(package_results)))
            print("Profile: {0}".format(config.resolved_profile().name))
            return 0

        if not input_path.is_file():
            raise EkittenError("Input is neither a file nor a directory: {0}".format(input_path))

        result = obfuscate_file(input_path, output_path, EkittenObfuscator(config))

        if arguments.manifest is not None:
            manifest_path = arguments.manifest.resolve()
            manifest_text = json.dumps(
                _manifest(result, input_path, output_path),
                indent=2,
                sort_keys=True,
            ) + "\n"
            _write_atomic(manifest_path, manifest_text)

        if arguments.verify:
            verify_equivalence(
                input_path,
                output_path,
                arguments.verify_arg,
                arguments.timeout,
            )
        if arguments.benchmark:
            benchmark = benchmark_equivalence(
                input_path,
                output_path,
                arguments.verify_arg,
                arguments.timeout,
                arguments.benchmark_repeat,
            )

        print("Protected file: {0}".format(output_path))
        print("Profile: {0}; BlazingOpossum layers: {1}".format(
            result.profile, result.encryption_layers
        ))
        print("Runtime mode: {0}".format(result.runtime_mode))
        print("Output SHA-256: {0}".format(result.output_sha256))
        if arguments.verify:
            print("Differential verification: OK")
        if arguments.benchmark:
            print(
                "Benchmark median seconds: original={0:.6f}; protected={1:.6f}; size_ratio={2:.2f}x".format(
                    benchmark["original_median_seconds"],
                    benchmark["protected_median_seconds"],
                    benchmark["size_ratio"],
                )
            )
        return 0
    except (EkittenError, OSError, subprocess.SubprocessError) as error:
        print("Ekitten Final error: {0}".format(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
