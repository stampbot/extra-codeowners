"""Check the required schema against a connected PostgreSQL or SQLite database."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager

from sqlalchemy import CheckConstraint, Index, MetaData, UniqueConstraint, inspect, select, text
from sqlalchemy.engine import Connection, Engine

_SCHEMA_EXPRESSION_TOKEN = re.compile(
    r"\s*(>=|<=|=|<|>|\(|\)|,|\"(?:[^\"]|\"\")*\"|'(?:[^']|'')*'|[A-Za-z_][A-Za-z0-9_]*|[0-9]+)"
)


def _postgresql_type_name_is_valid(value: str) -> bool:
    """Accept one simple PostgreSQL type name emitted by constraint deparsing."""

    parts = value.split()
    return bool(parts) and all(
        part.isascii()
        and part[0].isalpha()
        and all(character.isalnum() or character == "_" for character in part)
        for part in parts
    )


def _postgresql_any_array_values(source: str) -> list[str] | None:
    """Read string literals and their casts from PostgreSQL's ``ARRAY[...]`` text."""

    values: list[str] = []
    position = 0
    while True:
        while position < len(source) and source[position].isspace():
            position += 1
        if position >= len(source) or source[position] != "'":
            return None
        position += 1
        literal: list[str] = []
        while position < len(source):
            character = source[position]
            position += 1
            if character != "'":
                literal.append(character)
                continue
            if position < len(source) and source[position] == "'":
                literal.append("''")
                position += 1
                continue
            break
        else:
            return None
        cast_count = 0
        while True:
            while position < len(source) and source[position].isspace():
                position += 1
            if not source.startswith("::", position):
                break
            position += 2
            type_start = position
            while (
                position < len(source)
                and source[position] != ","
                and not source.startswith("::", position)
            ):
                position += 1
            if not _postgresql_type_name_is_valid(source[type_start:position].strip()):
                return None
            cast_count += 1
        if cast_count == 0:
            return None
        values.append("'" + "".join(literal) + "'")
        while position < len(source) and source[position].isspace():
            position += 1
        if position == len(source):
            return values
        if source[position] != ",":
            return None
        position += 1


def _normalize_postgresql_any_array_check(source: str) -> str | None:
    """Convert PostgreSQL's ``IN`` deparse form back to our narrow grammar.

    PostgreSQL renders a ``CHECK (column IN (...))`` as a type-cast ``ANY
    (ARRAY[...])`` expression.  The runtime schema verifier deliberately only
    accepts a small predicate grammar, so recognize precisely that deparse
    form rather than allowing arbitrary PostgreSQL expressions.
    """

    left, separator, right = source.partition("=")
    if not separator:
        return None
    column, cast, column_type = left.strip().partition("::")
    if not cast or not _postgresql_type_name_is_valid(column_type.strip()):
        return None
    any_expression = right.strip()
    if any_expression[:3].casefold() != "any":
        return None
    array_expression = any_expression[3:].strip()
    if not (array_expression.startswith("(") and array_expression.endswith(")")):
        return None
    array_expression = array_expression[1:-1].strip()
    if array_expression[:6].casefold() != "array[":
        return None

    in_string = False
    array_end: int | None = None
    for position, character in enumerate(array_expression[6:], start=6):
        if character != "'":
            if character == "]" and not in_string:
                array_end = position
                break
            continue
        if (
            in_string
            and position + 1 < len(array_expression)
            and array_expression[position + 1] == "'"
        ):
            continue
        in_string = not in_string
    if array_end is None or in_string:
        return None
    array_type = array_expression[array_end + 1 :].strip()
    if array_type:
        if not (array_type.startswith("::") and array_type.endswith("[]")):
            return None
        if not _postgresql_type_name_is_valid(array_type[2:-2].strip()):
            return None
    values = _postgresql_any_array_values(array_expression[6:array_end])
    if not values:
        return None
    return f"{column} IN ({', '.join(values)})"


def _normalize_schema_expression(value: object) -> tuple[object, ...] | None:
    """Parse the deliberately small SQL predicate grammar used by this schema."""

    if value is None:
        return None
    source = str(value).strip()
    postgresql_in = _normalize_postgresql_any_array_check(source)
    if postgresql_in is not None:
        source = postgresql_in
    tokens: list[str] = []
    position = 0
    while position < len(source):
        match = _SCHEMA_EXPRESSION_TOKEN.match(source, position)
        if match is None:
            raise RuntimeError("database schema contains an unsupported SQL expression")
        tokens.append(match.group(1))
        position = match.end()
    cursor = 0

    def operand() -> str:
        nonlocal cursor
        if cursor >= len(tokens):
            raise RuntimeError("database schema contains an incomplete SQL expression")
        token = tokens[cursor]
        if token.startswith('"') and token.endswith('"'):
            token = token[1:-1].replace('""', '"')
        elif token.startswith("'") and token.endswith("'"):
            token = token[1:-1].replace("''", "'")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+", token) is None:
            raise RuntimeError("database schema contains an unsupported SQL operand")
        cursor += 1
        return token.lower()

    def comparison() -> tuple[object, ...]:
        nonlocal cursor
        left = operand()
        if cursor >= len(tokens):
            raise RuntimeError("database schema contains an unsupported SQL comparison")
        if tokens[cursor].lower() == "in":
            cursor += 1
            if cursor >= len(tokens) or tokens[cursor] != "(":
                raise RuntimeError("database schema contains an invalid SQL IN expression")
            cursor += 1
            values = [operand()]
            while cursor < len(tokens) and tokens[cursor] == ",":
                cursor += 1
                values.append(operand())
            if cursor >= len(tokens) or tokens[cursor] != ")" or len(values) < 1:
                raise RuntimeError("database schema contains an invalid SQL IN expression")
            cursor += 1
            return ("in", left, *values)
        if tokens[cursor] not in {">=", "<=", "=", "<", ">"}:
            raise RuntimeError("database schema contains an unsupported SQL comparison")
        operator = tokens[cursor]
        cursor += 1
        return ("comparison", left, operator, operand())

    def term() -> tuple[object, ...]:
        nonlocal cursor
        if cursor < len(tokens) and tokens[cursor] == "(":
            cursor += 1
            result = expression()
            if cursor >= len(tokens) or tokens[cursor] != ")":
                raise RuntimeError("database schema contains unbalanced SQL parentheses")
            cursor += 1
            return result
        return comparison()

    def expression() -> tuple[object, ...]:
        nonlocal cursor
        terms = [term()]
        while cursor < len(tokens) and tokens[cursor].lower() == "and":
            cursor += 1
            terms.append(term())
        return terms[0] if len(terms) == 1 else ("and", *terms)

    contract = expression()
    if cursor != len(tokens):
        raise RuntimeError("database schema contains an unsupported SQL expression")
    return contract


def _empty_index_option(value: object) -> bool:
    return value is None or value is False or value == [] or value == () or value == {}


def _expected_index_contract(
    table_name: str,
    index: Index,
    dialect_name: str,
) -> tuple[tuple[str, ...], bool, tuple[object, ...] | None]:
    raw_columns = tuple(column.name for column in index.columns)
    if (
        not index.name
        or not raw_columns
        or any(not isinstance(column, str) or not column for column in raw_columns)
    ):
        raise RuntimeError(f"application index contract is invalid for table {table_name!r}")
    columns = tuple(str(column) for column in raw_columns)
    predicate = index.dialect_options[dialect_name].get("where")
    return columns, bool(index.unique), _normalize_schema_expression(predicate)


def _inspected_index_contract(
    table_name: str,
    index: Mapping[str, object],
    dialect_name: str,
) -> tuple[
    str,
    tuple[tuple[str, ...], bool, tuple[object, ...] | None],
]:
    name = index.get("name")
    columns = index.get("column_names")
    unique = index.get("unique")
    if (
        not isinstance(name, str)
        or not name
        or not isinstance(columns, list)
        or not columns
        or any(not isinstance(column, str) or not column for column in columns)
        or not isinstance(unique, (bool, int))
        or int(unique) not in (0, 1)
        or not _empty_index_option(index.get("include_columns"))
        or bool(index.get("column_sorting"))
        or bool(index.get("expressions"))
    ):
        raise RuntimeError(
            f"database table {table_name!r} contains an unsupported index definition"
        )
    dialect_options = index.get("dialect_options")
    if dialect_options is None:
        options: Mapping[str, object] = {}
    elif isinstance(dialect_options, Mapping):
        options = dialect_options
    else:
        raise RuntimeError(
            f"database table {table_name!r} contains an unsupported index definition"
        )
    where_key = f"{dialect_name}_where"
    for option_name, option_value in options.items():
        if option_name == where_key or _empty_index_option(option_value):
            continue
        raise RuntimeError(
            f"database index {name!r} on table {table_name!r} has unsupported options"
        )
    predicate = _normalize_schema_expression(options.get(where_key))
    return name, (tuple(columns), bool(unique), predicate)


@contextmanager
def _schema_connection(bind: Engine | Connection) -> Iterator[Connection]:
    if isinstance(bind, Connection):
        yield bind
    else:
        with bind.connect() as connection:
            yield connection


def validate_database_schema_contract(
    bind: Engine | Connection, metadata: MetaData, *, revision: str, version: int
) -> None:
    """Validate the required release schema contract using a supplied bind."""

    inspector = inspect(bind)
    dialect_name = bind.dialect.name
    tables = set(inspector.get_table_names())
    if "alembic_version" not in tables:
        raise RuntimeError(
            "database has not been migrated; run `extra-codeowners database migrate`"
        )
    with _schema_connection(bind) as connection:
        revisions = connection.execute(text("SELECT version_num FROM alembic_version")).scalars()
        current_revisions = tuple(revisions)
    if current_revisions != (revision,):
        raise RuntimeError(
            f"database migration revision {current_revisions!r} is incompatible with "
            f"required revision {revision!r}; run "
            "`extra-codeowners database migrate`"
        )
    actual_serials: dict[tuple[str, str], str | None] = {}
    actual_sequence_states: dict[
        tuple[str, str],
        tuple[str, int, int, int, int, int, bool] | None,
    ] = {}
    if dialect_name == "postgresql":
        with _schema_connection(bind) as connection:
            for table in metadata.sorted_tables:
                generated_column = table.autoincrement_column
                if generated_column is not None:
                    key = (table.name, generated_column.name)
                    serial_name = connection.scalar(
                        text("SELECT pg_get_serial_sequence(:table_name, :column_name)"),
                        {
                            "table_name": table.name,
                            "column_name": generated_column.name,
                        },
                    )
                    actual_serials[key] = serial_name
                    sequence_row = None
                    if serial_name is not None:
                        sequence_row = connection.execute(
                            text(
                                """
                                SELECT
                                    seqtypid::regtype::text,
                                    seqstart,
                                    seqincrement,
                                    seqmax,
                                    seqmin,
                                    seqcache,
                                    seqcycle
                                FROM pg_sequence
                                WHERE seqrelid = CAST(:sequence_name AS regclass)
                                """
                            ),
                            {"sequence_name": serial_name},
                        ).one_or_none()
                    actual_sequence_states[key] = (
                        None
                        if sequence_row is None
                        else (
                            str(sequence_row[0]),
                            int(sequence_row[1]),
                            int(sequence_row[2]),
                            int(sequence_row[3]),
                            int(sequence_row[4]),
                            int(sequence_row[5]),
                            bool(sequence_row[6]),
                        )
                    )
    for table in metadata.sorted_tables:
        if table.name not in tables:
            raise RuntimeError(f"database schema is missing table {table.name!r}")
        inspected_columns = inspector.get_columns(table.name)
        actual_columns = {column["name"] for column in inspected_columns}
        expected_columns = {column.name for column in table.columns}
        missing = expected_columns - actual_columns
        unexpected = actual_columns - expected_columns
        if missing or unexpected:
            raise RuntimeError(
                f"database table {table.name!r} has incompatible columns; "
                f"missing {sorted(missing)!r}, unexpected {sorted(unexpected)!r}"
            )
        actual_by_name = {column["name"]: column for column in inspected_columns}
        for expected_column in table.columns:
            actual_column = actual_by_name[expected_column.name]
            actual_type = actual_column["type"]
            expected_affinity = expected_column.type._type_affinity
            if expected_affinity is None or not isinstance(actual_type, expected_affinity):
                raise RuntimeError(
                    f"database column {table.name}.{expected_column.name} has incompatible "
                    f"type {actual_type!s}; expected {expected_column.type!s}"
                )
            expected_length = getattr(expected_column.type, "length", None)
            actual_length = getattr(actual_type, "length", None)
            if expected_length != actual_length:
                raise RuntimeError(
                    f"database column {table.name}.{expected_column.name} has incompatible "
                    f"length {actual_length!r}; expected {expected_length!r}"
                )
            if bool(actual_column["nullable"]) != bool(expected_column.nullable):
                raise RuntimeError(
                    f"database column {table.name}.{expected_column.name} has incompatible "
                    f"nullable={actual_column['nullable']!r}; expected "
                    f"nullable={expected_column.nullable!r}"
                )
            expected_timezone = getattr(expected_column.type, "timezone", None)
            actual_timezone = getattr(actual_type, "timezone", None)
            if (
                dialect_name == "postgresql"
                and expected_timezone is not None
                and actual_timezone != expected_timezone
            ):
                raise RuntimeError(
                    f"database column {table.name}.{expected_column.name} has incompatible "
                    f"timezone={actual_timezone!r}; expected timezone={expected_timezone!r}"
                )
            actual_default = actual_column.get("default")
            actual_identity = actual_column.get("identity")
            actual_computed = actual_column.get("computed")
            actual_autoincrement = bool(actual_column.get("autoincrement"))
            expected_generated = expected_column is table.autoincrement_column
            generation_matches = (
                actual_default is None
                and actual_identity is None
                and actual_computed is None
                and not actual_autoincrement
            )
            if dialect_name == "postgresql" and expected_generated:
                sequence_name = f"{table.name}_{expected_column.name}_seq"
                default_schema = inspector.default_schema_name
                expected_serial = (
                    f"{default_schema}.{sequence_name}" if default_schema else sequence_name
                )
                allowed_defaults = {
                    f"nextval('{sequence_name}'::regclass)",
                    f"nextval('{expected_serial}'::regclass)",
                }
                generation_matches = (
                    actual_serials[(table.name, expected_column.name)] == expected_serial
                    and actual_sequence_states[(table.name, expected_column.name)]
                    == ("integer", 1, 1, 2_147_483_647, 1, 1, False)
                    and actual_default in allowed_defaults
                    and actual_identity is None
                    and actual_computed is None
                    and actual_autoincrement
                )
            elif dialect_name == "sqlite" and expected_generated:
                generation_matches = (
                    actual_default is None and actual_identity is None and actual_computed is None
                )
            if not generation_matches:
                raise RuntimeError(
                    f"database column {table.name}.{expected_column.name} has incompatible "
                    "default, owned sequence configuration, identity, computed value, "
                    "or autoincrement behavior"
                )
        expected_primary_key = tuple(column.name for column in table.primary_key.columns)
        inspected_primary_key = inspector.get_pk_constraint(table.name)
        actual_primary_key = tuple(inspected_primary_key["constrained_columns"])
        if actual_primary_key != expected_primary_key:
            raise RuntimeError(
                f"database table {table.name!r} has incompatible primary key "
                f"{actual_primary_key!r}; expected {expected_primary_key!r}"
            )
        primary_key_name = inspected_primary_key.get("name")
        if dialect_name == "postgresql" and primary_key_name != f"{table.name}_pkey":
            raise RuntimeError(
                f"database table {table.name!r} has incompatible primary-key constraint name"
            )
        expected_uniques = {
            str(constraint.name): tuple(column.name for column in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint) and constraint.name is not None
        }
        actual_uniques: dict[str, tuple[str, ...]] = {}
        for unique_constraint in inspector.get_unique_constraints(table.name):
            name = unique_constraint.get("name")
            columns = unique_constraint.get("column_names")
            if (
                not isinstance(name, str)
                or not name
                or name in actual_uniques
                or not isinstance(columns, list)
                or not columns
                or any(not isinstance(column, str) or not column for column in columns)
            ):
                raise RuntimeError(
                    f"database table {table.name!r} has an unsupported unique constraint"
                )
            actual_uniques[name] = tuple(columns)
        if actual_uniques != expected_uniques:
            raise RuntimeError(
                f"database table {table.name!r} has incompatible unique constraints; "
                f"found {actual_uniques!r}, expected {expected_uniques!r}"
            )
        expected_indexes = {
            str(index.name): _expected_index_contract(table.name, index, dialect_name)
            for index in table.indexes
            if index.name is not None
        }
        actual_indexes: dict[
            str,
            tuple[tuple[str, ...], bool, tuple[object, ...] | None],
        ] = {}
        for index in inspector.get_indexes(table.name):
            duplicate = index.get("duplicates_constraint")
            if duplicate is not None:
                if not isinstance(duplicate, str) or duplicate not in actual_uniques:
                    raise RuntimeError(
                        f"database table {table.name!r} has an unsupported constraint index"
                    )
                continue
            name, contract = _inspected_index_contract(table.name, index, dialect_name)
            if name in actual_indexes:
                raise RuntimeError(f"database table {table.name!r} has duplicate index names")
            actual_indexes[name] = contract
        if actual_indexes != expected_indexes:
            raise RuntimeError(
                f"database table {table.name!r} has incompatible indexes; "
                f"found {actual_indexes!r}, expected {expected_indexes!r}"
            )
        if dialect_name == "sqlite":
            with _schema_connection(bind) as connection:
                rows = connection.exec_driver_sql(f'PRAGMA index_list("{table.name}")').all()
            explicit_index_names = {str(row[1]) for row in rows if len(row) >= 4 and row[3] == "c"}
            if explicit_index_names != set(expected_indexes):
                raise RuntimeError(
                    f"database table {table.name!r} has incompatible explicit indexes"
                )
        expected_checks = {
            str(constraint.name): _normalize_schema_expression(constraint.sqltext)
            for constraint in table.constraints
            if isinstance(constraint, CheckConstraint) and constraint.name is not None
        }
        actual_checks: dict[str, tuple[object, ...] | None] = {}
        for check_constraint in inspector.get_check_constraints(table.name):
            name = check_constraint.get("name")
            if (
                not isinstance(name, str)
                or not name
                or name in actual_checks
                or check_constraint.get("sqltext") is None
            ):
                raise RuntimeError(
                    f"database table {table.name!r} has an unsupported check constraint"
                )
            actual_checks[name] = _normalize_schema_expression(check_constraint["sqltext"])
        if actual_checks != expected_checks:
            raise RuntimeError(
                f"database table {table.name!r} has incompatible check constraints; "
                f"found {actual_checks!r}, expected {expected_checks!r}"
            )
        if dialect_name == "postgresql":
            with _schema_connection(bind) as connection:
                constraint_rows = connection.execute(
                    text(
                        """
                        SELECT
                            conname,
                            contype::text,
                            condeferrable,
                            condeferred,
                            convalidated,
                            connoinherit
                        FROM pg_constraint
                        WHERE conrelid = CAST(:table_name AS regclass)
                          AND contype IN ('p', 'u', 'c')
                        """
                    ),
                    {"table_name": table.name},
                ).all()
                index_rows = connection.execute(
                    text(
                        """
                        SELECT
                            index_class.relname,
                            index_state.indisunique,
                            index_state.indisprimary,
                            index_state.indimmediate,
                            index_state.indisvalid,
                            index_state.indisready,
                            index_state.indislive,
                            index_state.indisexclusion,
                            access_method.amname,
                            pg_get_expr(index_state.indpred, index_state.indrelid)
                        FROM pg_index AS index_state
                        JOIN pg_class AS table_class
                          ON table_class.oid = index_state.indrelid
                        JOIN pg_class AS index_class
                          ON index_class.oid = index_state.indexrelid
                        JOIN pg_am AS access_method
                          ON access_method.oid = index_class.relam
                        WHERE table_class.oid = CAST(:table_name AS regclass)
                        """
                    ),
                    {"table_name": table.name},
                ).all()
            expected_constraint_states = dict.fromkeys(
                expected_uniques,
                # PostgreSQL reports connoinherit=true for UNIQUE constraints.
                # The flag is meaningful only for CHECK constraints, so require
                # the canonical catalog value instead of treating it as unsafe.
                ("u", False, False, True, True),
            )
            expected_constraint_states.update(
                dict.fromkeys(
                    expected_checks,
                    ("c", False, False, True, False),
                )
            )
            assert isinstance(primary_key_name, str)
            expected_constraint_states[primary_key_name] = (
                "p",
                False,
                False,
                True,
                True,
            )
            actual_constraint_states = {
                str(row[0]): (
                    str(row[1]),
                    bool(row[2]),
                    bool(row[3]),
                    bool(row[4]),
                    bool(row[5]),
                )
                for row in constraint_rows
            }
            if actual_constraint_states != expected_constraint_states:
                raise RuntimeError(
                    f"database table {table.name!r} has unsafe PostgreSQL constraint state"
                )
            reflected_index_states = {
                str(row[0]): (
                    bool(row[1]),
                    bool(row[2]),
                    bool(row[3]),
                    bool(row[4]),
                    bool(row[5]),
                    bool(row[6]),
                    bool(row[7]),
                    str(row[8]),
                    _normalize_schema_expression(row[9]),
                )
                for row in index_rows
            }
            expected_index_states = {
                name: (
                    unique,
                    False,
                    True,
                    True,
                    True,
                    True,
                    False,
                    "btree",
                    predicate,
                )
                for name, (_columns, unique, predicate) in expected_indexes.items()
            }
            expected_index_states.update(
                dict.fromkeys(
                    expected_uniques,
                    (
                        True,
                        False,
                        True,
                        True,
                        True,
                        True,
                        False,
                        "btree",
                        None,
                    ),
                )
            )
            expected_index_states[primary_key_name] = (
                True,
                True,
                True,
                True,
                True,
                True,
                False,
                "btree",
                None,
            )
            actual_index_states = {
                name: reflected_index_states.get(name) for name in expected_index_states
            }
            if actual_index_states != expected_index_states:
                raise RuntimeError(
                    f"database table {table.name!r} has unsafe PostgreSQL index state"
                )
        if inspector.get_foreign_keys(table.name):
            raise RuntimeError(
                f"database table {table.name!r} has unsupported foreign-key constraints"
            )
    with _schema_connection(bind) as connection:
        marker = metadata.tables["schema_metadata"]
        actual_version = connection.scalar(
            select(marker.c.version).where(marker.c.singleton_id == 1)
        )
    if actual_version != version:
        raise RuntimeError(
            f"database schema version {actual_version!r} is incompatible with required version "
            f"{version}"
        )
