"""MQL v1: a small read-only graph language, parsed without SQL/eval/regex execution."""

import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from functools import cmp_to_key

from app.relationships import RELATIONS, bounded_graph, load_snapshot

FIELDS = {
    "Resource": "id entity resource_id connection_id uid name label kind region seen data exposure exposure_evidence limitations finding_count",
    "Finding": "id entity finding_id connection_id resource_uid name label severity score status last_seen check_id resource_current evidence remediation",
    "Connection": "id entity connection_id name label kind validated",
    "Internet": "id entity name label kind exposure",
    "Edge": "id source target type relation confidence evidence limitations",
    "Path": "length",
}
FIELDS = {kind: set(fields.split()) for kind, fields in FIELDS.items()}
MISSING, UNBOUND = object(), object()
TOKEN = re.compile(
    r'\s+|"(?:[^"\\\x00-\x1f]|\\.)*"|-?\d+(?:\.(?!\.)\d+)?|[A-Za-z_][A-Za-z_0-9]*|->|<-|>=|<=|!=|\.\.|[()\[\]:.,=*|<>+\-]'
)


class QueryError(ValueError):
    pass


class BudgetExceeded(Exception):
    pass


@dataclass
class Budget:
    started: float
    operations: int = 0

    def tick(self):
        self.operations += 1
        if self.operations > 25000 or time.monotonic() - self.started > 2:
            raise BudgetExceeded


@dataclass
class Node:
    alias: str
    kind: str


@dataclass
class Link:
    alias: str | None
    types: tuple
    direction: str
    minimum: int
    maximum: int


class Parser:
    def __init__(self, expression):
        if not expression.strip() or len(expression) > 8192:
            raise QueryError("Use a query between 1 and 8,192 characters.")
        self.tokens, self.positions = [], []
        offset = 0
        while offset < len(expression):
            match = TOKEN.match(expression, offset)
            if not match:
                raise QueryError(f"Unexpected character at column {offset + 1}.")
            value = match.group()
            if not value.isspace():
                self.tokens.append(value)
                self.positions.append(offset + 1)
            offset = match.end()
            if len(self.tokens) > 512:
                raise QueryError("Query exceeds the 512-token budget.")
        self.tokens.append("")
        self.positions.append(len(expression) + 1)
        self.index, self.aliases, self.depth = 0, {}, 0

    def peek(self):
        return self.tokens[self.index]

    def accept(self, value):
        if self.peek().upper() == value:
            self.index += 1
            return True
        return False

    def need(self, value):
        if not self.accept(value):
            raise QueryError(f"Expected {value} at column {self.positions[self.index]}.")

    def name(self):
        value = self.peek()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,39}", value):
            raise QueryError(f"Expected an identifier at column {self.positions[self.index]}.")
        self.index += 1
        return value

    def bind(self, name, kind):
        if name in self.aliases and self.aliases[name] != kind:
            raise QueryError("An alias cannot have multiple entity types.")
        self.aliases[name] = kind
        if len(self.aliases) > 16:
            raise QueryError("Use at most 16 aliases.")

    def node(self):
        self.need("(")
        alias = self.name()
        if self.accept(":"):
            requested = self.name().lower()
            kind = next((k for k in FIELDS if k.lower() == requested and k not in ("Edge", "Path")), None)
            if not kind:
                raise QueryError("Entity type must be Resource, Finding, Connection or Internet.")
            self.bind(alias, kind)
        elif alias not in self.aliases or self.aliases[alias] in ("Edge", "Path"):
            raise QueryError("Declare the entity type on the first occurrence of each node alias.")
        self.need(")")
        return Node(alias, self.aliases[alias])

    def integer(self):
        value = self.peek()
        if not re.fullmatch(r"\d{1,5}", value):
            raise QueryError("Expected a bounded positive integer.")
        self.index += 1
        return int(value)

    def link(self):
        incoming = self.accept("<-")
        if not incoming:
            self.need("-")
        alias, types, minimum, maximum = None, [], 1, 1
        if self.accept("["):
            if self.peek() not in (":", "*", "]"):
                alias = self.name()
                if alias in self.aliases:
                    raise QueryError("Relationship aliases must be unique.")
                self.bind(alias, "Edge")
            if self.accept(":"):
                while True:
                    kind = self.name().upper()
                    if kind not in RELATIONS:
                        raise QueryError("Unknown relationship type; consult the query schema.")
                    types.append(kind)
                    if not self.accept("|"):
                        break
            if self.accept("*"):
                minimum = self.integer()
                self.need("..")
                maximum = self.integer()
                if not 1 <= minimum <= maximum <= 4 or alias:
                    raise QueryError(
                        "Variable paths require 1–4 hops and no relationship alias; bind the path instead."
                    )
            self.need("]")
        if incoming:
            self.need("-")
            direction = "in"
        else:
            direction = "out" if self.accept("->") else "both"
            if direction == "both":
                self.need("-")
        return Link(alias, tuple(types), direction, minimum, maximum)

    def field(self):
        alias = self.name()
        if alias not in self.aliases:
            raise QueryError("Unknown alias in field expression.")
        keys = []
        while self.peek() in (".", "["):
            if self.accept("."):
                keys.append(self.name())
            else:
                self.need("[")
                if self.peek().startswith('"'):
                    keys.append(self.literal())
                else:
                    keys.append(self.integer())
                self.need("]")
            if len(keys) > 8:
                raise QueryError("Property paths are limited to eight components.")
        if keys and keys[0] not in FIELDS[self.aliases[alias]]:
            raise QueryError("Unknown entity property; consult the query schema.")
        return ("field", alias, tuple(keys))

    def literal(self):
        value = self.peek()
        try:
            parsed = json.loads(value.lower() if value.upper() in ("TRUE", "FALSE", "NULL") else value)
        except (ValueError, TypeError):
            raise QueryError("Use a JSON string, number, true, false or null literal.") from None
        if isinstance(parsed, (dict, list)) or isinstance(parsed, str) and len(parsed) > 2048:
            raise QueryError("Literal exceeds the scalar/string budget.")
        self.index += 1
        return parsed

    def operand(self):
        if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", self.peek()) and self.peek().upper() not in (
            "TRUE",
            "FALSE",
            "NULL",
        ):
            return self.field()
        return ("literal", self.literal())

    def atom(self):
        self.depth += 1
        if self.depth > 12:
            raise QueryError("Boolean nesting is limited to 12 levels.")
        try:
            if self.accept("NOT"):
                return ("NOT", self.atom())
            if self.accept("("):
                result = self.boolean()
                self.need(")")
                return result
            left = self.field()
            if not left[2]:
                raise QueryError("Filter an entity property, not the entire entity.")
            if self.accept("IS"):
                negate = self.accept("NOT")
                self.need("NULL")
                return ("IS NOT NULL" if negate else "IS NULL", left)
            negate = self.accept("NOT")
            if self.accept("IN"):
                self.need("[")
                values = []
                if self.peek() != "]":
                    while True:
                        values.append(self.literal())
                        if len(values) > 50:
                            raise QueryError("IN lists are limited to 50 values.")
                        if not self.accept(","):
                            break
                self.need("]")
                return ("NOT IN" if negate else "IN", left, ("literal", values))
            if negate:
                raise QueryError("NOT after a property must be followed by IN.")
            operation = self.peek().upper()
            if operation in ("STARTS", "ENDS"):
                self.index += 1
                self.need("WITH")
                operation += " WITH"
            elif operation in ("=", "!=", ">", "<", ">=", "<=", "CONTAINS", "ICONTAINS"):
                self.index += 1
            else:
                raise QueryError("Expected a comparison, IN, IS NULL or text operator.")
            right = self.operand()
            if right == ("literal", None):
                raise QueryError("Use IS NULL or IS NOT NULL for unavailable/null properties.")
            return (operation, left, right)
        finally:
            self.depth -= 1

    def boolean(self, level=0):
        if level == 2:
            return self.atom()
        result = self.boolean(level + 1)
        operation = "OR" if level == 0 else "AND"
        while self.accept(operation):
            result = (operation, result, self.boolean(level + 1))
        return result

    def parse(self):
        self.need("MATCH")
        patterns, seen = [], set()
        while True:
            path_alias = None
            if self.peek() != "(":
                path_alias = self.name()
                if path_alias in self.aliases:
                    raise QueryError("Path aliases must be unique.")
                self.bind(path_alias, "Path")
                self.need("=")
            nodes, links = [self.node()], []
            while self.peek() in ("-", "<-"):
                links.append(self.link())
                nodes.append(self.node())
                if sum(link.maximum for link in links) > 4:
                    raise QueryError("Each pattern is limited to four total relationship hops.")
            names = {n.alias for n in nodes}
            if len(names) != len(nodes):
                raise QueryError(
                    "Use simple paths; reuse a node alias across joined patterns instead of inside a cycle."
                )
            if patterns and not names & seen:
                raise QueryError("Additional MATCH patterns must share a node alias; Cartesian products are disabled.")
            seen |= names
            patterns.append((path_alias, nodes, links))
            if len(patterns) > 3:
                raise QueryError("Use at most three joined patterns.")
            if not self.accept(","):
                break
        where = self.boolean() if self.accept("WHERE") else None
        self.need("RETURN")
        distinct = self.accept("DISTINCT")
        columns = []
        while True:
            if self.accept("COUNT"):
                self.need("(")
                unique = self.accept("DISTINCT")
                value = None if self.accept("*") else self.field()
                if unique and value is None:
                    raise QueryError("COUNT DISTINCT requires an alias or property.")
                self.need(")")
                item = ("count", value, unique)
                label = "count"
            else:
                item = self.field()
                label = item[1] + "".join("." + str(key) for key in item[2])
            if self.accept("AS"):
                label = self.name()
            if any(name == label for name, _ in columns):
                raise QueryError("Return column names must be unique; use AS to rename them.")
            columns.append((label, item))
            if len(columns) > 12:
                raise QueryError("Return at most 12 columns.")
            if not self.accept(","):
                break
        ordering = []
        if self.accept("ORDER"):
            self.need("BY")
            while True:
                label = self.name()
                while self.accept("."):
                    label += "." + self.name()
                root = label.split(".")[0]
                if label not in [name for name, _ in columns] and root not in [name for name, _ in columns]:
                    raise QueryError("ORDER BY must name a returned column; use AS for complex properties.")
                descending = self.accept("DESC")
                if not descending:
                    self.accept("ASC")
                ordering.append((label, descending))
                if len(ordering) > 3:
                    raise QueryError("Sort by at most three columns.")
                if not self.accept(","):
                    break
        limit = self.integer() if self.accept("LIMIT") else 100
        if not 1 <= limit <= 200:
            raise QueryError("LIMIT must be between 1 and 200.")
        if self.peek():
            raise QueryError(
                f"Unexpected token at column {self.positions[self.index]}; mutations and SQL are unsupported."
            )
        return {
            "patterns": patterns,
            "where": where,
            "columns": columns,
            "order": ordering,
            "distinct": distinct,
            "limit": limit,
        }


def value(term, binding):
    if term[0] == "literal":
        return term[1]
    if term[1] not in binding:
        return UNBOUND
    result = binding[term[1]]
    for key in term[2]:
        if isinstance(result, dict):
            result = result.get(key, MISSING)
        elif isinstance(result, list) and isinstance(key, int) and 0 <= key < len(result):
            result = result[key]
        else:
            return MISSING
    return result


def unknown(item):
    return item is MISSING or item is UNBOUND or item is None


def comparable(left, right):
    return type(left) is type(right) or type(left) in (int, float) and type(right) in (int, float)


def predicate(term, binding):
    if term is None:
        return True
    op = term[0]
    if op == "NOT":
        result = predicate(term[1], binding)
        return None if result is None else not result
    if op in ("AND", "OR"):
        left, right = predicate(term[1], binding), predicate(term[2], binding)
        if op == "AND":
            return False if left is False or right is False else None if left is None or right is None else True
        return True if left is True or right is True else None if left is None or right is None else False
    left = value(term[1], binding)
    if op in ("IS NULL", "IS NOT NULL"):
        if left is UNBOUND:
            return None
        return unknown(left) if op == "IS NULL" else not unknown(left)
    right = value(term[2], binding)
    if unknown(left) or unknown(right):
        return None
    if op in ("IN", "NOT IN"):
        matched = any(comparable(left, item) and left == item for item in right if item is not None)
        result = True if matched else None if None in right else False
        return None if result is None else not result if op == "NOT IN" else result
    if op in ("CONTAINS", "ICONTAINS", "STARTS WITH", "ENDS WITH"):
        if op == "CONTAINS" and isinstance(left, list):
            return any(comparable(item, right) and item == right for item in left)
        if not isinstance(left, str) or not isinstance(right, str):
            return None
        return {
            "CONTAINS": lambda: right in left,
            "ICONTAINS": lambda: right.casefold() in left.casefold(),
            "STARTS WITH": lambda: left.startswith(right),
            "ENDS WITH": lambda: left.endswith(right),
        }[op]()
    if not comparable(left, right) or isinstance(left, (dict, list)):
        return None
    return {
        "=": lambda: left == right,
        "!=": lambda: left != right,
        ">": lambda: left > right,
        "<": lambda: left < right,
        ">=": lambda: left >= right,
        "<=": lambda: left <= right,
    }[op]()


def _walk(snapshot, start, link, adjacency, budget):
    stack = [(start, [], [start])]
    while stack:
        node, edges, visited = stack.pop()
        budget.tick()
        if len(edges) >= link.minimum:
            yield node, edges, visited
        if len(edges) == link.maximum:
            continue
        for target, edge, direction in adjacency[node]:
            budget.tick()
            if (link.direction == "both" or link.direction == direction) and (
                not link.types or edge["type"] in link.types
            ):
                if target not in visited:
                    stack.append((target, [*edges, edge], [*visited, target]))


def matches(snapshot, plan, budget):
    adjacency = defaultdict(list)
    for edge in snapshot.edges:
        adjacency[edge["source"]].append((edge["target"], edge, "out"))
        adjacency[edge["target"]].append((edge["source"], edge, "in"))
    by_kind = defaultdict(list)
    for node in snapshot.nodes.values():
        by_kind[node["entity"]].append(node)

    def pattern(index, binding, all_edges, all_nodes):
        if index == len(plan["patterns"]):
            if predicate(plan["where"], binding) is True:
                yield binding, all_edges, all_nodes
            return
        path_alias, nodes, links = plan["patterns"][index]

        def step(position, current, current_edges, current_nodes):
            budget.tick()
            if predicate(plan["where"], current) is False:
                return
            if position == len(links):
                if path_alias:
                    current = {
                        **current,
                        path_alias: {
                            "length": len(current_edges),
                            "nodes": [snapshot.summary(key) for key in current_nodes],
                            "edges": current_edges,
                        },
                    }
                yield from pattern(index + 1, current, [*all_edges, *current_edges], all_nodes | set(current_nodes))
                return
            link, destination = links[position], nodes[position + 1]
            for target, edges, visited in _walk(
                snapshot, current[nodes[position].alias]["id"], link, adjacency, budget
            ):
                candidate = snapshot.nodes[target]
                if candidate["entity"] != destination.kind:
                    continue
                if destination.alias in current and current[destination.alias]["id"] != target:
                    continue
                if set(visited[1:]) & set(current_nodes):
                    continue
                updated = {**current, destination.alias: candidate}
                if link.alias:
                    updated[link.alias] = edges[0]
                yield from step(position + 1, updated, [*current_edges, *edges], [*current_nodes, *visited[1:]])

        first = nodes[0]
        candidates = [binding[first.alias]] if first.alias in binding else by_kind[first.kind]
        for node in candidates:
            budget.tick()
            yield from step(0, {**binding, first.alias: node}, [], [node["id"]])

    yield from pattern(0, {}, [], set())


def projected(term, binding, snapshot):
    result = value(term, binding)
    if unknown(result):
        return None
    if term[0] == "field" and not term[2] and isinstance(result, dict) and result.get("entity"):
        return snapshot.summary(result["id"])
    return result


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def execute(db, workspace_id, expression):
    plan = Parser(expression).parse()
    budget = Budget(time.monotonic())
    snapshot = load_snapshot(db, workspace_id)
    aggregate = any(term[0] == "count" for _, term in plan["columns"])
    rows, groups, unique_rows = [], {}, set()
    observed, intermediate_size = 0, 0
    try:
        for binding, edges, node_ids in matches(snapshot, plan, budget):
            budget.tick()
            if observed == 5000:
                snapshot.warnings.add("intermediate_row_limit")
                break
            observed += 1
            values = {name: projected(term, binding, snapshot) for name, term in plan["columns"] if term[0] != "count"}
            key = encoded(values)
            # Bound the projected intermediate rows, group keys and distinct values.
            charge = len(key) + sum(len(k) for k in node_ids) + len(edges) * 64
            if charge > 512 * 1024 or intermediate_size + charge > 2 * 1024 * 1024:
                snapshot.warnings.add("intermediate_byte_limit")
                break
            intermediate_size += charge
            if aggregate:
                if key not in groups:
                    groups[key] = (
                        values,
                        {name: set() if term[2] else 0 for name, term in plan["columns"] if term[0] == "count"},
                    )
                _, counts = groups[key]
                for name, term in plan["columns"]:
                    if term[0] != "count":
                        continue
                    item = projected(term[1], binding, snapshot) if term[1] else 1
                    if item is not None:
                        if term[2]:
                            item = encoded(item)
                            intermediate_size += len(item)
                            if intermediate_size > 2 * 1024 * 1024:
                                raise BudgetExceeded
                            counts[name].add(item)
                        else:
                            counts[name] += 1
            elif not plan["distinct"] or key not in unique_rows:
                rows.append((values, edges, node_ids))
                unique_rows.add(key)
                if not plan["order"] and len(rows) > plan["limit"]:
                    break
    except BudgetExceeded:
        snapshot.warnings.add("execution_limit")
    if aggregate:
        if not groups and not snapshot.warnings and all(term[0] == "count" for _, term in plan["columns"]):
            groups["empty"] = ({}, {name: 0 for name, _ in plan["columns"]})
        rows = [
            (
                {**values, **{name: len(count) if isinstance(count, set) else count for name, count in counts.items()}},
                [],
                set(),
            )
            for values, counts in groups.values()
        ]

    def compare(a, b):
        def sort_value(row, name):
            if name in row:
                return row[name]
            result = row
            for key in name.split("."):
                result = result.get(key) if isinstance(result, dict) else None
            return result

        for name, descending in plan["order"]:
            left, right = sort_value(a[0], name), sort_value(b[0], name)
            if left is None or right is None:
                result = (left is None) - (right is None)
            else:
                if not comparable(left, right) or isinstance(left, (dict, list)):
                    left, right = encoded(left), encoded(right)
                result = (left > right) - (left < right)
                if descending:
                    result = -result
            if result:
                return result
        return 0

    if plan["order"]:
        rows.sort(key=cmp_to_key(compare))
    has_more = len(rows) > plan["limit"]
    selected, node_ids, graph_edges, size = [], set(), {}, 0
    for values, edges, ids in rows[: plan["limit"]]:
        charge = len(encoded(values).encode())
        if size + charge > 512 * 1024:
            snapshot.warnings.add("result_byte_limit")
            continue
        size += charge
        selected.append(values)
        node_ids |= ids
        for edge in edges:
            graph_edges[edge["id"]] = edge
    graph_result = bounded_graph(
        snapshot, node_ids, graph_edges.values(), node_limit=100, edge_limit=200, byte_limit=384 * 1024
    )

    return {
        **snapshot.metadata(),
        "language": "MQL/1",
        "columns": [name for name, _ in plan["columns"]],
        "rows": selected,
        "has_more": has_more,
        "limit": plan["limit"],
        "matched_rows_observed": observed,
        "aggregate": aggregate,
        "counts_complete": not bool(snapshot.warnings),
        "duration_ms": round((time.monotonic() - budget.started) * 1000),
        "operations": budget.operations,
        "graph": graph_result,
    }


EXAMPLES = [
    {
        "name": "Public S3 configuration",
        "query": 'MATCH (r:Resource) WHERE r.kind = "s3.bucket" AND r.exposure = "potential" RETURN r LIMIT 100',
    },
    {
        "name": "Workloads behind risky security groups",
        "query": 'MATCH (g:Resource)-[:SECURITY_GROUP_ATTACHED]->(r:Resource), (g)-[:HAS_FINDING]->(f:Finding) WHERE f.status = "open" AND f.severity IN ["high", "critical"] RETURN g, r, f ORDER BY f.score DESC LIMIT 100',
    },
    {
        "name": "Candidate paths from the Internet",
        "query": "MATCH p=(i:Internet)-[:PUBLIC_CONFIGURATION|SECURITY_GROUP_ATTACHED|USES_VOLUME*1..3]->(r:Resource) RETURN p, r LIMIT 50",
    },
    {
        "name": "Services that log to a bucket",
        "query": 'MATCH (t:Resource)-[:LOGS_TO]->(b:Resource) WHERE b.kind = "s3.bucket" RETURN t, b LIMIT 100',
    },
    {
        "name": "Production resources with high risks",
        "query": 'MATCH (r:Resource)-[:HAS_FINDING]->(f:Finding) WHERE (r.data.tags.environment IN ["production", "prod"] OR r.data.tags.env = "prod") AND f.status = "open" AND f.score >= 70 RETURN r.name AS resource, f.name AS risk, f.score AS score ORDER BY score DESC LIMIT 100',
    },
    {
        "name": "Declared code to cloud risk",
        "query": 'MATCH (repo:Resource)-[:DEPLOYS_TO]->(r:Resource)-[:HAS_FINDING]->(f:Finding) WHERE f.status = "open" RETURN repo, r, f LIMIT 100',
    },
    {
        "name": "Open findings by severity",
        "query": 'MATCH (f:Finding) WHERE f.status = "open" RETURN f.severity AS severity, COUNT(*) AS findings ORDER BY findings DESC LIMIT 20',
    },
    {
        "name": "Unknown S3 safeguards",
        "query": 'MATCH (r:Resource) WHERE r.kind = "s3.bucket" AND r.data.block_public_access IS NULL RETURN r LIMIT 100',
    },
]


def schema():
    return {
        "language": "MQL/1",
        "entities": {k: sorted(v) for k, v in FIELDS.items()},
        "relationships": RELATIONS,
        "operators": [
            "=",
            "!=",
            "<",
            "<=",
            ">",
            ">=",
            "IN",
            "NOT IN",
            "CONTAINS",
            "ICONTAINS",
            "STARTS WITH",
            "ENDS WITH",
            "IS NULL",
            "IS NOT NULL",
            "AND",
            "OR",
            "NOT",
        ],
        "examples": EXAMPLES,
        "limits": {
            "characters": 8192,
            "tokens": 512,
            "hops": 4,
            "patterns": 3,
            "result_rows": 200,
            "intermediate_rows": 5000,
            "operations": 25000,
            "execution_seconds": 2,
            "resources": 1000,
            "findings": 2000,
            "metadata_mib": 4,
            "result_graph_nodes": 100,
        },
    }
