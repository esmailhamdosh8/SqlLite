import sys
import struct
from dataclasses import dataclass
import re

# import sqlparse - available if you need it!

database_file_path = sys.argv[1]
command = sys.argv[2]

def serial_type_size(serial_type: int) -> int:
    fixed = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}
    if serial_type in fixed:
        return fixed[serial_type]
    if serial_type >= 12 and serial_type % 2 == 0:  # BLOB
        return (serial_type - 12) // 2
    if serial_type >= 13 and serial_type % 2 == 1:  # TEXT
        return (serial_type - 13) // 2
    raise ValueError(f"Unsupported serial type: {serial_type}")

def decode_value(serial_type: int, raw: bytes):
    if serial_type == 0:
        return None
    if serial_type in (1, 2, 3, 4, 5, 6):
        return int.from_bytes(raw, byteorder="big", signed=True)
    if serial_type == 7:
        return struct.unpack(">d", raw)[0]
    if serial_type == 8:
        return 0
    if serial_type == 9:
        return 1
    if serial_type % 2 == 0:
        return bytes(raw)  # BLOB
    return raw.decode("utf-8")  # TEXT

def read_varint(page, pos):
    value = 0
    for i in range(8):
        byte = page[pos + i]
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, i + 1

    value = (value << 8) | page[pos + 8]
    return value, 9

def parse_record(page, pos):
    header_start = pos
    header_size, n = read_varint(page, pos)
    pos += n
    serial_arr = []
    while pos < header_start + header_size:
        st, n = read_varint(page, pos)
        serial_arr.append(st)
        pos += n
    values = []
    for st in serial_arr:
        size = serial_type_size(st)
        values.append(decode_value(st, page[pos: pos + size]))
        pos += size
    return values

def get_row_from_page(cell_offset, page):
    pos = cell_offset
    _, n = read_varint(page, pos)
    pos += n
    record_id, n = read_varint(page, pos)
    pos += n
    return record_id, parse_record(page, pos)

def get_column_names(create_sql: str) -> list[str]:
    start = create_sql.index("(")
    end = create_sql.rindex(")")
    body = create_sql[start + 1:end]

    parts, depth, current = [], 0, []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))

    constraint_keywords = {"primary", "unique", "foreign", "check", "constraint"}
    names = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        first_word = part.split()[0]
        # Table-level constraints are not columns
        if first_word.lower() in constraint_keywords:
            continue
        # Names can be quoted as "name", `name`, [name] or 'name'
        names.append(first_word.strip('"`[]\''))
    return names

def cell_count(page, page_number):
    offset = 100 if page_number == 1 else 0
    return int.from_bytes(page[offset + 3:offset + 5], byteorder='big')

def read_page(database, page_number, page_size):
    database.seek((page_number - 1) * page_size)
    return database.read(page_size)

# read with index
def index_search(db, page_number, page_size, target):
    """Yield rowids of every index entry whose first column == target."""
    page = read_page(db, page_number, page_size)
    page_type = page[0]            # index pages are never page 1
    n_cells = int.from_bytes(page[3:5], "big")

    if page_type == 0x0A:          # index leaf
        for i in range(n_cells):
            off = int.from_bytes(page[8 + 2*i: 10 + 2*i], "big")
            _, n = read_varint(page, off)
            values = parse_record(page, off + n)
            key = values[0]
            if key is None or key < target:
                continue
            if key > target:
                break
            yield values[-1]

    elif page_type == 0x02:        # index interior
        for i in range(n_cells):
            off = int.from_bytes(page[12 + 2*i: 14 + 2*i], "big")
            child = int.from_bytes(page[off:off + 4], "big")
            _, n = read_varint(page, off + 4)
            values = parse_record(page, off + 4 + n)
            key = values[0]
            if key is None or key < target:
                continue                       # left child is all smaller
            yield from index_search(db, child, page_size, target)
            if key > target:
                return                         # nothing further can match
            yield values[-1]                   # key == target: the cell is an entry itself
        right = int.from_bytes(page[8:12], "big")
        yield from index_search(db, right, page_size, target)

    else:
        raise ValueError(f"Unexpected page type {page_type:#x}")

def table_lookup(db, page_number, page_size, rowid):
    """Return the record values for rowid, or None."""
    while True:
        page = read_page(db, page_number, page_size)
        hdr = 100 if page_number == 1 else 0
        page_type = page[hdr]
        n_cells = int.from_bytes(page[hdr + 3:hdr + 5], "big")

        if page_type == 0x05:                  # interior: find first key >= rowid
            ptr_start = hdr + 12
            lo, hi = 0, n_cells
            while lo < hi:
                mid = (lo + hi) // 2
                off = int.from_bytes(page[ptr_start + 2*mid: ptr_start + 2*mid + 2], "big")
                key, _ = read_varint(page, off + 4)
                if key >= rowid:
                    hi = mid
                else:
                    lo = mid + 1
            if lo < n_cells:
                off = int.from_bytes(page[ptr_start + 2*lo: ptr_start + 2*lo + 2], "big")
                page_number = int.from_bytes(page[off:off + 4], "big")
            else:
                page_number = int.from_bytes(page[hdr + 8:hdr + 12], "big")

        elif page_type == 0x0D:                # leaf: find exact rowid
            ptr_start = hdr + 8
            lo, hi = 0, n_cells - 1
            while lo <= hi:
                mid = (lo + hi) // 2
                off = int.from_bytes(page[ptr_start + 2*mid: ptr_start + 2*mid + 2], "big")
                _, n = read_varint(page, off)
                rid, _ = read_varint(page, off + n)
                if rid == rowid:
                    return get_row_from_page(off, page)[1]
                if rid < rowid:
                    lo = mid + 1
                else:
                    hi = mid - 1
            return None
        else:
            raise ValueError(f"Unexpected page type {page_type:#x}")

# read all
def walk_table(db, page_number, page_size):
    """Yield (page, cell_offset) for every cell in every leaf under page_number."""
    page = read_page(db, page_number, page_size)
    hdr = 100 if page_number == 1 else 0
    page_type = page[hdr]
    n_cells = int.from_bytes(page[hdr + 3:hdr + 5], "big")

    if page_type == 0x0D:  # table leaf
        ptr_start = hdr + 8
        for i in range(n_cells):
            yield page, int.from_bytes(page[ptr_start + 2*i: ptr_start + 2*i + 2], "big")

    elif page_type == 0x05:  # table interior
        ptr_start = hdr + 12
        for i in range(n_cells):
            cell_off = int.from_bytes(page[ptr_start + 2*i: ptr_start + 2*i + 2], "big")
            child = int.from_bytes(page[cell_off:cell_off + 4], "big")
            yield from walk_table(db, child, page_size)
        right_most = int.from_bytes(page[hdr + 8:hdr + 12], "big")
        yield from walk_table(db, right_most, page_size)

    else:
        raise ValueError(f"Unexpected page type {page_type:#x} on page {page_number}")

def read_table_rows(db, root_page, page_size, cols):
    rows = []
    for page, cell_off in walk_table(db, root_page, page_size):
        rowid, values = get_row_from_page(cell_off, page)
        row = dict(zip(cols, values))
        row["id"] = rowid
        rows.append(row)
    return rows

def find_index(schema, table, column):
    for r in schema:
        if r["type"] == "index" and r["tbl_name"] == table and r["sql"]:
            m = re.search(r"\(\s*[\"`\[]?(\w+)", r["sql"])
            if m and m.group(1) == column:
                return r
    return None

def dbinfo(database_file):
    database_file.seek(16)  # Skip the first 16 bytes of the header
    page_size = int.from_bytes(database_file.read(2), byteorder="big")
    page = read_page(database_file, 1, page_size)
    num_of_cells = cell_count(page, 1)
    print(f"database page size: {page_size}")
    print(f"number of tables: {num_of_cells}")

def tables(database_file):
    database_file.seek(16)  # Skip the first 16 bytes of the header
    page_size = int.from_bytes(database_file.read(2), byteorder="big")
    names = []
    cols = ['type', 'name', 'tbl_name', 'page', 'sql']
    for row in read_table_rows(database_file, 1, page_size, cols):
        names.append(row["tbl_name"])
    print(" ".join(names))

def COUNT_STAR(database_file, command):
    database_file.seek(16)  # Skip the first 16 bytes of the header
    page_size = int.from_bytes(database_file.read(2), byteorder="big")
    table_name = command.split(' ')[-1].rstrip(';')
    page_n = None
    cols = ['type', 'name', 'tbl_name', 'page', 'sql']
    for row in read_table_rows(database_file, 1, page_size, cols):
        if row["tbl_name"] == table_name:
            page_n = row["page"]
            break
    if page_n is None:
        print(f"Error No Such Table: {table_name}")
        sys.exit(1)
    table_page = read_page(database_file, page_n, page_size)
    n_cells = cell_count(table_page, page_n)
    print(n_cells)

def select(database_file, command):
    database_file.seek(16)  # Skip the first 16 bytes of the header
    page_size = int.from_bytes(database_file.read(2), byteorder="big")
    select_match = re.match(r"(?i)^SELECT\s+(.+?)\s+FROM\s+(\S+)(?:\s+WHERE\s+(.+))?$", command.strip())
    if not select_match: return False
    ans = []
    columns = [column.strip() for column in select_match.group(1).split(',')]
    table = select_match.group(2)
    where = select_match.group(3)
    if where is not None:
        key, _, val = where.partition('=')
        key, val = key.strip(), val.strip()
        if val.endswith("'"):
            val = val.strip("'")
        elif val.isdigit():
            val = int(val)
        
    schema_cols = ['type', 'name', 'tbl_name', 'page', 'sql']
    schema = read_table_rows(database_file, 1, page_size, schema_cols)
    tables = {r["name"]: r for r in schema if r["type"] == "table"}

    if table not in tables:
        print(f"Error No Such Table: {table}"); sys.exit(1)
    sql = tables[table]["sql"]
    root = tables[table]["page"]
    cols = get_column_names(sql)
    index = find_index(schema, table, key) if where is not None else None
    if index is not None:
        for rowid in index_search(database_file, index["page"], page_size, val):
            values = table_lookup(database_file, root, page_size, rowid)
            if values is None:
                continue
            row = dict(zip(cols, values))
            row["id"] = rowid                      # integer primary key is stored as NULL
            ans.append("|".join(str(row[c]) for c in columns))
    else:
        for row in read_table_rows(database_file, root, page_size, cols):
            if where is None or row[key] == val:
                ans.append("|".join(str(row[c]) for c in columns))
    print("\n".join(ans))
    return True

def main():
    with open(database_file_path, "rb") as database_file:
        print("Logs from your program will appear here!", file=sys.stderr)
        if command == ".dbinfo":
            dbinfo(database_file)
        elif command == ".tables":
            tables(database_file)
        elif command.upper().startswith("SELECT COUNT(*)"):
            COUNT_STAR(database_file, command)
        elif select(database_file, command):
            pass
        else:
            print(f"Invalid command: {command}")


if __name__ == '__main__':
    main()