from collections import Counter
from decimal import Decimal, InvalidOperation

from cargo.schemas import (
    CODE_PATTERN,
    CLASSIFIERS,
    DECIMAL_PATTERN,
    HEADER_ALIASES,
    HEADERS,
    MANUFACTURER_HEADER_ALIASES,
    MANUFACTURER_HEADERS,
    MANUFACTURER_REQUIRED_HEADERS,
    OPERATIONS,
    REQUIRED_HEADERS,
    TEMPLATE_REQUIRED_HEADERS,
    FileProblem,
)


def validate_rows(rows):
    if not rows:
        raise FileProblem('File is empty')
    headers = [HEADER_ALIASES.get(h.strip().upper(), h.strip()) for h in rows[0]]
    template_format = 'source' in headers
    required_headers = TEMPLATE_REQUIRED_HEADERS if template_format else REQUIRED_HEADERS
    if len(headers) != len(set(headers)):
        raise FileProblem('Duplicate column headers')
    if not required_headers.issubset(headers):
        raise FileProblem('Missing required headers: ' + ', '.join(sorted(required_headers - set(headers))))
    supported_headers = set(HEADERS) | {'source'}
    if any(h not in supported_headers for h in headers):
        raise FileProblem('Unsupported headers: ' + ', '.join(h for h in headers if h not in supported_headers))
    result = []
    for row_no, values in enumerate(rows[1:], start=2):
        if not any(values):
            continue
        errors = []
        if len(values) > len(headers) and any(values[len(headers):]):
            errors.append('Extra values beyond header columns')
        data = dict(zip(headers, values + [''] * max(0, len(headers) - len(values))))
        for key in required_headers:
            if not data.get(key, '').strip():
                errors.append(f'{key} is required')
        op = data.get('operation', 'CREATE' if template_format else '').upper()
        code = data.get('dealerCode', '').upper()
        kind = data.get('dealerType', '').upper()
        classifier = CLASSIFIERS.get(kind)
        if op not in OPERATIONS:
            errors.append('Operation must be CREATE, UPDATE or UPSERT')
        if not CODE_PATTERN.fullmatch(code):
            errors.append('Dealer code must contain 5 letters followed by 5 digits')
        if classifier is None:
            errors.append('Dealer type must be Normal or Premium')
        source = data.get('source', 'Dealer').strip()
        if template_format and source.upper() not in {'DEALER', 'DFA', 'DSA'}:
            errors.append('Source must be Dealer, DFA or DSA')
        if source.upper() in {'DEALER', 'DFA', 'DSA'}:
            source = {'DEALER': 'Dealer', 'DFA': 'DFA', 'DSA': 'DSA'}[source.upper()]
        status_raw = data.get('status', '').strip().upper()
        if status_raw not in ('', 'ACTIVE', 'INACTIVE', '1', '0'):
            errors.append('Status must be Active, Inactive, 1 or 0')
        status = 0 if status_raw in ('INACTIVE', '0') else 1 if status_raw in ('ACTIVE', '1') else None
        manufacturer = data.get('manufacturer', '').strip()
        if manufacturer.lower() in ('null', 'nan'):
            manufacturer = ''
        dto = {'classifier': classifier, 'code': code, 'name': data.get('dealerName') or None,
               'parentClassifier': 'source', 'parentReferenceCode': source,
               'field1': data.get('state') or None, 'field2': manufacturer,
               'status': status}
        result.append({'row': row_no, 'operation': op, 'status': 'INVALID' if errors else 'READY_FOR_LOOKUP',
                       'errors': errors, 'dealer': dto})
    counts = Counter((r['dealer']['code'] for r in result if r['dealer']['code']))
    for r in result:
        if r['dealer']['code'] and counts[r['dealer']['code']] > 1:
            r['errors'].append('Duplicate dealer code within uploaded file')
            r['status'] = 'INVALID'
    return result


def parse_decimal(value):
    value = value.strip()
    if not DECIMAL_PATTERN.fullmatch(value):
        return None
    try:
        number = Decimal(value)
    except InvalidOperation:
        return None
    return number if number.is_finite() else None


def decimal_text(value):
    text = format(value, 'f')
    if '.' in text:
        text = text.rstrip('0').rstrip('.')
    return '0' if text in ('-0', '') else text


def validate_manufacturer_rows(rows):
    if not rows:
        raise FileProblem('File is empty')
    headers = [MANUFACTURER_HEADER_ALIASES.get(h.strip().upper(), h.strip()) for h in rows[0]]
    if len(headers) != len(set(headers)):
        raise FileProblem('Duplicate column headers')
    if not MANUFACTURER_REQUIRED_HEADERS.issubset(headers):
        missing = sorted(MANUFACTURER_REQUIRED_HEADERS - set(headers))
        raise FileProblem('Missing required headers: ' + ', '.join(missing))
    if any(header not in MANUFACTURER_HEADERS for header in headers):
        raise FileProblem('Unsupported headers: ' + ', '.join(h for h in headers if h not in MANUFACTURER_HEADERS))

    results = []
    identities = {}
    for row_no, values in enumerate(rows[1:], start=2):
        if not any(values):
            continue
        errors = []
        if len(values) > len(headers) and any(values[len(headers):]):
            errors.append('Extra values beyond header columns')
        data = dict(zip(headers, values + [''] * max(0, len(headers) - len(values))))
        text_fields = ('state', 'manufacturer', 'model', 'modelVariant', 'modelGrade')
        for field in text_fields:
            data[field] = data[field].strip()
            if not data[field]:
                errors.append(f'{field} is required')
            if data[field].startswith('='):
                errors.append(f'{field} must not contain a formula')

        hp = parse_decimal(data['hp'])
        if hp is None or hp <= 0:
            errors.append('HP must be a finite, positive decimal number')
        cost = parse_decimal(data['tractorCost'])
        if cost is None or cost < 0:
            errors.append('Tractor Cost must be a finite, non-negative decimal number')

        operation = data.get('operation', '').strip().upper() or 'UPSERT'
        if operation not in OPERATIONS:
            errors.append('Operation must be CREATE, UPDATE or UPSERT')

        result = {
            'row': row_no,
            'operation': operation,
            'status': 'INVALID' if errors else 'READY_FOR_LOOKUP',
            'errors': errors,
            'manufacturer': {
                'state': data['state'],
                'manufacturer': data['manufacturer'],
                'model': data['model'],
                'modelVariant': data['modelVariant'],
                'hp': decimal_text(hp) if hp is not None else None,
                'tractorCost': decimal_text(cost) if cost is not None else None,
                'modelGrade': data['modelGrade'],
            },
        }
        results.append(result)
        if all(data[field] for field in ('state', 'manufacturer', 'model', 'modelVariant')) and hp is not None:
            identity = tuple(data[field].strip().casefold() for field in ('state', 'manufacturer', 'model', 'modelVariant')) + (hp,)
            identities.setdefault(identity, []).append(result)

    for matching_rows in identities.values():
        if len(matching_rows) > 1:
            row_numbers = ', '.join(str(row['row']) for row in matching_rows)
            message = f'Duplicate manufacturer identity with spreadsheet rows: {row_numbers}'
            for result in matching_rows:
                result['errors'].append(message)
                result['status'] = 'INVALID'
    return results