import csv
import io
import unittest
import zipfile

from fastapi.testclient import TestClient
from openpyxl import Workbook

from cargo.parser import check_xlsx_archive
from cargo.router import router as cargo_router
from cargo.schemas import FileProblem
from main import app


DEALER_HEADERS = [
    'operation', 'dealerCode', 'dealerName', 'dealerType', 'state', 'manufacturer', 'status'
]
MANUFACTURER_HEADERS = [
    'operation', 'state', 'manufacturer', 'model', 'modelVariant', 'hp',
    'tractorCost', 'modelGrade'
]


def csv_bytes(headers, rows):
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue().encode('utf-8')


def xlsx_bytes(headers, rows, sheet_count=1):
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = 'Data'
    sheet.append(headers)
    for row in rows:
        sheet.append(row)
    for index in range(1, sheet_count):
        workbook.create_sheet(f'Sheet{index + 1}')
    output = io.BytesIO()
    workbook.save(output)
    workbook.close()
    return output.getvalue()


def archive_with_entries(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml', '<Types/>')
        archive.writestr('xl/workbook.xml', '<workbook/>')
        for name, value in entries:
            archive.writestr(name, value)
    return output.getvalue()


class CargoApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def post_file(self, path, blob, filename='upload.csv'):
        return self.client.post(path, files={'file': (filename, blob)})

    def test_valid_dealer_csv_preserves_dto_and_response(self):
        blob = csv_bytes(DEALER_HEADERS, [[
            'CREATE', 'ABCDE12345', 'Example Dealer', 'Normal', 'KA', 'Maker', 'Active'
        ]])
        response = self.post_file('/api/parse/dealers', blob)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(set(body), {'total', 'ready', 'invalid', 'rows'})
        self.assertEqual((body['total'], body['ready'], body['invalid']), (1, 1, 0))
        self.assertEqual(body['rows'], [{
            'row': 2, 'operation': 'CREATE', 'status': 'READY_FOR_LOOKUP', 'errors': [],
            'dealer': {
                'classifier': 'dsfa_master', 'code': 'ABCDE12345', 'name': 'Example Dealer',
                'parentClassifier': 'source', 'parentReferenceCode': 'Dealer',
                'field1': 'KA', 'field2': 'Maker', 'status': 1,
            },
        }])

    def test_valid_dealer_xlsx(self):
        response = self.post_file(
            '/api/parse/dealers',
            xlsx_bytes(DEALER_HEADERS, [['UPSERT', 'ABCDE12345', 'Dealer', 'Premium', 'MH', '', 'Active']]),
            'dealers.xlsx',
        )
        self.assertEqual(response.status_code, 200)
        row = response.json()['rows'][0]
        self.assertEqual(row['status'], 'READY_FOR_LOOKUP')
        self.assertEqual(row['dealer']['classifier'], 'premium_dsfa_master')

    def test_valid_manufacturer_csv_preserves_decimal_precision(self):
        blob = csv_bytes(MANUFACTURER_HEADERS, [[
            '', 'KA', 'Maker', 'Model A', 'Variant 1', '1.2300', '12345678901234567890.123400', 'A'
        ]])
        response = self.post_file('/api/parse/manufacturers', blob)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual((body['total'], body['ready'], body['invalid']), (1, 1, 0))
        self.assertEqual(body['rows'][0]['operation'], 'UPSERT')
        self.assertEqual(body['rows'][0]['manufacturer']['hp'], '1.23')
        self.assertEqual(body['rows'][0]['manufacturer']['tractorCost'], '12345678901234567890.1234')

    def test_valid_manufacturer_xlsx(self):
        response = self.post_file(
            '/api/parse/manufacturers',
            xlsx_bytes(MANUFACTURER_HEADERS, [['UPDATE', 'KA', 'Maker', 'M1', 'V1', '55.5', '1000', 'A']]),
            'manufacturers.xlsx',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['rows'][0]['manufacturer']['hp'], '55.5')

    def test_dealer_headers_and_duplicate_headers_errors(self):
        response = self.post_file('/api/parse/dealers', csv_bytes(['wrong'], [['x']]))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'error': 'Missing required headers: dealerCode, dealerName, dealerType, operation, state, status'
        })
        duplicate = DEALER_HEADERS + ['dealerCode']
        response = self.post_file('/api/parse/dealers', csv_bytes(duplicate, []))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Duplicate column headers'})

    def test_manufacturer_header_errors(self):
        response = self.post_file('/api/parse/manufacturers', csv_bytes(['state', 'unknown'], []))
        self.assertEqual(response.status_code, 400)
        self.assertIn('Missing required headers:', response.json()['error'])
        duplicate = MANUFACTURER_HEADERS + ['state']
        response = self.post_file('/api/parse/manufacturers', csv_bytes(duplicate, []))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Duplicate column headers'})

    def test_invalid_dealer_code_classification_and_duplicate_codes(self):
        rows = [
            ['CREATE', 'bad-code', 'Dealer A', 'Unknown', 'KA', '', 'Active'],
            ['UPDATE', 'ABCDE12345', 'Dealer B', 'Normal', 'KA', '', 'Active'],
            ['CREATE', 'ABCDE12345', 'Dealer C', 'Normal', 'KA', '', 'Active'],
        ]
        response = self.post_file('/api/parse/dealers', csv_bytes(DEALER_HEADERS, rows))
        body = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual((body['total'], body['ready'], body['invalid']), (3, 0, 3))
        self.assertIn('Dealer code must contain 5 letters followed by 5 digits', body['rows'][0]['errors'])
        self.assertIn('Dealer type must be Normal or Premium', body['rows'][0]['errors'])
        self.assertEqual(body['rows'][1]['errors'], ['Duplicate dealer code within uploaded file'])
        self.assertEqual(body['rows'][2]['status'], 'INVALID')

    def test_manufacturer_invalid_decimals_and_duplicate_identity(self):
        rows = [
            ['', 'KA', 'Maker', 'Model', 'Variant', 'NaN', '-1', 'A'],
            ['', 'KA', 'Maker', 'Model', 'Variant', '12.50', '100.00', 'B'],
            ['', 'ka', 'MAKER', 'model', 'variant', '12.500', '200', 'C'],
        ]
        response = self.post_file('/api/parse/manufacturers', csv_bytes(MANUFACTURER_HEADERS, rows))
        body = response.json()
        self.assertEqual((body['total'], body['ready'], body['invalid']), (3, 0, 3))
        self.assertIn('HP must be a finite, positive decimal number', body['rows'][0]['errors'])
        self.assertIn('Tractor Cost must be a finite, non-negative decimal number', body['rows'][0]['errors'])
        self.assertEqual(body['rows'][1]['errors'], [
            'Duplicate manufacturer identity with spreadsheet rows: 3, 4'
        ])
        self.assertEqual(body['rows'][2]['errors'], body['rows'][1]['errors'])

    def test_missing_upload_unsupported_extension_empty_and_size_limit(self):
        response = self.client.post('/api/parse/dealers')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Multipart form field "file" is required'})

        response = self.post_file('/api/parse/dealers', b'data', 'upload.txt')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Only .xlsx and .csv are supported'})

        response = self.post_file('/api/parse/dealers', b'', 'empty.csv')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'File is empty'})

        response = self.post_file('/api/parse/dealers', b'x' * (2 * 1024 * 1024 + 1))
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json(), {'error': 'Upload exceeds 2 MB'})

        response = self.post_file('/api/parse/dealers', b'x' * (2 * 1024 * 1024))
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json(), {'error': 'Upload exceeds 2 MB'})

    def test_malformed_csv_invalid_xlsx_and_content_mismatch(self):
        response = self.post_file('/api/parse/dealers', b'a,b\n"unterminated', 'bad.csv')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Malformed CSV'})

        response = self.post_file('/api/parse/dealers', b'not a zip', 'bad.xlsx')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Invalid XLSX archive'})

        response = self.post_file('/api/parse/dealers', b'PK\x03\x04bad', 'bad.csv')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'File content does not match CSV format'})

    def test_xlsx_formula_and_multiple_sheets_are_rejected(self):
        formula_rows = [['CREATE', 'ABCDE12345', '=1+1', 'Normal', 'KA', '', '']]
        response = self.post_file(
            '/api/parse/dealers', xlsx_bytes(DEALER_HEADERS, formula_rows), 'formula.xlsx'
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Formula cells are not supported'})

        response = self.post_file(
            '/api/parse/dealers',
            xlsx_bytes(DEALER_HEADERS, [], sheet_count=2),
            'multiple.xlsx',
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Exactly one worksheet is required'})

    def test_xlsx_archive_safety_limits(self):
        many_entries = archive_with_entries([(f'xl/extra-{index}.xml', 'x') for index in range(149)])
        with self.assertRaisesRegex(FileProblem, 'Workbook contains too many archive entries'):
            check_xlsx_archive(many_entries)

        unsafe_path = archive_with_entries([('../unsafe.xml', 'x')])
        with self.assertRaisesRegex(FileProblem, 'Unsafe workbook archive path'):
            check_xlsx_archive(unsafe_path)

        binary_component = archive_with_entries([('xl/vbaProject.bin', 'x')])
        with self.assertRaisesRegex(FileProblem, 'Workbook binary components are unsupported'):
            check_xlsx_archive(binary_component)

        encrypted = bytearray(archive_with_entries([]))
        local_header = encrypted.index(b'PK\x03\x04')
        central_header = encrypted.index(b'PK\x01\x02')
        encrypted[local_header + 6:local_header + 8] = (1).to_bytes(2, 'little')
        encrypted[central_header + 8:central_header + 10] = (1).to_bytes(2, 'little')
        with self.assertRaisesRegex(FileProblem, 'Encrypted workbooks are unsupported'):
            check_xlsx_archive(bytes(encrypted))

        high_ratio = archive_with_entries([('xl/large.xml', 'a' * (1024 * 1024 + 1))])
        with self.assertRaisesRegex(FileProblem, 'Workbook contains an oversized compressed entry'):
            check_xlsx_archive(high_ratio)

        expanded = archive_with_entries([('xl/expanded.xml', 'a' * (20 * 1024 * 1024 + 1))])
        with self.assertRaisesRegex(FileProblem, 'Workbook expands beyond safe size'):
            check_xlsx_archive(expanded)

    def test_no_cargo_health_route_is_registered(self):
        paths = [route.path for route in cargo_router.routes]
        self.assertEqual(paths.count('/health'), 0)
        self.assertIn('/api/parse/dealers', paths)
        self.assertIn('/api/parse/manufacturers', paths)


if __name__ == '__main__':
    unittest.main()