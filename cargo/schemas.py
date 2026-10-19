import re

MAX_CONTENT_LENGTH = 2 * 1024 * 1024
MAX_ROWS = 1000
MAX_COLUMNS = 12
MAX_CELL_CHARS = 500
MAX_ZIP_FILES = 150
MAX_ZIP_UNCOMPRESSED = 20 * 1024 * 1024
MAX_ZIP_RATIO = 100

HEADERS = ['operation', 'dealerCode', 'dealerName', 'dealerType', 'state', 'manufacturer', 'status']
REQUIRED_HEADERS = set(HEADERS) - {'manufacturer'}
TEMPLATE_REQUIRED_HEADERS = {'dealerType', 'source', 'dealerName', 'dealerCode', 'state'}
HEADER_ALIASES = {header.upper(): header for header in HEADERS}
HEADER_ALIASES.update({'DEALER TYPE *': 'dealerType', 'SOURCE *': 'source',
                       'DEALER NAME *': 'dealerName', 'DEALER CODE *': 'dealerCode',
                       'STATE *': 'state', 'MANUFACTURER': 'manufacturer'})
CODE_PATTERN = re.compile(r'^[A-Z]{5}[0-9]{5}$')
CLASSIFIERS = {'NORMAL': 'dsfa_master', 'PREMIUM': 'premium_dsfa_master', 'DEALER': 'dsfa_master', 'PREMIUM DEALER': 'premium_dsfa_master', 'DSFA_MASTER': 'dsfa_master', 'PREMIUM_DSFA_MASTER': 'premium_dsfa_master'}
OPERATIONS = {'CREATE', 'UPDATE', 'UPSERT'}
DECIMAL_PATTERN = re.compile(r'^[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)$')

MANUFACTURER_HEADERS = ['operation', 'state', 'manufacturer', 'model', 'modelVariant', 'hp', 'tractorCost', 'modelGrade']
MANUFACTURER_REQUIRED_HEADERS = set(MANUFACTURER_HEADERS) - {'operation'}
MANUFACTURER_HEADER_ALIASES = {header.upper(): header for header in MANUFACTURER_HEADERS}
MANUFACTURER_HEADER_ALIASES.update({
    'MODEL VARIANT': 'modelVariant', 'TRACTOR COST': 'tractorCost', 'MODEL GRADE': 'modelGrade'
})


class FileProblem(Exception):
    def __init__(self, message, status=400):
        self.message = message
        self.status = status