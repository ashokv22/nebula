from cargo.parser import read_uploaded_rows
from cargo.schemas import MAX_CONTENT_LENGTH


async def process_upload(upload, validator):
    if upload is None:
        rows = read_uploaded_rows(None, None)
    else:
        blob = await upload.read(MAX_CONTENT_LENGTH + 1)
        rows = read_uploaded_rows(upload.filename, blob)
    results = validator(rows)
    return {
        'total': len(results),
        'ready': sum(row['status'] == 'READY_FOR_LOOKUP' for row in results),
        'invalid': sum(row['status'] == 'INVALID' for row in results),
        'rows': results,
    }