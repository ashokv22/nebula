import logging

from fastapi import APIRouter, File, Request, UploadFile
from fastapi.responses import JSONResponse

from core.logging_config import log_sanitized_exception
from cargo.schemas import MAX_CONTENT_LENGTH, FileProblem
from cargo.service import process_upload
from cargo.validators import validate_manufacturer_rows, validate_rows

router = APIRouter()
logger = logging.getLogger(__name__)


async def _parse_upload(request, upload, validator):
    try:
        content_length = request.headers.get('content-length')
        if content_length and int(content_length) > MAX_CONTENT_LENGTH:
            raise FileProblem('Upload exceeds 2 MB', 413)
        return await process_upload(upload, validator)
    except FileProblem as exc:
        return JSONResponse({'error': exc.message}, status_code=exc.status)
    except Exception as exc:
        log_sanitized_exception(logger, "Unexpected request failure", exc)
        return JSONResponse({'error': 'Unable to process file'}, status_code=500)


@router.post('/api/parse/dealers')
async def parse_dealers(request: Request, file: UploadFile | None = File(default=None)):
    return await _parse_upload(request, file, validate_rows)


@router.post('/api/parse/manufacturers')
async def parse_manufacturers(request: Request, file: UploadFile | None = File(default=None)):
    return await _parse_upload(request, file, validate_manufacturer_rows)