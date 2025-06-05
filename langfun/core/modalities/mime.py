# Zmodyfikowana wersja langfun/core/modalities/mime.py
# Zastępuje libmagic prostym wykrywaniem sygnatury

import base64
import functools
import mimetypes
from typing import Annotated, Any, Iterable, Type, Union
import langfun.core as lf
import pyglove as pg
import requests


# === ZASTĄPIENIE LIBMAGIC ===

def detect_mime_from_signature(data: bytes) -> str:
    """Nienatywne wykrywanie MIME type na podstawie sygnatury pliku."""
    
    if not data:
        return 'application/octet-stream'
    
    # Rozszerzona lista sygnatur
    signatures = [
        # Obrazy
        (b'\xFF\xD8\xFF', 'image/jpeg'),
        (b'\x89PNG\r\n\x1a\n', 'image/png'),
        (b'GIF87a', 'image/gif'),
        (b'GIF89a', 'image/gif'),
        (b'BM', 'image/bmp'),
        (b'\x00\x00\x01\x00', 'image/vnd.microsoft.icon'),  # ICO
        
        # WebP, AVI, WAV (wszystkie RIFF - wymagają dalszej analizy)
        (b'RIFF', None),  # Wymaga sprawdzenia typu
        
        # PDF
        (b'%PDF-', 'application/pdf'),
        
        # Video i Audio (MP4/M4A/M4V)
        (b'\x00\x00\x00\x20ftypisom', 'video/mp4'),
        (b'\x00\x00\x00\x20ftypmp41', 'video/mp4'),
        (b'\x00\x00\x00\x18ftypmp4', 'video/mp4'),
        (b'\x00\x00\x00\x1cftyp', None),  # Wymaga sprawdzenia typu ftyp
        (b'ftypmp4', 'video/mp4'),
        (b'ftypM4A', 'audio/mp4'),  # M4A Audio
        (b'ftypm4a', 'audio/mp4'),  # M4A Audio (lowercase)
        (b'ftypM4V', 'video/x-m4v'),  # M4V Video
        (b'ftypm4v', 'video/x-m4v'),  # M4V Video (lowercase)
        (b'ftypf4v', 'video/mp4'),  # Flash Video MP4
        (b'ftypavc1', 'video/mp4'),  # AVC
        (b'ftypqt', 'video/quicktime'),  # QuickTime
        
        # Audio - rozszerzona obsługa
        (b'ID3', 'audio/mpeg'),  # MP3 z tagami ID3
        (b'\xFF\xFB', 'audio/mpeg'),  # MP3 - MPEG-1 Layer 3
        (b'\xFF\xF3', 'audio/mpeg'),  # MP3 - MPEG-1 Layer 3
        (b'\xFF\xF2', 'audio/mpeg'),  # MP3 - MPEG-1 Layer 3
        (b'\xFF\xFA', 'audio/mpeg'),  # MP3 - MPEG-1 Layer 3
        (b'\xFF\xE2', 'audio/mpeg'),  # MP3 - MPEG-2/2.5 Layer 3
        (b'\xFF\xE3', 'audio/mpeg'),  # MP3 - MPEG-2/2.5 Layer 3
        (b'OggS', None),  # Ogg container - wymaga dalszej analizy
        (b'fLaC', 'audio/flac'),  # FLAC
        (b'FORM', None),  # AIFF/AIFC - wymaga sprawdzenia typu
        (b'wvpk', 'audio/x-wavpack'),  # WavPack
        (b'MAC ', 'audio/x-monkey'),  # Monkey's Audio
        (b'MPCK', 'audio/x-musepack'),  # Musepack
        (b'TTA1', 'audio/x-tta'),  # True Audio
        (b'#!AMR', 'audio/amr'),  # AMR-NB
        (b'#!AMR-WB', 'audio/amr-wb'),  # AMR-WB
        (b'\x30\x26\xB2\x75\x8E\x66\xCF\x11', 'audio/x-ms-wma'),  # WMA/ASF
        (b'ADIF', 'audio/aac'),  # AAC ADIF
        (b'\xFF\xF1', 'audio/aac'),  # AAC ADTS
        (b'\xFF\xF9', 'audio/aac'),  # AAC ADTS
        
        # Archives
        (b'PK\x03\x04', None),  # ZIP - wymaga dalszej analizy
        (b'Rar!\x1a\x07\x00', 'application/x-rar-compressed'),
        (b'\x1f\x8b\x08', 'application/gzip'),
        (b'7z\xbc\xaf\x27\x1c', 'application/x-7z-compressed'),
        
        # Documents
        (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'application/msword'),  # Old Office
        
        # Text formats
        (b'<?xml', 'application/xml'),
        (b'<xml', 'application/xml'),
        (b'<html', 'text/html'),
        (b'<HTML', 'text/html'),
        (b'<!DOCTYPE html', 'text/html'),
        (b'<!DOCTYPE HTML', 'text/html'),
        
        # JSON (heuristic)
        (b'{\n', 'application/json'),
        (b'{"', 'application/json'),
        (b'[\n', 'application/json'),
        (b'[{', 'application/json'),
    ]
    
    # Sprawdź każdą sygnaturę
    for signature, mime_type in signatures:
        if data.startswith(signature):
            if mime_type is None:
                # Przypadki specjalne wymagające dalszej analizy
                if signature == b'RIFF':
                    return _check_riff_format(data)
                elif signature == b'PK\x03\x04':
                    return _check_zip_format(data)
                elif signature == b'OggS':
                    return _check_ogg_format(data)
                elif signature == b'FORM':
                    return _check_form_format(data)
                elif signature == b'\x00\x00\x00\x1cftyp':
                    return _check_ftyp_format(data)
            else:
                return mime_type
    
    # Sprawdź czy to prawdopodobnie tekst
    if _is_likely_text(data):
        return 'text/plain'
    
    return 'application/octet-stream'

def _check_ogg_format(data: bytes) -> str:
    """Sprawdza typ zawartości kontenera Ogg (Vorbis, Opus, Theora, etc)."""
    if len(data) < 35:
        return 'application/ogg'
    
    # Szukaj nagłówka kodeka w pierwszych stronach Ogg
    search_data = data[:512] if len(data) > 512 else data
    
    if b'OpusHead' in search_data:
        return 'audio/opus'
    elif b'vorbis' in search_data:
        return 'audio/ogg'  # Ogg Vorbis
    elif b'theora' in search_data:
        return 'video/ogg'  # Ogg Theora
    elif b'FLAC' in search_data:
        return 'audio/flac'  # Ogg FLAC
    elif b'speex' in search_data:
        return 'audio/speex'  # Speex
    
    return 'application/ogg'

def _check_form_format(data: bytes) -> str:
    """Sprawdza typ FORM (AIFF, AIFC, etc)."""
    if len(data) < 12:
        return 'application/octet-stream'
    
    form_type = data[8:12]
    if form_type == b'AIFF':
        return 'audio/aiff'
    elif form_type == b'AIFC':
        return 'audio/aiff'  # Compressed AIFF
    
    return 'application/octet-stream'

def _check_ftyp_format(data: bytes) -> str:
    """Sprawdza typ ftyp dla kontenerów MP4/M4A/M4V."""
    if len(data) < 16:
        return 'application/octet-stream'
    
    # Szukaj ftyp w pierwszych 20 bajtach
    ftyp_start = data.find(b'ftyp')
    if ftyp_start == -1 or ftyp_start + 8 > len(data):
        return 'application/octet-stream'
    
    # Typ major brand (4 bajty po 'ftyp')
    major_brand = data[ftyp_start + 4:ftyp_start + 8]
    
    audio_brands = {b'M4A ', b'm4a ', b'M4B ', b'm4b '}  # M4A, M4B (audiobook)
    video_brands = {b'mp41', b'mp42', b'isom', b'avc1', b'M4V ', b'm4v '}
    
    if major_brand in audio_brands:
        return 'audio/mp4'
    elif major_brand in video_brands:
        return 'video/mp4'
    elif major_brand == b'qt  ':
        return 'video/quicktime'
    
    return 'application/octet-stream'
    """Rozróżnia między formatami RIFF (WebP, AVI, WAV)."""
    if len(data) < 12:
        return 'application/octet-stream'
    
    format_type = data[8:12]
    if format_type == b'WEBP':
        return 'image/webp'
    elif format_type == b'AVI ':
        return 'video/x-msvideo'
    elif format_type == b'WAVE':
        return 'audio/wav'
    
    return 'application/octet-stream'

def _check_zip_format(data: bytes) -> str:
    """Sprawdza czy ZIP to dokument Office czy zwykły archive."""
    # Szukaj śladów Office w pierwszych KB
    search_data = data[:2048] if len(data) > 2048 else data
    
    office_markers = {
        b'word/': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        b'xl/': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 
        b'ppt/': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        b'content.xml': 'application/vnd.oasis.opendocument.text',  # LibreOffice
    }
    
    for marker, mime_type in office_markers.items():
        if marker in search_data:
            return mime_type
    
    return 'application/zip'

def _is_likely_text(data: bytes, sample_size: int = 1024) -> bool:
    """Heurystyka sprawdzająca czy dane to prawdopodobnie tekst."""
    if not data:
        return False
    
    # Sprawdź tylko próbkę dla wydajności
    sample = data[:sample_size]
    
    try:
        # Spróbuj dekodować jako UTF-8
        text = sample.decode('utf-8')
        
        # Policz znaki drukowalne i białe znaki
        printable_count = sum(1 for c in text if c.isprintable() or c.isspace())
        
        # Jeśli >95% to znaki drukowalne/białe, prawdopodobnie tekst
        return printable_count / len(text) > 0.95
        
    except UnicodeDecodeError:
        # Spróbuj inne kodowania
        for encoding in ['latin1', 'cp1252', 'ascii']:
            try:
                text = sample.decode(encoding)
                printable_count = sum(1 for c in text if c.isprintable() or c.isspace())
                if printable_count / len(text) > 0.95:
                    return True
            except UnicodeDecodeError:
                continue
        
        return False

def from_buffer_fallback(data: bytes, mime: bool = False) -> str:
    """Zastępuje magic.from_buffer bez natywnych dependencies."""
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    if mime:
        return detect_mime_from_signature(data)
    else:
        # Dla trybu bez MIME zwróć opis (uproszczony)
        mime_type = detect_mime_from_signature(data)
        
        descriptions = {
            # Obrazy
            'image/jpeg': 'JPEG image data',
            'image/png': 'PNG image data',
            'image/gif': 'GIF image data',
            'image/webp': 'WebP image data',
            'image/bmp': 'BMP image data',
            'image/aiff': 'AIFF image data',
            
            # Audio
            'audio/mpeg': 'MP3 audio data',
            'audio/mp4': 'M4A/AAC audio data',
            'audio/wav': 'WAV audio data',
            'audio/aiff': 'AIFF audio data',
            'audio/flac': 'FLAC audio data',
            'audio/ogg': 'Ogg Vorbis audio data',
            'audio/opus': 'Opus audio data',
            'audio/speex': 'Speex audio data',
            'audio/x-wavpack': 'WavPack audio data',
            'audio/amr': 'AMR audio data',
            'audio/amr-wb': 'AMR-WB audio data',
            'audio/x-ms-wma': 'Windows Media Audio',
            'audio/aac': 'AAC audio data',
            'audio/x-monkey': 'Monkey\'s Audio',
            'audio/x-musepack': 'Musepack audio data',
            'audio/x-tta': 'True Audio data',
            
            # Video
            'video/mp4': 'MP4 video data',
            'video/x-m4v': 'M4V video data',
            'video/quicktime': 'QuickTime video data',
            'video/x-msvideo': 'AVI video data',
            'video/ogg': 'Ogg Theora video data',
            
            # Dokumenty
            'application/pdf': 'PDF document',
            'text/plain': 'ASCII text',
            'text/html': 'HTML document',
            'application/json': 'JSON data',
            'application/xml': 'XML document',
            
            # Archiwa
            'application/zip': 'ZIP archive',
            'application/x-rar-compressed': 'RAR archive',
            'application/gzip': 'gzip compressed data',
            
            # Ogólne
            'application/octet-stream': 'binary data'
        }
        
        return descriptions.get(mime_type, 'data')

# === INTEGRACJA ===

# Zastąpienie oryginalnego importu
try:
    import magic
    from_buffer = magic.from_buffer
    HAS_MAGIC = True
except ImportError:
    from_buffer = from_buffer_fallback
    HAS_MAGIC = False


# === RESZTA KLASY MIME BEZ ZMIAN ===

class Mime(lf.Modality):
    """Base for MIME data - wersja z fallback detection."""

    MIME_PREFIX = None

    uri: Annotated[str | None, 'The URI for locating the MIME data. '] = None
    content: Annotated[
        Union[str, bytes, None], 'The raw content of the MIME type.'
    ] = None

    @functools.cached_property
    def mime_type(self) -> str:
        """Returns the MIME type."""
        data = self.to_bytes()
        mime = from_buffer(data, mime=True)
        
        # Dodatkowa walidacja z mimetypes jeśli mamy URI
        if hasattr(self, 'uri') and self.uri and not HAS_MAGIC:
            # Fallback: sprawdź rozszerzenie jako dodatkową walidację
            guess_mime, _ = mimetypes.guess_type(self.uri)
            if guess_mime and mime == 'application/octet-stream':
                mime = guess_mime
        
        if (
            self.MIME_PREFIX
            and not mime.lower().startswith(self.MIME_PREFIX.lower())
            and mime != 'application/octet-stream'
        ):
            raise ValueError(
                f'Expected MIME type: {self.MIME_PREFIX}, Encountered: {mime}'
            )
        return mime

    # ... reszta metod bez zmian ...
    
    @functools.cached_property
    def is_text(self) -> bool:
        return self.mime_type.startswith((
            'text/',
            'application/javascript',
            'application/json',
            'application/ld+json',
            'application/plain',
            'application/rtf',
            'application/xhtml+xml',
            'application/xml',
            'application/x-javascript',
            'application/x-python-code',
            'application/x-tex',
            'application/x-typescript',
            'application/x-yaml',
        ))

    @property
    def is_binary(self) -> bool:
        return not self.is_text

    def to_text(self) -> str:
        if not self.is_text:
            raise lf.ModalityError(
                f'MIME type {self.mime_type!r} cannot be converted to text.'
            )
        return self.to_bytes().decode()

    def is_compatible(self, mime_types: str | Iterable[str]) -> bool:
        if isinstance(mime_types, str):
            mime_types = {mime_types}
        return self._is_compatible(mime_types)

    def _is_compatible(self, mime_types: Iterable[str]):
        return self.mime_type in mime_types

    def make_compatible(self, mime_types: str | Iterable[str]) -> Union['Mime', list['Mime']]:
        if isinstance(mime_types, str):
            mime_types = {mime_types}
        if not self._is_compatible(mime_types):
            raise lf.ModalityError(
                f'MIME type {self.mime_type!r} cannot be converted to supported '
                f'types: {mime_types!r}.'
            )
        return self._make_compatible(mime_types)

    def _make_compatible(self, mime_types: Iterable[str]) -> Union['Mime', list['Mime']]:
        del mime_types
        return self

    def _on_bound(self):
        super()._on_bound()
        if self.uri is None and self.content is None:
            raise ValueError('Either uri or content must be provided.')

    def to_bytes(self) -> bytes:
        if self.content is not None:
            if isinstance(self.content, str):
                return self.content.encode('utf-8')
            return self.content

        self.rebind(content=self.download(self.uri), skip_notification=True)
        return self.content

    @property
    def content_uri(self) -> str:
        base64_content = base64.b64encode(self.to_bytes()).decode()
        return f'data:{self.mime_type};base64,{base64_content}'

    @property
    def embeddable_uri(self) -> str:
        if self.uri and self.uri.lower().startswith(('http:', 'https:', 'ftp:')):
            return self.uri
        return self.content_uri

    @classmethod
    def from_uri(cls, uri: str, **kwargs) -> 'Mime':
        if uri.startswith('data:'):
            mime_type, content = cls._parse_data_uri(uri)
            return cls.class_from_mime_type(mime_type).from_bytes(content, **kwargs)

        if cls is Mime:
            content = cls.download(uri)
            mime = from_buffer(content, mime=True).lower()
            return cls.class_from_mime_type(mime)(uri=uri, content=content, **kwargs)
        return cls(uri=uri, content=None, **kwargs)

    @classmethod
    def _parse_data_uri(cls, uri: str) -> tuple[str, bytes]:
        assert uri.startswith('data:'), uri
        mime_end_pos = uri.find(';', 0)
        if mime_end_pos == -1:
            raise ValueError(f'Invalid data URI: {uri!r}.')
        mime_type = uri[5: mime_end_pos].strip().lower()
        encoding_end_pos = uri.find(',', mime_end_pos + 1)
        if encoding_end_pos == -1:
            raise ValueError(f'Invalid data URI: {uri!r}.')
        encoding = uri[mime_end_pos + 1: encoding_end_pos].strip().lower()
        if encoding != 'base64':
            raise ValueError(f'Unsupported encoding: {encoding!r}.')
        base64_content = uri[encoding_end_pos + 1:].strip().encode()
        return mime_type, base64.b64decode(base64_content)

    @classmethod
    def from_bytes(cls, content: bytes | str, **kwargs) -> 'Mime':
        if cls is Mime:
            if isinstance(content, str):
                content = content.encode('utf-8')
            mime = from_buffer(content, mime=True).lower()
            return cls.class_from_mime_type(mime)(content=content, **kwargs)
        return cls(content=content, **kwargs)

    @classmethod
    def class_from_mime_type(cls, mime_type: str) -> Type['Mime']:
        for subcls in cls.__subclasses__():
            if subcls.MIME_PREFIX is not None and mime_type.startswith(
                subcls.MIME_PREFIX):
                return subcls
        return cls

    @classmethod
    def download(cls, uri: str) -> bytes | str:
        if uri.lower().startswith(('http:', 'https:', 'ftp:')):
            return requests.get(uri, headers={'User-Agent': 'Mozilla/5.0'}).content
        else:
            content = pg.io.readfile(uri, mode='rb')
            assert content is not None
            return content

    def _html_tree_view_content(self, **kwargs) -> str:
        return self._raw_html()

    def _raw_html(self) -> str:
        if self.uri and self.uri.lower().startswith(('http:', 'https:', 'ftp:')):
            uri = self.uri
        else:
            uri = self.content_uri
        return self._mime_control_for(uri)

    def _mime_control_for(self, uri) -> str:
        return f'<embed type="{self.mime_type}" src="{uri}"/>'


@pg.use_init_args(['mime', 'content', 'uri'])
class Custom(Mime):
    """Custom MIME data."""

    mime: Annotated[str, 'The MIME type of the data. E.g. text/plain, or image/png. ']

    @property
    def mime_type(self) -> str:
        return self.mime

# === INFORMACJA O TRYBIE ===
def get_mime_detection_info():
    """Zwraca informacje o sposobie wykrywania MIME."""
    if HAS_MAGIC:
        return "Using native libmagic for MIME detection"
    else:
        return "Using fallback signature-based MIME detection (no native dependencies)"