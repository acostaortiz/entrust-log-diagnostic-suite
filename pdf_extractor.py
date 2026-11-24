"""
Zero-dependency Entrust PDF text & error-code extractor.

Extraction tiers (first available non-empty result wins; honest reporting on scanned/encrypted PDFs):
  1. Optional Python PDF libraries (pypdf, PyPDF2, fitz/PyMuPDF, pdfplumber) if installed.
  2. Optional system CLI (`pdftotext -layout`) if present on PATH.
  3. Always-available pure-Python stdlib PDF 1.x parser (zlib FlateDecode, ASCII85/ASCIIHex,
     PDF 1.5+ /ObjStm unpacking, /ToUnicode CMap bfchar/bfrange decoding, BT..ET text operators).
"""

import base64
from html.parser import HTMLParser
import os
import re
import shutil
import subprocess
import zlib


def is_valid_pdf_bytes(raw_bytes):
    if not raw_bytes or not isinstance(raw_bytes, (bytes, bytearray)):
        return False
    return b'%PDF-' in bytes(raw_bytes[:1024])


def _clean_page_text(raw_text):
    if not raw_text:
        return ''
    text = str(raw_text).replace('\r\n', '\n').replace('\r', '\n').replace('\x00', '')
    lines = []
    blank_run = 0
    for ln in text.split('\n'):
        cleaned = re.sub(r'[ \t\f\v]+', ' ', ln).strip()
        if not cleaned:
            blank_run += 1
            if blank_run <= 1 and lines:
                lines.append('')
        else:
            blank_run = 0
            lines.append(cleaned)
    while lines and not lines[-1]:
        lines.pop()
    return '\n'.join(lines)


def _extract_with_python_libs(file_path, max_pages=800):
    # Tier 1a: pypdf / PyPDF2
    for mod_name in ('pypdf', 'PyPDF2'):
        try:
            mod = __import__(mod_name)
            PdfReader = getattr(mod, 'PdfReader', None)
            if PdfReader is None:
                continue
            reader = PdfReader(file_path)
            is_encrypted = bool(getattr(reader, 'is_encrypted', False))
            if is_encrypted:
                try:
                    decrypt_res = reader.decrypt('')
                    if decrypt_res == 0:
                        return {
                            'ok': True,
                            'engine': mod_name,
                            'pageCount': len(reader.pages),
                            'pages': [],
                            'totalChars': 0,
                            'isScannedOrEmpty': True,
                            'isEncrypted': True,
                            'warning': 'El PDF está cifrado con contraseña; no se pudo extraer texto sin descifrado.'
                        }
                except Exception:
                    return {
                        'ok': True,
                        'engine': mod_name,
                        'pageCount': 0,
                        'pages': [],
                        'totalChars': 0,
                        'isScannedOrEmpty': True,
                        'isEncrypted': True,
                        'warning': 'El PDF está cifrado con contraseña; no se pudo extraer texto sin descifrado.'
                    }
            raw_pages = reader.pages[:max_pages]
            pages = []
            total_chars = 0
            for idx, page in enumerate(raw_pages, 1):
                txt = _clean_page_text(page.extract_text() or '')[:25000]
                if txt:
                    total_chars += len(txt)
                    pages.append({'page': idx, 'text': txt})
            return {
                'ok': True,
                'engine': mod_name,
                'pageCount': len(raw_pages),
                'pages': pages,
                'totalChars': total_chars,
                'isScannedOrEmpty': total_chars < 20,
                'isEncrypted': is_encrypted,
                'warning': 'PDF sin capa de texto seleccionable (posible PDF escaneado como imagen).' if total_chars < 20 else ''
            }
        except ImportError:
            continue
        except Exception:
            continue

    # Tier 1b: PyMuPDF (fitz)
    try:
        import fitz  # type: ignore
        doc = fitz.open(file_path)
        is_encrypted = bool(getattr(doc, 'needs_pass', False))
        if is_encrypted:
            doc.close()
            return {
                'ok': True,
                'engine': 'fitz',
                'pageCount': 0,
                'pages': [],
                'totalChars': 0,
                'isScannedOrEmpty': True,
                'isEncrypted': True,
                'warning': 'El PDF requiere contraseña para extraer su contenido.'
            }
        total_p = min(len(doc), max_pages)
        pages = []
        total_chars = 0
        for idx in range(total_p):
            txt = _clean_page_text(doc[idx].get_text('text') or '')[:25000]
            if txt:
                total_chars += len(txt)
                pages.append({'page': idx + 1, 'text': txt})
        doc.close()
        return {
            'ok': True,
            'engine': 'fitz',
            'pageCount': total_p,
            'pages': pages,
            'totalChars': total_chars,
            'isScannedOrEmpty': total_chars < 20,
            'isEncrypted': False,
            'warning': 'PDF sin capa de texto seleccionable (posible PDF escaneado como imagen).' if total_chars < 20 else ''
        }
    except ImportError:
        pass
    except Exception:
        pass

    # Tier 1c: pdfplumber
    try:
        import pdfplumber  # type: ignore
        with pdfplumber.open(file_path) as pdf:
            raw_pages = pdf.pages[:max_pages]
            pages = []
            total_chars = 0
            for idx, page in enumerate(raw_pages, 1):
                txt = _clean_page_text(page.extract_text() or '')[:25000]
                if txt:
                    total_chars += len(txt)
                    pages.append({'page': idx, 'text': txt})
            return {
                'ok': True,
                'engine': 'pdfplumber',
                'pageCount': len(raw_pages),
                'pages': pages,
                'totalChars': total_chars,
                'isScannedOrEmpty': total_chars < 20,
                'isEncrypted': False,
                'warning': 'PDF sin capa de texto seleccionable (posible PDF escaneado como imagen).' if total_chars < 20 else ''
            }
    except ImportError:
        pass
    except Exception:
        pass

    return None


def _extract_with_pdftotext(file_path, max_pages=800):
    exe = shutil.which('pdftotext')
    if not exe:
        return None
    try:
        proc = subprocess.run(
            [exe, '-layout', '-enc', 'UTF-8', '-l', str(max_pages), file_path, '-'],
            capture_output=True,
            timeout=60,
        )
        if proc.returncode != 0:
            return None
        out = proc.stdout.decode('utf-8', errors='replace')
        chunks = out.split('\x0c')
        if chunks and not chunks[-1].strip():
            chunks.pop()
        if not chunks:
            return None
        pages = []
        total_chars = 0
        for idx, chunk in enumerate(chunks[:max_pages], 1):
            txt = _clean_page_text(chunk)[:25000]
            if txt:
                total_chars += len(txt)
                pages.append({'page': idx, 'text': txt})
        if total_chars < 20:
            return None
        return {
            'ok': True,
            'engine': 'pdftotext',
            'pageCount': len(chunks[:max_pages]),
            'pages': pages,
            'totalChars': total_chars,
            'isScannedOrEmpty': False,
            'isEncrypted': False,
            'warning': ''
        }
    except Exception:
        return None


# ==============================================================================
# Tier 3: Pure-Python Stdlib PDF 1.x Parser (Zero External Dependencies)
# ==============================================================================

_OBJ_HEADER_RE = re.compile(rb'(?:^|[\r\n\s])(\d+)\s+(\d+)\s+obj\b')
_STREAM_START_RE = re.compile(rb'stream(\r\n|\n|\r)')


def _decompress_stream(dict_bytes, stream_bytes):
    if not stream_bytes:
        return b''
    d_lower = dict_bytes
    # Skip embedded binary images
    if re.search(rb'/Subtype\s*/Image\b', d_lower) or re.search(rb'/Filter\s*(?:\[[^\]]*)?/(?:DCTDecode|JPXDecode|JBIG2Decode|CCITTFaxDecode)\b', d_lower):
        return b''

    data = stream_bytes
    filters = re.findall(rb'/(FlateDecode|Fl|ASCII85Decode|A85|ASCIIHexDecode|AHx)\b', d_lower)
    if not filters:
        # Handle compressed object streams or plain text streams
        return data

    for flt in filters:
        if flt in (b'FlateDecode', b'Fl'):
            decompressed = None
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 32):
                try:
                    decompressed = zlib.decompress(data, wbits)
                    break
                except Exception:
                    continue
            if decompressed is None:
                return b''
            data = decompressed
        elif flt in (b'ASCII85Decode', b'A85'):
            try:
                body = data.strip()
                if body.endswith(b'~>'):
                    body = body[:-2]
                data = base64.a85decode(body, adobe=False)
            except Exception:
                return b''
        elif flt in (b'ASCIIHexDecode', b'AHx'):
            try:
                hex_only = re.sub(rb'[^0-9A-Fa-f]', b'', data.split(b'>', 1)[0])
                if len(hex_only) % 2 == 1:
                    hex_only += b'0'
                data = bytes.fromhex(hex_only.decode('ascii'))
            except Exception:
                return b''
    return data


def _scan_pdf_objects(raw_bytes):
    """Parse indirect PDF objects (dict_bytes, stream_bytes_or_none) without being tricked by 'endobj' inside streams."""
    objects = {}
    n = len(raw_bytes)
    pos = 0
    while pos < n:
        m = _OBJ_HEADER_RE.search(raw_bytes, pos)
        if not m:
            break
        obj_num = int(m.group(1))
        gen_num = int(m.group(2))
        body_start = m.end()

        endobj_pos = raw_bytes.find(b'endobj', body_start)
        stream_kw_pos = raw_bytes.find(b'stream', body_start)

        if stream_kw_pos != -1 and (endobj_pos == -1 or stream_kw_pos < endobj_pos):
            sm = _STREAM_START_RE.match(raw_bytes, stream_kw_pos)
            if sm:
                dict_bytes = raw_bytes[body_start:stream_kw_pos]
                s_start = sm.end()
                length_m = re.search(rb'/Length\s+(\d+)\b(?!\s+\d+\s+R)', dict_bytes)
                s_end = -1
                if length_m:
                    claimed_len = int(length_m.group(1))
                    cand = s_start + claimed_len
                    # Verify 'endstream' follows within optional CR/LF
                    tail_slice = raw_bytes[cand:min(n, cand + 24)]
                    if b'endstream' in tail_slice:
                        s_end = cand
                if s_end == -1:
                    s_end = raw_bytes.find(b'endstream', s_start)
                if s_end == -1:
                    pos = body_start
                    continue
                stream_bytes = raw_bytes[s_start:s_end].rstrip(b'\r\n')
                after_stream = raw_bytes.find(b'endobj', s_end + 9)
                pos = (after_stream + 6) if after_stream != -1 else (s_end + 9)
                objects[(obj_num, gen_num)] = (dict_bytes, stream_bytes)
                continue

        if endobj_pos == -1:
            break
        dict_bytes = raw_bytes[body_start:endobj_pos]
        objects[(obj_num, gen_num)] = (dict_bytes, None)
        pos = endobj_pos + 6

    # Unpack PDF 1.5+ /ObjStm compressed object streams
    embedded_objects = {}
    for (_, _), (d_bytes, s_bytes) in list(objects.items()):
        if s_bytes and re.search(rb'/Type\s*/ObjStm\b', d_bytes):
            n_m = re.search(rb'/N\s+(\d+)', d_bytes)
            first_m = re.search(rb'/First\s+(\d+)', d_bytes)
            if not (n_m and first_m):
                continue
            count = min(int(n_m.group(1)), 5000)
            first_off = int(first_m.group(1))
            unpacked = _decompress_stream(d_bytes, s_bytes)
            if not unpacked or first_off > len(unpacked):
                continue
            header_nums = re.findall(rb'\d+', unpacked[:first_off])
            if len(header_nums) < count * 2:
                continue
            pairs = []
            for i in range(count):
                emb_num = int(header_nums[2 * i])
                emb_off = first_off + int(header_nums[2 * i + 1])
                pairs.append((emb_num, emb_off))
            for i, (emb_num, start_off) in enumerate(pairs):
                end_off = pairs[i + 1][1] if i + 1 < len(pairs) else len(unpacked)
                if 0 <= start_off <= end_off <= len(unpacked):
                    embedded_objects[(emb_num, 0)] = (unpacked[start_off:end_off], None)

    for k, v in embedded_objects.items():
        if k not in objects:
            objects[k] = v

    return objects


def _decode_cmap_hex(hex_bytes):
    if not hex_bytes:
        return ''
    b_len = len(hex_bytes)
    if b_len % 2 == 0 and b_len >= 2:
        try:
            return hex_bytes.decode('utf-16-be', errors='ignore')
        except Exception:
            pass
    return hex_bytes.decode('latin-1', errors='ignore')


def _parse_tounicode_cmap(cmap_bytes):
    """Parse CMap beginbfchar and beginbfrange sections into {(key_bytes): unicode_str}."""
    mapping = {}
    if not cmap_bytes or (b'bfchar' not in cmap_bytes and b'bfrange' not in cmap_bytes):
        return mapping

    # beginbfchar ... endbfchar
    for sec in re.findall(rb'beginbfchar\s*(.*?)\s*endbfchar', cmap_bytes, re.DOTALL):
        for src_h, dst_h in re.findall(rb'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', sec):
            try:
                if len(src_h) % 2 == 1:
                    src_h = b'0' + src_h
                if len(dst_h) % 2 == 1:
                    dst_h = b'0' + dst_h
                src_b = bytes.fromhex(src_h.decode('ascii'))
                dst_b = bytes.fromhex(dst_h.decode('ascii'))
                val = _decode_cmap_hex(dst_b)
                if val:
                    mapping[src_b] = val
            except Exception:
                continue

    # beginbfrange ... endbfrange
    for sec in re.findall(rb'beginbfrange\s*(.*?)\s*endbfrange', cmap_bytes, re.DOTALL):
        # Array destination: <start> <end> [<d1> <d2> ...]
        for start_h, end_h, arr_body in re.findall(rb'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*\[([^\]]*)\]', sec, re.DOTALL):
            try:
                src_width = max(1, (len(start_h) + 1) // 2)
                s_val = int(start_h, 16)
                e_val = int(end_h, 16)
                dst_list = re.findall(rb'<([0-9A-Fa-f]+)>', arr_body)
                for offset, dst_h in enumerate(dst_list):
                    if s_val + offset > e_val or offset > 4096:
                        break
                    if len(dst_h) % 2 == 1:
                        dst_h = b'0' + dst_h
                    src_b = (s_val + offset).to_bytes(src_width, 'big')
                    val = _decode_cmap_hex(bytes.fromhex(dst_h.decode('ascii')))
                    if val:
                        mapping[src_b] = val
            except Exception:
                continue

        # Scalar increment destination: <start> <end> <dstStart>
        cleaned_sec = re.sub(rb'<[0-9A-Fa-f]+>\s*<[0-9A-Fa-f]+>\s*\[[^\]]*\]', b'', sec, flags=re.DOTALL)
        for start_h, end_h, dst_h in re.findall(rb'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', cleaned_sec):
            try:
                src_width = max(1, (len(start_h) + 1) // 2)
                dst_width = max(1, (len(dst_h) + 1) // 2)
                s_val = int(start_h, 16)
                e_val = int(end_h, 16)
                d_val = int(dst_h, 16)
                span = min(4096, max(0, e_val - s_val + 1))
                for offset in range(span):
                    src_b = (s_val + offset).to_bytes(src_width, 'big')
                    dst_b = (d_val + offset).to_bytes(dst_width, 'big')
                    val = _decode_cmap_hex(dst_b)
                    if val:
                        mapping[src_b] = val
            except Exception:
                continue

    return mapping


def _decode_pdf_literal_bytes(raw_inner):
    """Unescape PDF (...) literal string content into raw bytes."""
    out = bytearray()
    i = 0
    n = len(raw_inner)
    esc_map = {
        ord('n'): 10,
        ord('r'): 13,
        ord('t'): 9,
        ord('b'): 8,
        ord('f'): 12,
        ord('('): ord('('),
        ord(')'): ord(')'),
        ord('\\'): ord('\\'),
    }
    while i < n:
        b = raw_inner[i]
        if b == 92 and i + 1 < n:  # backslash
            nxt = raw_inner[i + 1]
            if nxt in esc_map:
                out.append(esc_map[nxt])
                i += 2
            elif nxt == 13:  # \r or \r\n line continuation
                i += 3 if (i + 2 < n and raw_inner[i + 2] == 10) else 2
            elif nxt == 10:  # \n line continuation
                i += 2
            elif 48 <= nxt <= 55:  # octal \ddd
                oct_digits = [nxt]
                j = i + 2
                while j < n and len(oct_digits) < 3 and 48 <= raw_inner[j] <= 55:
                    oct_digits.append(raw_inner[j])
                    j += 1
                out.append(int(bytes(oct_digits), 8) & 0xFF)
                i = j
            else:
                out.append(nxt)
                i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


def _decode_bytes_with_cmap(raw_bytes, cmap=None, key_widths=None, from_hex=False):
    if not raw_bytes:
        return ''
    if len(raw_bytes) >= 2 and raw_bytes[:2] == b'\xfe\xff':
        return raw_bytes[2:].decode('utf-16-be', errors='ignore')

    if cmap and key_widths:
        # Try matching CMap key widths (e.g. 2-byte CID keys or 1-byte simple font keys)
        res = []
        matched_any = False
        idx = 0
        nb = len(raw_bytes)
        while idx < nb:
            hit = None
            for w in key_widths:
                if idx + w <= nb:
                    chunk = raw_bytes[idx:idx + w]
                    if chunk in cmap:
                        hit = (cmap[chunk], w)
                        break
            if hit is not None:
                res.append(hit[0])
                idx += hit[1]
                matched_any = True
            else:
                # Fallback byte when glyph not in ToUnicode
                ch = raw_bytes[idx]
                if 32 <= ch <= 126 or ch in (9, 10, 13):
                    res.append(chr(ch))
                idx += 1
        if matched_any:
            return ''.join(res)

    if from_hex and len(raw_bytes) % 2 == 0 and len(raw_bytes) >= 2:
        # UTF-16BE without BOM heuristic: every high byte is 0x00 for ASCII glyphs
        even_bytes = raw_bytes[0::2]
        if all(b == 0 for b in even_bytes):
            return raw_bytes.decode('utf-16-be', errors='ignore')

    try:
        return raw_bytes.decode('cp1252')
    except Exception:
        return raw_bytes.decode('latin-1', errors='ignore')


def _extract_bt_et_text(stream_bytes, font_cmaps=None, fallback_cmap=None):
    """Extract readable lines from BT ... ET content stream blocks."""
    if not stream_bytes or (b'Tj' not in stream_bytes and b'TJ' not in stream_bytes and b"'" not in stream_bytes):
        return ''
    font_cmaps = font_cmaps or {}
    fallback_widths = sorted({len(k) for k in fallback_cmap.keys()}, reverse=True) if fallback_cmap else None

    out = []
    # Find BT ... ET blocks, or parse whole stream if BT omitted in synthetic fragments
    blocks = re.findall(rb'\bBT\b(.*?)\bET\b', stream_bytes, re.DOTALL)
    if not blocks:
        blocks = [stream_bytes]

    # Pre-check initial font outside BT if any
    active_font = None

    for blk in blocks:
        i = 0
        n = len(blk)
        stack = []  # stack of ('str', bytes, is_hex) or ('arr', list) or ('num', float) or ('name', str)
        last_y = None
        last_x = None

        while i < n:
            b = blk[i]
            # Skip whitespace
            if b in (9, 10, 12, 13, 32):
                i += 1
                continue
            # Skip PDF comment %...\n
            if b == 37:
                nl = blk.find(b'\n', i)
                i = (nl + 1) if nl != -1 else n
                continue
            # Literal string (...)
            if b == 40:
                depth = 1
                j = i + 1
                while j < n and depth > 0:
                    c = blk[j]
                    if c == 92:  # escaped char
                        j += 2
                        continue
                    if c == 40:
                        depth += 1
                    elif c == 41:
                        depth -= 1
                    j += 1
                inner = blk[i + 1:max(i + 1, j - 1)]
                stack.append(('str', _decode_pdf_literal_bytes(inner), False))
                i = j
                continue
            # Hex string <...> (not << >> dict)
            if b == 60:
                if i + 1 < n and blk[i + 1] == 60:
                    i += 2
                    continue
                close = blk.find(b'>', i + 1)
                if close == -1:
                    break
                hex_part = re.sub(rb'\s+', b'', blk[i + 1:close])
                if len(hex_part) % 2 == 1:
                    hex_part += b'0'
                try:
                    raw_h = bytes.fromhex(hex_part.decode('ascii', errors='ignore'))
                except Exception:
                    raw_h = b''
                stack.append(('str', raw_h, True))
                i = close + 1
                continue
            if b == 62:  # '>'
                i += 1
                continue
            # Array [ ... ] (used for TJ)
            if b == 91:
                arr_items = []
                j = i + 1
                while j < n:
                    cb = blk[j]
                    if cb in (9, 10, 12, 13, 32):
                        j += 1
                    elif cb == 93:  # ']'
                        j += 1
                        break
                    elif cb == 40:
                        depth = 1
                        k = j + 1
                        while k < n and depth > 0:
                            cc = blk[k]
                            if cc == 92:
                                k += 2
                                continue
                            if cc == 40:
                                depth += 1
                            elif cc == 41:
                                depth -= 1
                            k += 1
                        inner = blk[j + 1:max(j + 1, k - 1)]
                        arr_items.append(('str', _decode_pdf_literal_bytes(inner), False))
                        j = k
                    elif cb == 60:
                        close = blk.find(b'>', j + 1)
                        if close == -1:
                            j += 1
                            break
                        hex_part = re.sub(rb'\s+', b'', blk[j + 1:close])
                        if len(hex_part) % 2 == 1:
                            hex_part += b'0'
                        try:
                            raw_h = bytes.fromhex(hex_part.decode('ascii', errors='ignore'))
                        except Exception:
                            raw_h = b''
                        arr_items.append(('str', raw_h, True))
                        j = close + 1
                    else:
                        # Number inside TJ array
                        k = j
                        while k < n and blk[k] not in (9, 10, 12, 13, 32, 40, 60, 91, 93):
                            k += 1
                        tok = blk[j:k]
                        try:
                            arr_items.append(('num', float(tok)))
                        except Exception:
                            pass
                        j = k
                stack.append(('arr', arr_items))
                i = j
                continue
            # /Name token
            if b == 47:
                j = i + 1
                while j < n and blk[j] not in (9, 10, 12, 13, 32, 40, 41, 47, 60, 62, 91, 93):
                    j += 1
                stack.append(('name', blk[i + 1:j].decode('latin-1', errors='ignore')))
                i = j
                continue

            # Regular token (number or operator)
            j = i
            while j < n and blk[j] not in (9, 10, 12, 13, 32, 40, 41, 47, 60, 62, 91, 93):
                j += 1
            tok_b = blk[i:j]
            i = j
            if not tok_b:
                i += 1
                continue

            try:
                num_val = float(tok_b)
                stack.append(('num', num_val))
                continue
            except Exception:
                pass

            op = tok_b.decode('latin-1', errors='ignore')
            cmap_info = font_cmaps.get(active_font) if active_font else None
            cmap = cmap_info[0] if cmap_info else fallback_cmap
            widths = cmap_info[1] if cmap_info else fallback_widths

            if op == 'Tf':
                # /FontName size Tf
                for item in reversed(stack[-3:]):
                    if item[0] == 'name':
                        active_font = item[1]
                        break
                stack.clear()
            elif op == 'Tj':
                if stack and stack[-1][0] == 'str':
                    out.append(_decode_bytes_with_cmap(stack[-1][1], cmap, widths, from_hex=stack[-1][2]))
                stack.clear()
            elif op == "'":
                out.append('\n')
                if stack and stack[-1][0] == 'str':
                    out.append(_decode_bytes_with_cmap(stack[-1][1], cmap, widths, from_hex=stack[-1][2]))
                stack.clear()
            elif op == '"':
                out.append('\n')
                if stack and stack[-1][0] == 'str':
                    out.append(_decode_bytes_with_cmap(stack[-1][1], cmap, widths, from_hex=stack[-1][2]))
                stack.clear()
            elif op == 'TJ':
                if stack and stack[-1][0] == 'arr':
                    parts = []
                    for item in stack[-1][1]:
                        if item[0] == 'str':
                            parts.append(_decode_bytes_with_cmap(item[1], cmap, widths, from_hex=item[2]))
                        elif item[0] == 'num' and item[1] <= -150:
                            if not parts or not parts[-1].endswith(' '):
                                parts.append(' ')
                    out.append(''.join(parts))
                stack.clear()
            elif op == 'T*':
                out.append('\n')
                stack.clear()
            elif op in ('Td', 'TD'):
                nums = [x[1] for x in stack[-2:] if x[0] == 'num']
                if len(nums) == 2:
                    tx, ty = nums
                    if abs(ty) > 0.5:
                        out.append('\n')
                    elif tx > 3.0 and out and not out[-1].endswith((' ', '\n')):
                        out.append(' ')
                stack.clear()
            elif op == 'Tm':
                nums = [x[1] for x in stack[-6:] if x[0] == 'num']
                if len(nums) == 6:
                    e, f = nums[4], nums[5]
                    if last_y is not None and abs(f - last_y) > 2.0:
                        out.append('\n')
                    elif last_x is not None and (e - last_x) > 3.0 and out and not out[-1].endswith((' ', '\n')):
                        out.append(' ')
                    last_x, last_y = e, f
                stack.clear()
            else:
                if len(stack) > 32:
                    stack.clear()

        if out and not out[-1].endswith('\n'):
            out.append('\n')

    return ''.join(out)


def _find_object_dict(objects, obj_num):
    for (num, _), (d_bytes, s_bytes) in objects.items():
        if num == obj_num:
            return d_bytes, s_bytes
    return None, None


def _collect_page_ids_from_pages_tree(objects):
    """Traverse /Catalog -> /Pages -> /Kids to preserve true document page order."""
    root_num = None
    for (num, _), (d_bytes, _) in objects.items():
        if re.search(rb'/Type\s*/Catalog\b', d_bytes):
            pages_m = re.search(rb'/Pages\s+(\d+)\s+\d+\s+R', d_bytes)
            if pages_m:
                root_num = int(pages_m.group(1))
                break

    if root_num is None:
        # Look for top /Pages without /Parent
        for (num, _), (d_bytes, _) in objects.items():
            if re.search(rb'/Type\s*/Pages\b', d_bytes) and not re.search(rb'/Parent\b', d_bytes):
                root_num = num
                break

    ordered_pages = []
    visited = set()

    def walk(node_num):
        if node_num in visited or len(ordered_pages) >= 5000:
            return
        visited.add(node_num)
        d_bytes, _ = _find_object_dict(objects, node_num)
        if not d_bytes:
            return
        kids_m = re.search(rb'/Kids\s*\[(.*?)\]', d_bytes, re.DOTALL)
        if kids_m and re.search(rb'/Type\s*/Pages\b', d_bytes):
            for k in re.findall(rb'(\d+)\s+\d+\s+R', kids_m.group(1)):
                walk(int(k))
        elif re.search(rb'/Type\s*/Page\b(?!s)', d_bytes):
            ordered_pages.append(node_num)

    if root_num is not None:
        walk(root_num)

    if not ordered_pages:
        # Fallback: scan objects in numeric order for /Type /Page
        for (num, _), (d_bytes, _) in sorted(objects.items()):
            if re.search(rb'/Type\s*/Page\b(?!s)', d_bytes):
                ordered_pages.append(num)

    return ordered_pages


def _extract_with_stdlib_pdf(raw_bytes, max_pages=800):
    is_encrypted = bool(re.search(rb'/Encrypt\s+(\d+\s+\d+\s+R|<<)', raw_bytes))
    objects = _scan_pdf_objects(raw_bytes)

    # Decompress CMaps and map CMap object IDs
    cmaps_by_obj = {}
    merged_cmap = {}
    for (num, _), (d_bytes, s_bytes) in objects.items():
        if not s_bytes:
            continue
        decomp = _decompress_stream(d_bytes, s_bytes)
        if decomp and (b'beginbfchar' in decomp or b'beginbfrange' in decomp):
            cm = _parse_tounicode_cmap(decomp)
            if cm:
                cmaps_by_obj[num] = cm
                merged_cmap.update(cm)

    # Map Font object number -> (cmap, widths)
    font_obj_cmaps = {}
    for (num, _), (d_bytes, _) in objects.items():
        tu_m = re.search(rb'/ToUnicode\s+(\d+)\s+\d+\s+R', d_bytes)
        if tu_m:
            cm_num = int(tu_m.group(1))
            if cm_num in cmaps_by_obj:
                cm = cmaps_by_obj[cm_num]
                widths = sorted({len(k) for k in cm.keys()}, reverse=True)
                font_obj_cmaps[num] = (cm, widths)

    # Helper to extract /Font << /F1 12 0 R >> maps
    def extract_font_map(dict_bytes, depth=0):
        res = {}
        if not dict_bytes or depth > 3:
            return res
        # Check inherited /Parent
        parent_m = re.search(rb'/Parent\s+(\d+)\s+\d+\s+R', dict_bytes)
        if parent_m:
            p_dict, _ = _find_object_dict(objects, int(parent_m.group(1)))
            if p_dict:
                res.update(extract_font_map(p_dict, depth + 1))

        # Locate /Resources block (inline or indirect)
        res_block = dict_bytes
        res_ref = re.search(rb'/Resources\s+(\d+)\s+\d+\s+R', dict_bytes)
        if res_ref:
            r_dict, _ = _find_object_dict(objects, int(res_ref.group(1)))
            if r_dict:
                res_block = r_dict

        font_block = b''
        font_ref = re.search(rb'/Font\s+(\d+)\s+\d+\s+R', res_block)
        if font_ref:
            f_dict, _ = _find_object_dict(objects, int(font_ref.group(1)))
            if f_dict:
                font_block = f_dict
        else:
            font_inline = re.search(rb'/Font\s*<<(.*?)>>', res_block, re.DOTALL)
            if font_inline:
                font_block = font_inline.group(1)

        for fname_b, fobj_b in re.findall(rb'/([A-Za-z0-9_.+-]+)\s+(\d+)\s+\d+\s+R', font_block):
            fobj_num = int(fobj_b)
            fname = fname_b.decode('latin-1', errors='ignore')
            if fobj_num in font_obj_cmaps:
                res[fname] = font_obj_cmaps[fobj_num]
            elif fname not in res:
                res[fname] = ({}, [])
        return res

    page_ids = _collect_page_ids_from_pages_tree(objects)
    pages = []
    total_chars = 0
    page_count = len(page_ids)

    if page_ids:
        for page_idx, p_num in enumerate(page_ids[:max_pages], 1):
            d_bytes, _ = _find_object_dict(objects, p_num)
            if not d_bytes:
                continue
            font_map = extract_font_map(d_bytes)
            content_refs = []
            arr_m = re.search(rb'/Contents\s*\[(.*?)\]', d_bytes, re.DOTALL)
            if arr_m:
                content_refs = [int(x) for x in re.findall(rb'(\d+)\s+\d+\s+R', arr_m.group(1))]
            else:
                one_m = re.search(rb'/Contents\s+(\d+)\s+\d+\s+R', d_bytes)
                if one_m:
                    content_refs = [int(one_m.group(1))]

            chunks = []
            for cref in content_refs:
                cd_bytes, cs_bytes = _find_object_dict(objects, cref)
                if cs_bytes:
                    decomp = _decompress_stream(cd_bytes, cs_bytes)
                    if decomp:
                        txt = _extract_bt_et_text(decomp, font_map, merged_cmap if not font_map else None)
                        if txt:
                            chunks.append(txt)
            page_txt = _clean_page_text('\n'.join(chunks))[:25000]
            if page_txt:
                total_chars += len(page_txt)
                pages.append({'page': page_idx, 'text': page_txt})

    # If no structured pages yielded text, scan standalone content streams (useful if tree used unsupported XRef stream)
    if total_chars < 20 and not is_encrypted:
        stream_idx = 0
        fallback_pages = []
        fallback_chars = 0
        for (num, _), (d_bytes, s_bytes) in sorted(objects.items()):
            if not s_bytes:
                continue
            if re.search(rb'/Type\s*/(?:ObjStm|XRef|Metadata)\b', d_bytes):
                continue
            decomp = _decompress_stream(d_bytes, s_bytes)
            if not decomp or b'begincmap' in decomp or b'beginbfchar' in decomp:
                continue
            txt = _clean_page_text(_extract_bt_et_text(decomp, None, merged_cmap or None))[:25000]
            if txt:
                stream_idx += 1
                fallback_chars += len(txt)
                fallback_pages.append({'page': stream_idx, 'text': txt})
                if stream_idx >= max_pages:
                    break
        if fallback_chars > total_chars:
            pages = fallback_pages
            total_chars = fallback_chars
            page_count = max(page_count, len(fallback_pages))

    warning = ''
    if is_encrypted:
        warning = 'El PDF está cifrado/protegido; no se pudo extraer el texto completo sin descifrado.'
    elif total_chars < 20:
        warning = 'PDF sin capa de texto seleccionable (posible PDF escaneado como imagen o compilado sin texto embebido).'

    return {
        'ok': True,
        'engine': 'stdlib-pdf',
        'pageCount': max(page_count, len(pages), 1 if raw_bytes else 0),
        'pages': pages,
        'totalChars': total_chars,
        'isScannedOrEmpty': total_chars < 20,
        'isEncrypted': is_encrypted,
        'warning': warning
    }


def extract_pdf_text(file_path, max_pages=800):
    if not file_path or not os.path.isfile(file_path):
        return {'ok': False, 'error': 'Archivo PDF no encontrado en disco.'}
    try:
        with open(file_path, 'rb') as f:
            head = f.read(1024)
            if not is_valid_pdf_bytes(head):
                return {'ok': False, 'error': 'El archivo no tiene una firma binaria válida %PDF-.'}
    except Exception as e:
        return {'ok': False, 'error': f'Error leyendo el archivo PDF: {e}'}

    tier1 = _extract_with_python_libs(file_path, max_pages=max_pages)
    if tier1 and tier1.get('ok') and (tier1.get('totalChars', 0) >= 20 or tier1.get('isEncrypted')):
        return tier1

    tier2 = _extract_with_pdftotext(file_path, max_pages=max_pages)
    if tier2 and tier2.get('ok') and tier2.get('totalChars', 0) >= 20:
        return tier2

    try:
        with open(file_path, 'rb') as f:
            raw_bytes = f.read(80 * 1024 * 1024)
        tier3 = _extract_with_stdlib_pdf(raw_bytes, max_pages=max_pages)
        # If tier1 knew exact pageCount on an empty/scanned PDF, preserve higher pageCount
        if tier1 and tier1.get('pageCount', 0) > tier3.get('pageCount', 0):
            tier3['pageCount'] = tier1['pageCount']
        return tier3
    except Exception as e:
        if tier1:
            return tier1
        return {'ok': False, 'error': f'Error procesando PDF: {e}'}


# ==============================================================================
# Verbatim Entrust / Oracle Error Code Extractor (Zero Hallucinations)
# ==============================================================================

_CODE_EXTRACT_RE = re.compile(r'\b(52\d{5}|520\d{3}|AUD\d{2,4}|ORA-\d{5})\b', re.IGNORECASE)
_TABLE_CELL_CODE_RE = re.compile(r'^[\[\(\s]*(5\d{5,7}|AUD\d{2,5}|ORA-\d{5})(?=[\]\)\s:\-–—]|$)', re.IGNORECASE)


def _classify_code_meta(code_upper, excerpt):
    if code_upper.startswith(('5', 'ORA-')):
        family = 'ORA' if code_upper.startswith('ORA-') else '520'
        severity = 'ERROR'
    else:
        family = 'AUD'
        low_ctx = excerpt.lower()
        if any(w in low_ctx for w in ('fail', 'error', 'locked out', 'revoked', 'past expiry')):
            severity = 'ERROR'
        elif any(w in low_ctx for w in ('warn', 'near expiry', 'exhausted', '80 percent')):
            severity = 'WARN'
        else:
            severity = 'INFO'
    return family, severity


def extract_entrust_codes_from_pages(pages, filename, rel_path, source_type='PDF_CUSTOM', line_anchors=None, use_page_fragment=True):
    """
    Scan extracted PDF pages or document sections and collect verbatim context snippets for 52xxxxx, 520xxx, AUDxxx, ORA-xxxxx.
    Never invents causes or remediations not literally present in the document text.
    """
    if not isinstance(pages, list) or not pages:
        return {}

    best_by_code = {}

    for p_obj in pages:
        try:
            page_num = int(p_obj.get('page') or 1)
        except Exception:
            page_num = 1
        text = str(p_obj.get('text') or '')
        if not text:
            continue
        sec_anchor = str(p_obj.get('anchor') or '').strip()

        lines = [ln.strip() for ln in text.split('\n')]
        non_empty = [(idx, ln) for idx, ln in enumerate(lines) if ln]

        for pos_i, (orig_idx, line) in enumerate(non_empty):
            matches = list(_CODE_EXTRACT_RE.finditer(line))
            if not matches:
                continue

            for m in matches:
                code_upper = m.group(1).upper()

                # Score occurrence quality so actual definitions beat TOC mentions
                score = 10
                if re.match(r'^[\[\(\s]*' + re.escape(code_upper) + r'[\]\)\s:\-–—|]+', line, re.IGNORECASE):
                    score += 50
                elif m.start() <= 20:
                    score += 25
                if re.search(r'\.{4,}\s*\d+\s*$', line):
                    score -= 35  # Likely a Table of Contents entry
                if len(line) >= 24:
                    score += 10

                prev = best_by_code.get(code_upper)
                if prev and prev['_score'] >= score:
                    continue

                # Clean title from the matched line verbatim
                clean_title = re.sub(
                    r'^[\[\(\s]*' + re.escape(code_upper) + r'[\]\)\s:\-–—|]*',
                    '',
                    line,
                    flags=re.IGNORECASE
                ).strip()
                if not clean_title or len(clean_title) < 3:
                    clean_title = line
                if len(clean_title) > 160:
                    clean_title = clean_title[:157].rstrip() + '...'

                # Gather matched line + up to 2 subsequent non-empty lines verbatim
                ctx_lines = [line]
                for k in (1, 2):
                    if pos_i + k < len(non_empty):
                        nxt_ln = non_empty[pos_i + k][1]
                        if len(' '.join(ctx_lines)) + len(nxt_ln) <= 440:
                            ctx_lines.append(nxt_ln)
                excerpt = ' | '.join(ctx_lines)
                if len(excerpt) > 450:
                    excerpt = excerpt[:447].rstrip() + '...'

                family, severity = _classify_code_meta(code_upper, excerpt)

                anchor = ''
                if line_anchors and isinstance(line_anchors, dict):
                    anchor = line_anchors.get((page_num, line)) or line_anchors.get(line) or ''
                if not anchor and not use_page_fragment:
                    anchor = sec_anchor

                if use_page_fragment:
                    manual_ref = f'{rel_path}#page={page_num}'
                elif anchor:
                    manual_ref = f'{rel_path}#{anchor}'
                else:
                    manual_ref = rel_path

                best_by_code[code_upper] = {
                    '_score': score,
                    'code': code_upper,
                    'title': clean_title,
                    'excerpt': excerpt,
                    'sourceFile': filename,
                    'page': page_num,
                    'manualFile': manual_ref,
                    'anchor': anchor,
                    'family': family,
                    'severity': severity,
                    'sourceType': source_type
                }

    out = {}
    for code, entry in sorted(best_by_code.items()):
        cleaned = dict(entry)
        cleaned.pop('_score', None)
        out[code] = cleaned
    return out


# ==============================================================================
# Structured HTML / Markdown / Text Document Extractor (Zero Truncation)
# ==============================================================================

_HTML_SKIP_TAGS = {'script', 'style', 'noscript', 'svg', 'template'}
_HTML_BLOCK_TAGS = {'p', 'div', 'li', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'dt', 'dd', 'section', 'article', 'hr', 'blockquote', 'pre'}
_HTML_ANCHOR_TAGS = {'tr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'div', 'section', 'article', 'p', 'dt'}


class _StructuredHtmlDocParser(HTMLParser):
    """Parse HTML manuals preserving table rows, block newlines, headings, and anchor IDs."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip_depth = 0
        self.in_title = False
        self.in_h1 = False
        self.title_parts = []
        self.h1_parts = []

        self.in_row = False
        self.in_cell = False
        self.cell_buf = []
        self.current_cells = []
        self.row_anchor = ''

        self.line_buf = []
        self.active_anchor = ''

        self.lines = []       # list of (line_text, anchor)
        self.table_rows = []  # list of (cells_list, anchor, line_idx)

    def _flush_cell(self):
        if not self.cell_buf:
            return ''
        txt = re.sub(r'\s+', ' ', ''.join(self.cell_buf)).strip()
        self.cell_buf.clear()
        return txt

    def _flush_line(self):
        if not self.line_buf:
            return
        txt = re.sub(r'\s+', ' ', ''.join(self.line_buf)).strip()
        self.line_buf.clear()
        if txt:
            self.lines.append((txt, self.active_anchor))

    def _flush_row(self):
        if self.in_cell:
            cell_txt = self._flush_cell()
            if cell_txt:
                self.current_cells.append(cell_txt)
            self.in_cell = False
        if self.current_cells:
            clean_cells = [c for c in self.current_cells if c]
            if clean_cells:
                joined = ' | '.join(clean_cells)
                anchor = self.row_anchor or self.active_anchor
                line_idx = len(self.lines)
                self.lines.append((joined, anchor))
                self.table_rows.append((clean_cells, anchor, line_idx))
        self.current_cells = []
        self.row_anchor = ''
        self.in_row = False

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t in _HTML_SKIP_TAGS:
            self.skip_depth += 1
            return
        if self.skip_depth > 0:
            return

        attr_map = {}
        for k, v in attrs:
            if k and v is not None:
                attr_map[k.lower()] = v.strip()

        elem_id = attr_map.get('id') or (attr_map.get('name') if t == 'a' else '') or ''
        if elem_id and (t in _HTML_ANCHOR_TAGS or t == 'a' or t in ('td', 'th')):
            if self.in_row and not self.row_anchor:
                self.row_anchor = elem_id
            if t in _HTML_ANCHOR_TAGS:
                self.active_anchor = elem_id
            elif t == 'a' and not self.active_anchor:
                self.active_anchor = elem_id

        if t == 'title':
            self.in_title = True
        elif t == 'h1' and not self.h1_parts:
            self.in_h1 = True

        if t == 'tr':
            if self.in_row:
                self._flush_row()
            self._flush_line()
            self.in_row = True
            self.current_cells = []
            self.cell_buf = []
            self.row_anchor = elem_id or ''
        elif t in ('td', 'th'):
            if self.in_row:
                if self.in_cell:
                    prev_txt = self._flush_cell()
                    if prev_txt:
                        self.current_cells.append(prev_txt)
                self.in_cell = True
                self.cell_buf = []
        elif t == 'br':
            if self.in_cell:
                self.cell_buf.append(' ')
            else:
                self._flush_line()
        elif t in _HTML_BLOCK_TAGS:
            if not self.in_row:
                self._flush_line()

    def handle_endtag(self, tag):
        t = tag.lower()
        if t in _HTML_SKIP_TAGS:
            if self.skip_depth > 0:
                self.skip_depth -= 1
            return
        if self.skip_depth > 0:
            return

        if t == 'title':
            self.in_title = False
        elif t == 'h1':
            self.in_h1 = False

        if t in ('td', 'th') and self.in_row:
            if self.in_cell:
                cell_txt = self._flush_cell()
                if cell_txt:
                    self.current_cells.append(cell_txt)
                self.in_cell = False
        elif t == 'tr':
            self._flush_row()
        elif t in _HTML_BLOCK_TAGS:
            if self.in_row and self.in_cell:
                self.cell_buf.append(' ')
            elif not self.in_row:
                self._flush_line()

    def handle_data(self, data):
        if self.skip_depth > 0 or not data:
            return
        if self.in_title:
            self.title_parts.append(data)
            return
        if self.in_h1:
            self.h1_parts.append(data)
        if self.in_row and self.in_cell:
            self.cell_buf.append(data)
        else:
            self.line_buf.append(data)

    def close(self):
        try:
            super().close()
        except Exception:
            pass
        if self.in_row:
            self._flush_row()
        self._flush_line()


def extract_html_or_text_document(file_path, max_bytes=60 * 1024 * 1024, chunk_chars=8000):
    """Extract structured sections, table rows, anchors, and full text from .html/.htm/.md/.txt files."""
    if not os.path.isfile(file_path):
        return {'ok': False, 'error': 'Archivo no encontrado en disco.'}

    try:
        with open(file_path, 'rb') as f:
            raw_bytes = f.read(max_bytes)
    except Exception as e:
        return {'ok': False, 'error': f'Error leyendo archivo: {e}'}

    text = None
    for enc in ('utf-8', 'utf-8-sig', 'cp1252', 'latin-1'):
        try:
            text = raw_bytes.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        text = raw_bytes.decode('utf-8', errors='ignore')

    text = text.replace('\xa0', ' ').replace('\r\n', '\n').replace('\r', '\n').replace('\x00', '')
    ext = os.path.splitext(file_path)[1].lower()
    is_html = ext in ('.html', '.htm')

    lines = []
    table_rows = []
    doc_title = ''

    if is_html:
        parser = _StructuredHtmlDocParser()
        try:
            parser.feed(text)
            parser.close()
        except Exception:
            parser.close()
        lines = parser.lines
        table_rows = parser.table_rows
        doc_title = re.sub(r'\s+', ' ', ''.join(parser.title_parts)).strip()
        if not doc_title or doc_title.lower() in ('untitled', 'document'):
            doc_title = re.sub(r'\s+', ' ', ''.join(parser.h1_parts)).strip()
        if not lines and text.strip():
            # Fallback regex tag strip
            stripped = re.sub(r'(?is)<(script|style)[^>]*>.*?</\1>', ' ', text)
            stripped = re.sub(r'<[^>]+>', '\n', stripped)
            for ln in stripped.splitlines():
                cl = re.sub(r'[ \t\f\v]+', ' ', ln).strip()
                if cl:
                    lines.append((cl, ''))
    else:
        for ln in text.splitlines():
            cl = re.sub(r'[ \t\f\v]+', ' ', ln).strip()
            if cl:
                lines.append((cl, ''))
                if not doc_title and ln.lstrip().startswith('#'):
                    doc_title = ln.lstrip('#').strip()

    doc_title = (doc_title or os.path.basename(file_path))[:180]

    # Group lines into searchable sections of ~chunk_chars without losing a single character
    sections = []
    line_to_section = {}
    line_anchors = {}
    cur_lines = []
    cur_len = 0
    cur_anchor = ''
    sec_num = 1

    for idx, (ln_text, ln_anchor) in enumerate(lines):
        if ln_anchor and not cur_anchor:
            cur_anchor = ln_anchor
        if cur_lines and (cur_len + len(ln_text) + 1 > chunk_chars):
            sections.append({
                'page': sec_num,
                'text': '\n'.join(cur_lines),
                'anchor': cur_anchor
            })
            sec_num += 1
            cur_lines = []
            cur_len = 0
            cur_anchor = ln_anchor or ''

        cur_lines.append(ln_text)
        cur_len += len(ln_text) + 1
        line_to_section[idx] = sec_num
        if ln_anchor:
            line_anchors[(sec_num, ln_text)] = ln_anchor
            if ln_text not in line_anchors:
                line_anchors[ln_text] = ln_anchor

    if cur_lines:
        sections.append({
            'page': sec_num,
            'text': '\n'.join(cur_lines),
            'anchor': cur_anchor
        })

    if not sections:
        sections = [{'page': 1, 'text': '', 'anchor': ''}]

    total_chars = sum(len(s['text']) for s in sections)
    annotated_rows = []
    for cells, r_anchor, r_line_idx in table_rows:
        annotated_rows.append((cells, r_anchor, line_to_section.get(r_line_idx, 1)))

    return {
        'ok': True,
        'engine': 'html-parser' if is_html else 'text-parser',
        'title': doc_title,
        'sectionCount': len(sections),
        'totalChars': total_chars,
        'pages': sections,
        'tableRows': annotated_rows,
        'lineAnchors': line_anchors
    }


def extract_entrust_codes_from_html_or_text(doc_res, filename, rel_path):
    """
    Extract verbatim Entrust/Oracle error & audit codes from parsed HTML tables and full document sections.
    """
    if not isinstance(doc_res, dict) or not doc_res.get('ok'):
        return {}

    scored_by_code = {}

    # 1. High-precision scan of structured HTML <table> rows
    for cells, r_anchor, sec_num in (doc_res.get('tableRows') or []):
        if not cells:
            continue
        first_cell = cells[0].strip()
        m_cell = _TABLE_CELL_CODE_RE.match(first_cell)
        if not m_cell:
            continue
        rest_cells = [c.strip() for c in cells[1:] if c and c.strip()]
        rest_joined = ' | '.join(rest_cells)
        if len(rest_joined) < 10:
            # Skip index/TOC rows with no real description
            inline_tail = first_cell[m_cell.end():].strip(' :-–—|[]()')
            if len(inline_tail) < 10:
                continue
            rest_joined = inline_tail

        code_upper = m_cell.group(1).upper()
        title_raw = (rest_cells[0] if rest_cells else rest_joined).strip()
        if len(title_raw) > 160:
            title_raw = title_raw[:157].rstrip() + '...'
        excerpt = ' | '.join(cells)
        if len(excerpt) > 450:
            excerpt = excerpt[:447].rstrip() + '...'

        score = 100 + (15 if r_anchor else 0) + min(20, len(rest_cells) * 5)
        prev = scored_by_code.get(code_upper)
        if prev and prev[0] >= score:
            continue

        family, severity = _classify_code_meta(code_upper, excerpt)
        manual_ref = f'{rel_path}#{r_anchor}' if r_anchor else rel_path
        scored_by_code[code_upper] = (score, {
            'code': code_upper,
            'title': title_raw or code_upper,
            'excerpt': excerpt,
            'sourceFile': filename,
            'page': int(sec_num or 1),
            'manualFile': manual_ref,
            'anchor': r_anchor or '',
            'family': family,
            'severity': severity,
            'sourceType': 'DOC_CUSTOM'
        })

    # 2. Fallback / companion scan across all chunks (non-table headings, prose, .md/.txt)
    prose_codes = extract_entrust_codes_from_pages(
        doc_res.get('pages') or [],
        filename,
        rel_path,
        source_type='DOC_CUSTOM',
        line_anchors=doc_res.get('lineAnchors'),
        use_page_fragment=False
    )
    for code_upper, entry in prose_codes.items():
        if code_upper not in scored_by_code:
            scored_by_code[code_upper] = (50, entry)

    return {code: payload for code, (_, payload) in sorted(scored_by_code.items())}
