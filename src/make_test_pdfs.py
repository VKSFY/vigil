"""
Build two minimal PDFs for the scanner test:
  - data/test_samples/clean.pdf       - plain "Hello, world." page
  - data/test_samples/malicious.pdf   - same body + /JavaScript /OpenAction /Launch

Pure structural builder so the xref offsets land correctly; pdfminer.six
parses both without warnings.
"""
from __future__ import annotations

import os


def _build_pdf(objects: list[bytes], catalog_index: int = 1) -> bytes:
    """Assemble objects into a PDF with a correct xref table."""
    out = bytearray()
    out += b"%PDF-1.4\n%\xc1\xc2\xc3\xc4\n"   # binary-safe marker
    offsets = [0]  # object 0 has offset 0 (the free-list head)
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_start = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_index} 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode()
    return bytes(out)


def make_clean() -> bytes:
    content_stream = b"BT /F1 24 Tf 100 700 Td (Hello, world.) Tj ET"
    objs = [
        # 1: Catalog
        b"<< /Type /Catalog /Pages 2 0 R >>",
        # 2: Pages
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        # 3: Page
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        # 4: Content stream
        b"<< /Length " + str(len(content_stream)).encode() + b" >>\nstream\n"
        + content_stream + b"\nendstream",
        # 5: Font
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    return _build_pdf(objs)


def make_malicious() -> bytes:
    content_stream = b"BT /F1 18 Tf 100 700 Td (You opened a tainted invoice.) Tj ET"
    # JavaScript blob (harmless — just an app.alert) — the SCANNER looks for the
    # marker /JS, /JavaScript, /OpenAction, /Launch, not at the code itself.
    js_code = b"app.alert({cMsg:'Update your reader to view this document', cTitle:'PDF Reader', nIcon:1});"
    objs = [
        # 1: Catalog with /OpenAction pointing at the JS action
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R /Names << /JavaScript 7 0 R >> /AA << /WC 8 0 R >> >>",
        # 2: Pages
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        # 3: Page (also has its own /AA additional-action set)
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R "
        b"/AA << /O 6 0 R >> >>",
        # 4: Content stream
        b"<< /Length " + str(len(content_stream)).encode() + b" >>\nstream\n"
        + content_stream + b"\nendstream",
        # 5: Font
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        # 6: JavaScript action (auto-triggered)
        b"<< /Type /Action /S /JavaScript /JS " + repr(js_code.decode()).encode() + b" >>",
        # 7: Names tree for JavaScript
        b"<< /Names [(EICAR) 9 0 R] >>",
        # 8: Document close action -> Launch external program
        b"<< /Type /Action /S /Launch /F (cmd.exe) /Win << /F (cmd.exe) /P (/c calc.exe) >> >>",
        # 9: Another /JS action invoked from the Names tree
        b"<< /Type /Action /S /JavaScript /JS " + repr("app.beep(0);").encode() + b" >>",
        # 10: Encoded stream — FlateDecode + ASCIIHexDecode chain (no real payload)
        b"<< /Length 4 /Filter [/ASCIIHexDecode /FlateDecode] >>\nstream\n00>\n\nendstream",
        # 11: Embedded file reference
        b"<< /Type /Filespec /F (payload.exe) /EF << /F 12 0 R >> >>",
        # 12: Embedded file stream
        b"<< /Length 4 /Type /EmbeddedFile >>\nstream\nMZ\x90\x00\nendstream",
    ]
    return _build_pdf(objs)


def main():
    out_dir = "data/test_samples"
    os.makedirs(out_dir, exist_ok=True)
    clean = make_clean()
    mal = make_malicious()
    with open(os.path.join(out_dir, "clean.pdf"), "wb") as f:
        f.write(clean)
    with open(os.path.join(out_dir, "malicious.pdf"), "wb") as f:
        f.write(mal)
    print(f"wrote {out_dir}/clean.pdf ({len(clean)} bytes)")
    print(f"wrote {out_dir}/malicious.pdf ({len(mal)} bytes)")


if __name__ == "__main__":
    main()
