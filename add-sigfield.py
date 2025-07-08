"""
Add a signature field to a PDF file.
"""
input_pdf_path = "unsigned/test.pdf"
output_pdf_path = "unsigned/test_with_sigfield.pdf"
box = (100, 300, 300, 400)


from pathlib import Path

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields
from pyhanko.sign.fields import SigFieldSpec


Path(output_pdf_path).parent.mkdir(parents=True, exist_ok=True)
with open(input_pdf_path, "rb") as f:
    w = IncrementalPdfFileWriter(f)
    fields.append_signature_field(
        w,
        sig_field_spec=SigFieldSpec(
            sig_field_name="Signature1",
            box=box
        ),
    )

    with open(output_pdf_path, "wb") as f:
        w.write(f)