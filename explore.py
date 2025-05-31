import io
import os
from pathlib import Path
#import pikepdf
from pyhanko.sign import signers, timestamps, fields
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.sign.signers import PdfSigner, PdfSignatureMetadata
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko import stamp
from pyhanko.pdf_utils.font import opentype
from pyhanko.pdf_utils import text, images

from pyhanko.pdf_utils.crypt.permissions import PdfPermissions

from pyhanko.pdf_utils.crypt import StandardSecurityHandler
from pyhanko_certvalidator import ValidationContext


P12_PATH = os.getenv("SECRET_FILE")
P12_PASSWORD = os.getenv("SECRET_PASSWORD").encode()


pdf_input_path = "unsigned/test.pdf"
pdf_output_path = "signed/test-signed.pdf"


# Load the signer from the .p12 file
signer = signers.SimpleSigner.load_pkcs12(
    pfx_file=P12_PATH,
    passphrase=P12_PASSWORD,
    prefer_pss=False 
)

tsa_root = load_cert_from_pemder("certs/SectigoQualifiedTimeStampingRootR45.crt")
tsa_intermediate = load_cert_from_pemder("certs/SectigoQualifiedTimeStampingCAR35.crt")


validation_context=ValidationContext(
        extra_trust_roots=[tsa_root],
        other_certs=[tsa_intermediate],
        allow_fetching=True,
)

signature_meta = PdfSignatureMetadata(
    field_name='Signature1',
    #subfilter=fields.SigSeedSubFilter.PADES, 
    embed_validation_info=True,
    validation_context=validation_context,
    use_pades_lta=True, # False,  # True
)

stamp_style=stamp.TextStampStyle(
    stamp_text='Digitally signed\n%(signer)s\n%(ts)s',
    background=images.PdfImage('images/pf.png')
)


#tsa_client = timestamps.HTTPTimeStamper('http://timestamp.digicert.com')
#tsa_client = timestamps.HTTPTimeStamper(
#    'http://rfc3161timestamp.globalsign.com/advanced',
#)
tsa_client = timestamps.HTTPTimeStamper("http://timestamp.sectigo.com/qualified")


pdf_signer = PdfSigner(
    signature_meta=signature_meta,
    signer=signer,
    timestamper=tsa_client,
    stamp_style=stamp_style,
)

#pdf = pikepdf.open(pdf_input_path)

#buffer = io.BytesIO()


#pdf.save(
#    buffer,
#    encryption=pikepdf.Encryption(
#        owner="heslo",
#        user="",
#        allow=pikepdf.Permissions(
#            extract=False,
#            modify_annotation=False,
#            modify_assembly=False,
#            modify_form=False,
#            modify_other=False,
#            print_lowres=False,
#            print_highres=False
#        )
#    )
#)
#
#buffer.seek(0)

with open(pdf_input_path, 'rb') as f:
    w = IncrementalPdfFileWriter(f)

#w.encrypt(user_pwd="heslo")

    append_signature_field(w, sig_field_spec=SigFieldSpec(
        sig_field_name='Signature1',
        box=(315, 250, 465, 300)
    ))

# Step 4: Sign the PDF
    with open(pdf_output_path, 'wb') as final_output:
        pdf_signer.sign_pdf(w, output=final_output)
