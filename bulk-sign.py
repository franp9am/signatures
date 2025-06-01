import configparser
import logging
import os
from pathlib import Path
from typing import Optional, Tuple

from pyhanko import stamp
from pyhanko.pdf_utils import images
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import (PdfSignatureMetadata, PdfSigner, fields, signers,
                          timestamps)
from pyhanko.sign.fields import SigFieldSpec
from pyhanko_certvalidator import ValidationContext

logger = logging.getLogger(__name__)
logger.setLevel(
    logging.DEBUG
)  # Set the minimum logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter(
    fmt="[%(asctime)s] [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


class BulkSigner:
    def __init__(
        self,
        config_path: str = "config.ini",
        p12_file: Optional[str] = None,
        p12_password: Optional[str] = None,
        use_lta: bool = False,
        tsa_root_cert_path: str = "certs/SectigoQualifiedTimeStampingRootR45.crt",
        tsa_intermediate_cert_path: str = "certs/SectigoQualifiedTimeStampingCAR35.crt",
    ):
        config = configparser.ConfigParser()
        config.read(config_path)

        credentials_file = p12_file or config["credentials"].get("p12_file")
        credentials_password = p12_password or config["credentials"].get("p12_password")

        if not credentials_file:
            raise ValueError("Credentials file is required")

        if not os.path.exists(credentials_file):
            raise FileNotFoundError(f"Credentials file not found: {credentials_file}")

        if not isinstance(credentials_password, str):
            raise ValueError("Credentials password must be a string")

        image_path = config["stamp"]["image_path"]
        bbox_x_min = config["stamp"]["bbox_x_min"]
        bbox_x_max = config["stamp"]["bbox_x_max"]
        bbox_y_min = config["stamp"]["bbox_y_min"]
        bbox_y_max = config["stamp"]["bbox_y_max"]
        self.bbox = tuple(map(int, (bbox_x_min, bbox_y_min, bbox_x_max, bbox_y_max)))

        if use_lta:
            validation_context = ValidationContext(
                extra_trust_roots=[tsa_root_cert_path],
                other_certs=[tsa_intermediate_cert_path],
                allow_fetching=True,
            )
        else:
            validation_context = ValidationContext(allow_fetching=True)

        signature_meta = PdfSignatureMetadata(
            field_name="Signature1",
            subfilter=fields.SigSeedSubFilter.PADES if use_lta else None,
            embed_validation_info=use_lta,
            validation_context=validation_context,
            use_pades_lta=use_lta,
            certify=True,
        )

        signer = signers.SimpleSigner.load_pkcs12(
            pfx_file=credentials_file,
            passphrase=credentials_password.encode(),
            prefer_pss=False,
        )
        if signer is None:
            raise RuntimeError("Failed to load signer")

        timestamper = (
            timestamps.HTTPTimeStamper("http://timestamp.sectigo.com/qualified")
            if use_lta
            else None
        )

        stamp_style = stamp.TextStampStyle(
            stamp_text="Digitally signed\n%(signer)s\n%(ts)s",
            background=images.PdfImage(image_path),
        )

        self.pdf_signer = PdfSigner(
            signature_meta=signature_meta,
            signer=signer,
            timestamper=timestamper,
            stamp_style=stamp_style,
        )

    def sign_one(self, input_pdf_path: str, output_pdf_path: str):
        logger.info(f"Signing {input_pdf_path} -> {output_pdf_path}")
        Path(output_pdf_path).parent.mkdir(parents=True, exist_ok=True)
        with open(input_pdf_path, "rb") as f:
            w = IncrementalPdfFileWriter(f)
            fields.append_signature_field(
                w,
                sig_field_spec=SigFieldSpec(
                    sig_field_name="Signature1",
                    box=self.bbox,
                ),
            )

            with open(output_pdf_path, "wb") as final_output:
                self.pdf_signer.sign_pdf(w, output=final_output)


if __name__ == "__main__":
    bs = BulkSigner()
    bs.sign_one(
        input_pdf_path="unsigned/test.pdf",
        output_pdf_path="signed/test-signed.pdf",
    )