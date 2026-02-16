from pyhanko.sign import signers
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.pdf_utils import layout
import os


def sign_pdf(
    input_path,
    output_path,
    p12_path,
    passphrase,
    page_number=1,
    x1=None,
    y1=None,
    x2=None,
    y2=None,
):
    """
    Signs a PDF using a PKCS12 certificate.
    """
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Load the signer from the .pb12 (PKCS12) file
    signer = signers.SimpleSigner.load_pkcs12(
        p12_path,
        passphrase=passphrase.encode() if isinstance(passphrase, str) else passphrase,
    )

    with open(input_path, "rb") as inf:
        writer = IncrementalPdfFileWriter(inf, strict=False)

        with open(output_path, "wb") as outf:
            signers.sign_pdf(
                writer,
                signers.PdfSignatureMetadata(
                    field_name="Signature1",
                    reason="Digitally signed by DigiSigner",
                    location="Kathmandu, Nepal",
                ),
                signer=signer,
                output=outf,
                new_field_spec=SigFieldSpec(
                    sig_field_name="Signature1",
                    on_page=page_number - 1 if page_number else 0,
                    box=(x1, y1, x2, y2) if all([x1, y1, x2, y2]) else None,
                ),
            )
    return True


def verify_pdf(pdf_path):
    """
    Verifies all signatures in a PDF file.
    Returns (is_valid, message)
    """
    try:
        with open(pdf_path, "rb") as f:
            r = PdfFileReader(f, strict=False)
            # Find all signatures
            if not r.embedded_signatures:
                return False, "No digital signatures found in the document."

            # Validate all signatures
            valid_signatures = 0
            for sig in r.embedded_signatures:
                status = validate_pdf_signature(sig)
                if status.intact and status.valid:
                    valid_signatures += 1

            if valid_signatures > 0:
                return True, f"Successfully verified {valid_signatures} signature(s)."
            else:
                return (
                    False,
                    "Digital signatures are present but invalid or tampered with.",
                )
    except Exception as e:
        return False, f"Verification failed: {str(e)}"


def get_signature_details(pdf_path):
    """
    Extracts signature details from a PDF file.
    """
    try:
        with open(pdf_path, "rb") as f:
            r = PdfFileReader(f, strict=False)
            results = []
            sigs = list(r.embedded_signatures)
            for sig in sigs:
                signer_info = sig.signer_cert

                signer_name = "Unknown"
                if signer_info:
                    try:
                        signer_name = str(signer_info.subject.human_friendly_name)
                    except AttributeError:
                        try:
                            signer_name = str(signer_info.subject.human_friendly)
                        except AttributeError:
                            signer_name = str(signer_info.subject)

                # Try to get timestamp from multiple locations
                completion_time = "N/A"
                if hasattr(sig, "self_signed_timestamp") and sig.self_signed_timestamp:
                    completion_time = sig.self_signed_timestamp.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                else:
                    # Fallback to signing time from signature object if available
                    m_time = sig.sig_object.get("/M")
                    if m_time:
                        completion_time = str(m_time)

                results.append(
                    {
                        "field_name": sig.field_name,
                        "signer": signer_name,
                        "reason": str(sig.sig_object.get("/Reason", "N/A")),
                        "time": completion_time,
                    }
                )
            return results
    except Exception as e:
        print(f"Extraction error: {e}")
        return []


def get_signature_positions(pdf_path):
    """
    Extracts the visual positions (page and bounding box) of all signatures.
    Returns a list of dicts: {'field_name': str, 'page': int, 'rect': [x1, y1, x2, y2]}
    """
    try:
        positions = []
        with open(pdf_path, "rb") as f:
            r = PdfFileReader(f, strict=False)

            def walk_pages(node):
                if node["/Type"] == "/Page":
                    yield node
                elif node["/Type"] == "/Pages":
                    for kid in node["/Kids"]:
                        yield from walk_pages(kid.get_object())

            pages = list(walk_pages(r.root["/Pages"]))
            for i, page in enumerate(pages):
                if "/Annots" in page:
                    for annot_ref in page["/Annots"]:
                        annot = annot_ref.get_object()
                        if (
                            annot.get("/Subtype") == "/Widget"
                            and annot.get("/FT") == "/Sig"
                        ):
                            # The field name might be in the annotation or the parent
                            field_name = annot.get("/T")
                            rect = annot.get("/Rect")
                            if rect:
                                positions.append(
                                    {
                                        "field_name": (
                                            str(field_name) if field_name else "Unknown"
                                        ),
                                        "page": i + 1,
                                        "rect": [float(x) for x in rect],
                                    }
                                )
        return positions
    except Exception as e:
        print(f"Position extraction error: {e}")
        return []
