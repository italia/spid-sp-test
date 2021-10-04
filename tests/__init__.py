from spid_sp_test.metadata_extra import SpidSpMetadataCheckExtra
from tempfile import NamedTemporaryFile


def get_md_check(metadata_url):
    md = SpidSpMetadataCheckExtra(metadata_url=metadata_url)
    md.load()
    return md


def load_metadata(metadata):
    tmp_file = NamedTemporaryFile(suffix=".xml")
    tmp_file.write(metadata)
    tmp_file.seek(0)
    return get_md_check(f"file://{tmp_file.name}")
