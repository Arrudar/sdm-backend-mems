import binascii
import os

DERIVE_MODE = os.environ.get("DERIVE_MODE", "standard")
MASTER_KEY = binascii.unhexlify(os.environ.get("MASTER_KEY", "757bf1693bca463bb529ee1771c1ea09"))

ENC_PICC_DATA_PARAM = os.environ.get("ENC_PICC_DATA_PARAM", "picc_data")
ENC_FILE_DATA_PARAM = os.environ.get("ENC_FILE_DATA_PARAM", "enc")

UID_PARAM = os.environ.get("UID_PARAM", "uid")
CTR_PARAM = os.environ.get("CTR_PARAM", "ctr")

SDMMAC_PARAM = os.environ.get("SDMMAC_PARAM", "cmac")

REQUIRE_LRP = os.environ.get("REQUIRE_LRP", "0") == "1"
