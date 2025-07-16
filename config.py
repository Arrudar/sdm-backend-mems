import binascii

# Your custom master key for NTAG 424 DNA
MASTER_KEY = binascii.unhexlify("757bf1693bca463bb529ee1771c1ea09")

# Configuration parameters
DERIVE_MODE = "standard"
REQUIRE_LRP = False

# Parameter names for SDM validation
CTR_PARAM = "ctr"
ENC_FILE_DATA_PARAM = "enc_file_data"
ENC_PICC_DATA_PARAM = "picc_data"
SDMMAC_PARAM = "cmac"
UID_PARAM = "uid"

