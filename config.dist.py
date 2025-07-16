import binascii

# used for derivation of per-tag keys
DERIVE_MODE = "standard"
MASTER_KEY = binascii.unhexlify("757bf1693bca463bb529ee1771c1ea09")

# for encrypted mirroring
ENC_FILE_DATA_PARAM = "enc_file_data"
ENC_PICC_DATA_PARAM = "picc_data"


# for plaintext mirroring
UID_PARAM = "uid"
CTR_PARAM = "ctr"

# always applied
SDMMAC_PARAM = "cmac"

# accept only SDM using LRP, disallow usage of AES
REQUIRE_LRP = False

