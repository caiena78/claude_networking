

def test_mask_secrets():
    from helper_common import mask_secrets
    d = {"name": "FW", "authenticationSettings": {"radiusSharedSecret": "x", "enableMultiSecret": "false",
         "keyEncryptionKey": ""}, "snmp": [{"roCommunity": "public"}], "keyInputFormat": "ASCII"}
    m = mask_secrets(d)
    assert m["authenticationSettings"] == {"radiusSharedSecret": "********", "enableMultiSecret": "false",
                                           "keyEncryptionKey": ""}
    assert m["snmp"][0]["roCommunity"] == "********" and m["keyInputFormat"] == "ASCII" and d["snmp"][0]["roCommunity"] == "public"
