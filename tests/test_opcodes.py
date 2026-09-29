"""Opcode tables agree with each other, and the analyzer uses those objects."""

import analyze_capture as ac
import couchbase_opcodes as opcodes


def test_opcode_tables_agree():
    assert ac.OPCODES is opcodes.OPCODES
    assert ac.OPCODE_DESCRIPTIONS is opcodes.OPCODE_DESCRIPTIONS
    assert ac.STATUS is opcodes.STATUS
    assert ac.CLUSTER_OPCODES is opcodes.CLUSTER_OPCODES
    assert ac.NO_REPLY_OPCODES is opcodes.NO_REPLY_OPCODES
    assert ac.MULTI_RESPONSE_OPCODES is opcodes.MULTI_RESPONSE_OPCODES
    assert set(opcodes.OPCODE_DESCRIPTIONS) <= set(opcodes.OPCODES)
    for text in opcodes.CLUSTER_OPCODES:
        assert int(text, 16) in opcodes.OPCODES
    for number in opcodes.NO_REPLY_OPCODES | opcodes.MULTI_RESPONSE_OPCODES:
        assert number in opcodes.OPCODES
    assert all(isinstance(name, str) and name for name in opcodes.OPCODES.values())
    assert all(isinstance(text, str) and text for text in opcodes.OPCODE_DESCRIPTIONS.values())
    assert all(isinstance(text, str) and text for text in opcodes.STATUS.values())
