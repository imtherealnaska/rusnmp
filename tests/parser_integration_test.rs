use rusnmp::ber::Asn1Tag;
use rusnmp::snmp::message::parse_message;
use rusnmp::snmp::pdu::ErrorStatus;
use rusnmp::snmp::pdu::ObjectSyntax;

const RAW_PACKET: &[u8] = &[
    0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x1c, 0x02,
    0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06,
    0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
];

#[test]
fn test_parse_v2c_get_request() {
    let message = parse_message(RAW_PACKET).unwrap();

    assert_eq!(message.version, 1);
    assert_eq!(message.community, b"public");

    let pdu = message.pdu;
    assert_eq!(pdu.tag, Asn1Tag::GetRequest);
    assert_eq!(pdu.request_id, 1);
    assert_eq!(pdu.error_status, ErrorStatus::NoError);
    assert_eq!(pdu.error_index, 0);

    assert_eq!(pdu.varbinds.len(), 1);

    let varbind = &pdu.varbinds[0];
    let expected_oid: Vec<u32> = vec![1, 3, 6, 1, 2, 1, 1, 1, 0];
    assert_eq!(varbind.oid, expected_oid);

    assert_eq!(varbind.value, ObjectSyntax::Null);
}

const RAW_PACKET_RESPONSE: &[u8] = &[
    0x30, 0x42, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x35, 0x02,
    0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x27, 0x30, 0x25, 0x06,
    0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x04, 0x19, 0x53, 0x61, 0x6d, 0x70, 0x6c,
    0x65, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
    0x74, 0x69, 0x6f, 0x6e,
];

#[test]
fn test_parse_v2c_get_response() {
    let message = parse_message(RAW_PACKET_RESPONSE).unwrap();

    assert_eq!(message.version, 1);
    assert_eq!(message.community, b"public");

    let pdu = message.pdu;
    assert_eq!(pdu.tag, Asn1Tag::GetResponse);
    assert_eq!(pdu.request_id, 1);
    assert_eq!(pdu.error_status, ErrorStatus::NoError);
    assert_eq!(pdu.error_index, 0);

    assert_eq!(pdu.varbinds.len(), 1);

    let varbind = &pdu.varbinds[0];
    let expected_oid: Vec<u32> = vec![1, 3, 6, 1, 2, 1, 1, 1, 0];
    assert_eq!(varbind.oid, expected_oid);

    let expected_value = b"Sample system description";
    match &varbind.value {
        ObjectSyntax::OctetString(val) => {
            assert_eq!(val, expected_value);
        }
        _ => panic!("Expected OctetString, got {:?}", varbind.value),
    }
}
