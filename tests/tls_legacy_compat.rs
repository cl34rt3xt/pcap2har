use pcap2har::tls::{ClientSecrets, TlsSecrets, TrafficSecrets};
use std::collections::HashMap;

#[test]
fn legacy_literals_and_public_mutations_drive_tls_secret_lookups() {
    let random = "ab".repeat(32);
    let client_random = [0xab; 32];
    let mut secrets = TlsSecrets {
        client_randoms: HashMap::from([(
            random.clone(),
            ClientSecrets {
                master_secret: Some(vec![0x11; 48]),
            },
        )]),
        traffic_secrets: HashMap::from([(
            random.clone(),
            TrafficSecrets {
                client_handshake_traffic_secret: Some(vec![0x22; 32]),
                server_handshake_traffic_secret: Some(vec![0x33; 32]),
                client_traffic_secret_0: Some(vec![0x44; 32]),
                server_traffic_secret_0: Some(vec![0x55; 32]),
                exporter_secret: Some(vec![0x66; 32]),
            },
        )]),
    };

    assert_eq!(secrets.legacy_master(&client_random), Some(&[0x11; 48][..]));
    assert_eq!(
        secrets
            .traffic(&client_random)
            .unwrap()
            .client_traffic_secret_0
            .as_deref(),
        Some(&[0x44; 32][..])
    );

    secrets
        .client_randoms
        .get_mut(&random)
        .unwrap()
        .master_secret = Some(vec![0x77; 48]);
    secrets
        .traffic_secrets
        .get_mut(&random)
        .unwrap()
        .client_traffic_secret_0 = Some(vec![0x88; 32]);
    let conflicting_keylog = format!(
        "CLIENT_RANDOM {random} {}\nCLIENT_TRAFFIC_SECRET_0 {random} {}\n",
        "99".repeat(48),
        "aa".repeat(32),
    );
    secrets.parse_keylog(conflicting_keylog.as_bytes());

    assert_eq!(secrets.legacy_master(&client_random), Some(&[0x77; 48][..]));
    assert_eq!(
        secrets
            .traffic(&client_random)
            .unwrap()
            .client_traffic_secret_0
            .as_deref(),
        Some(&[0x88; 32][..])
    );
}
