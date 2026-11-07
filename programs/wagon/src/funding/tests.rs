//! Tests de unidad de la E/S del registro (`crate::funding`): las ramas que ningún test
//! de punta a punta puede alcanzar (solo este programa asigna la PDA canónica o le da
//! espacio) quedan fijadas aquí con `AccountInfo` sintéticos. `close_account_to` y la
//! rama `ToRecord` de `settle_refund` no se prueban en el host (`realloc` exige el
//! buffer serializado del runtime); las cubre la batería mock (suites 40 a 50).

use super::*;
use anchor_lang::solana_program::system_program;
use crate::state::{FUNDING_KIND_DEPOSIT, FUNDING_KIND_WITHDRAW};

type Buf = Vec<u8>;

fn ai<'a>(
    key: &'a Pubkey,
    owner: &'a Pubkey,
    lamports: &'a mut u64,
    data: &'a mut [u8],
) -> AccountInfo<'a> {
    AccountInfo::new(key, false, true, lamports, data, owner, false, 0)
}

fn record_bytes(session: &Pubkey, bump: u8, generation: u64) -> Buf {
    let rec = FundingRecord {
        session: *session,
        payer: Pubkey::new_unique(),
        refund_to: Pubkey::new_unique(),
        generation,
        kind: FUNDING_KIND_DEPOSIT,
        bump,
        ..Default::default()
    };
    let mut v = Vec::new();
    rec.try_serialize(&mut v).unwrap();
    assert_eq!(v.len(), FundingRecord::LEN);
    v
}

/// `load_record_at` sobre (clave, dueño, datos) debe revertir con `FundingRecordNotCanonical`.
fn no_canonica(key: &Pubkey, owner: &Pubkey, mut data: Buf, session: &Pubkey) {
    let mut lamports = 1u64;
    match load_record_at(&ai(key, owner, &mut lamports, &mut data), session) {
        Err(e) => assert!(format!("{e:?}").contains("FundingRecordNotCanonical"), "{e:?}"),
        Ok(_) => panic!("esperaba FundingRecordNotCanonical"),
    }
}

fn refund_to_check(key: &Pubkey, exec: bool, payer: &Pubkey, authority: &Pubkey) -> Result<()> {
    let (mut l, mut d): (u64, [u8; 0]) = (0, []);
    let a = AccountInfo::new(key, false, true, &mut l, &mut d, &system_program::ID, exec, 0);
    check_refund_to(&a, payer, authority)
}

/// PR 5B: `matched_record` devuelve el registro (y con él su S de salida) SOLO si empareja.
#[test]
fn matched_record_solo_devuelve_el_registro_que_empareja_y_su_s_de_salida() {
    let session = Pubkey::new_unique();
    let (key, bump) = find_record_address(&session);
    let bytes = |generation: u64, kind: u8| -> Buf {
        let rec = FundingRecord {
            session,
            payer: Pubkey::new_unique(),
            refund_to: Pubkey::new_unique(),
            generation,
            kind,
            bump,
            exit_service_usdc: 300_000,
            ..Default::default()
        };
        let mut v = Vec::new();
        rec.try_serialize(&mut v).unwrap();
        assert_eq!(v.len(), FundingRecord::LEN);
        v
    };
    // Emparejado (sesión + generación + tipo): Some con su S y su generación entera.
    let (mut l, mut d) = (1u64, bytes(7, FUNDING_KIND_WITHDRAW));
    let r = matched_record(&ai(&key, &crate::ID, &mut l, &mut d), &session, 7, FUNDING_KIND_WITHDRAW)
        .unwrap()
        .unwrap();
    assert_eq!((r.exit_service_usdc, r.generation), (300_000, 7));
    // Rancio (otra generación), otro tipo o sello legacy 0: None aunque el registro lleve S > 0
    // (ese S nunca se cobra: es de OTRA sesión de la misma pareja).
    for (sealed, kind) in [(8u64, FUNDING_KIND_WITHDRAW), (7, FUNDING_KIND_DEPOSIT), (0, FUNDING_KIND_WITHDRAW)] {
        let (mut l, mut d) = (1u64, bytes(7, FUNDING_KIND_WITHDRAW));
        let got = matched_record(&ai(&key, &crate::ID, &mut l, &mut d), &session, sealed, kind).unwrap();
        assert!(got.is_none(), "sello {sealed} tipo {kind}");
    }
    // Dirección vacía: None (legacy). Otra clave en el hueco: FundingRecordNotCanonical.
    let (mut l0, mut d0): (u64, [u8; 0]) = (0, []);
    assert!(matched_record(&ai(&key, &system_program::ID, &mut l0, &mut d0), &session, 7, FUNDING_KIND_WITHDRAW).unwrap().is_none());
    let otra = Pubkey::new_unique();
    let (mut l2, mut d2) = (1u64, bytes(7, FUNDING_KIND_WITHDRAW));
    match matched_record(&ai(&otra, &crate::ID, &mut l2, &mut d2), &session, 7, FUNDING_KIND_WITHDRAW) {
        Err(e) => assert!(format!("{e:?}").contains("FundingRecordNotCanonical"), "{e:?}"),
        Ok(_) => panic!("esperaba FundingRecordNotCanonical"),
    }
}

#[test]
fn direccion_vacia_es_legacy_con_o_sin_lamports_donados() {
    let session = Pubkey::new_unique();
    let (key, _) = find_record_address(&session);
    for lamports in [0u64, 890_880] {
        let (mut l, mut d): (u64, [u8; 0]) = (lamports, []);
        let a = ai(&key, &system_program::ID, &mut l, &mut d);
        assert!(load_record_at(&a, &session).unwrap().is_none());
    }
}

#[test]
fn registro_valido_se_lee_y_conserva_sus_campos() {
    let session = Pubkey::new_unique();
    let (key, bump) = find_record_address(&session);
    let mut data = record_bytes(&session, bump, 7);
    let mut lamports = 1u64;
    let rec = load_record_at(&ai(&key, &crate::ID, &mut lamports, &mut data), &session)
        .unwrap()
        .unwrap();
    assert_eq!((rec.session, rec.bump, rec.generation, rec.kind), (session, bump, 7, 1));
}

#[test]
fn cualquier_otra_forma_revierte_como_no_canonica() {
    let session = Pubkey::new_unique();
    let (key, bump) = find_record_address(&session);
    let ajena = Pubkey::new_unique();
    // Clave que no es la PDA canónica (aunque el contenido sea un registro perfecto).
    no_canonica(&ajena, &crate::ID, record_bytes(&session, bump, 7), &session);
    // Bump no canónico.
    no_canonica(&key, &crate::ID, record_bytes(&session, bump.wrapping_add(1), 7), &session);
    // Discriminador corrupto.
    let mut mal_disc = record_bytes(&session, bump, 7);
    mal_disc[0] ^= 0xff;
    no_canonica(&key, &crate::ID, mal_disc, &session);
    // Tamaño distinto de 154.
    let mut corto = record_bytes(&session, bump, 7);
    corto.pop();
    no_canonica(&key, &crate::ID, corto, &session);
    // Dueño ajeno con datos, y cuenta del sistema CON datos.
    no_canonica(&key, &ajena, record_bytes(&session, bump, 7), &session);
    no_canonica(&key, &system_program::ID, vec![0u8], &session);
}

#[test]
fn refund_to_solo_payer_o_authority_y_nunca_ejecutable() {
    let (payer, authority) = (Pubkey::new_unique(), Pubkey::new_unique());
    let otro = Pubkey::new_unique();
    assert!(refund_to_check(&payer, false, &payer, &authority).is_ok());
    assert!(refund_to_check(&authority, false, &payer, &authority).is_ok());
    for (key, exec) in [(&otro, false), (&payer, true), (&authority, true)] {
        let e = refund_to_check(key, exec, &payer, &authority).unwrap_err();
        assert!(format!("{e:?}").contains("FundingRefundToNotAllowed"), "{e:?}");
    }
}

#[test]
fn legacy_exige_al_propietario_tambien_cuando_el_registro_no_empareja() {
    // Registro presente pero de otra generación: legacy (motivo 1), destino = propietario,
    // y el registro queda intacto (no se cierra). Con otro destino, revierte.
    let session = Pubkey::new_unique();
    let (key, bump) = find_record_address(&session);
    let (owner, otro) = (Pubkey::new_unique(), Pubkey::new_unique());
    let auth = Pubkey::new_unique();
    let mut rec = record_bytes(&session, bump, 7);
    let (mut lr, mut ls, mut lo, mut lx, mut la) = (1u64, 5u64, 0u64, 0u64, 0u64);
    let mut ds = [0u8; 4];
    let (mut dz, mut dx, mut da): ([u8; 0], [u8; 0], [u8; 0]) = ([], [], []);
    let record = ai(&key, &crate::ID, &mut lr, &mut rec);
    let session_ai = ai(&session, &crate::ID, &mut ls, &mut ds);
    let target_ok = ai(&owner, &system_program::ID, &mut lo, &mut dz);
    settle_refund(&record, &target_ok, &session_ai, &owner, &owner, &auth, &otro, 8, FUNDING_KIND_DEPOSIT, None)
        .unwrap();
    assert_eq!(record.lamports(), 1, "el registro rancio no se toca");
    let target_mal = ai(&otro, &system_program::ID, &mut lx, &mut dx);
    let wd = FUNDING_KIND_WITHDRAW;
    let e = settle_refund(&record, &target_mal, &session_ai, &owner, &owner, &auth, &otro, 8, wd, None)
        .unwrap_err();
    assert!(format!("{e:?}").contains("FundingRefundTargetMismatch"), "{e:?}");
    // El cinturón de la authority (B2) NO se aplica en legacy, ni aunque firme el propietario.
    let target_auth = ai(&auth, &system_program::ID, &mut la, &mut da);
    let e = settle_refund(&record, &target_auth, &session_ai, &owner, &owner, &auth, &owner, 8, wd, None)
        .unwrap_err();
    assert!(format!("{e:?}").contains("FundingRefundTargetMismatch"), "{e:?}");
    // B3: en legacy cobra `legacy_dest` aunque sea distinto del propietario (abort limpio por un
    // tercero: el caller), y el propietario NO puede exigirse a sí mismo en ese caso.
    let (mut lt, mut dt): (u64, [u8; 0]) = (0, []);
    let target_tercero = ai(&otro, &system_program::ID, &mut lt, &mut dt);
    settle_refund(&record, &target_tercero, &session_ai, &otro, &owner, &auth, &otro, 8, wd, None).unwrap();
    let e = settle_refund(&record, &target_ok, &session_ai, &otro, &owner, &auth, &otro, 8, wd, None)
        .unwrap_err();
    assert!(format!("{e:?}").contains("FundingRefundTargetMismatch"), "{e:?}");
}
