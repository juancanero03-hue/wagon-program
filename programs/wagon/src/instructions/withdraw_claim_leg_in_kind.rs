//! `withdraw_claim_leg_in_kind` — ceremonia #39 (C-B, P5'). SUSTITUYE a la
//! renuncia (`withdraw_renounce_leg`), que era la fuente de B-1 y B-2.
//!
//! Una pata de retiro que no se puede vender (token deslistado, sin ruta de
//! Jupiter, o el vault sostenido en un status que bloquea la venta) se PAGA EN
//! ESPECIE al inversor: los tokens de su hucha van a SU propia ATA. Es
//! value-neutral (la hucha contiene exactamente el slice pro-rata que el init
//! movió del vault, y `total_shares` ya se decrementó allí), así que NO destruye
//! valor del inversor ni mueve el NAV/share de los co-inversores. El caller NO
//! elige el destino (se deriva de `investor`), así que un tercero que lo dispare
//! gana CERO — el incentivo del canal de confiscación de la renuncia desaparece.
//!
//! Marca la pata `legs_completed` + `legs_swept` (drena Y cierra la hucha, como
//! el barrido) y pone `sold = 1` INCONDICIONAL: cobrar COMPROMETE a asentar
//! igual que vender (si no, cobrar todas las patas + abort re-acuñaría shares =
//! el doble pago). Así una sesión alcanza terminal SIN pasar por
//! `withdraw_sweep_batch` (y sin su gate de status) → el creador pierde la
//! palanca del congelamiento (B-2).
//!
//! SIN VaultGuard, SIN gate de status, SIN CPI a Jupiter, SIN oráculo — por eso
//! es la salida que el creador NO puede bloquear congelando el vault.
//!
//! Autorización (refinamiento ① acotado, 2026-07-22): `WITHDRAW_INKIND_TIMEOUT_SECS`
//! (24 h) para CUALQUIERA, el inversor incluido; un TERCERO además exige sesión
//! COMPROMETIDA (`sold == 1`) para que no pueda elegirle al inversor la forma de
//! cobrar. El plazo hace que deje de ser un atajo para evadir la comisión de
//! éxito, y al NO exigir `sold` al inversor no puede dejar a nadie sin salida.
//! Ver el razonamiento largo en el gate del handler.
//!
//! # remaining_accounts layout
//! Por cada leg en `leg_indices`: `[mint, escrow_ata, investor_ata]`.

use anchor_lang::prelude::*;
use anchor_spl::token::{spl_token, Token};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::WithdrawLegClaimedInKind;
use crate::state::withdraw_session::WITHDRAW_INKIND_TIMEOUT_SECS;
use crate::state::WithdrawSession;
use crate::token_io::{
    close_token_account_signed, derive_live_ata, read_mint_decimals, read_token_amount,
    transfer_checked_signed, verify_token_account, TOKEN_2022_PROGRAM_ID,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct WithdrawClaimLegInKindArgs {
    pub leg_indices: Vec<u8>,
}

#[derive(Accounts)]
pub struct WithdrawClaimLegInKind<'info> {
    /// El inversor a cualquier hora; un tercero solo tras 24 h sobre una sesión
    /// comprometida. Paga la tx; nunca recibe fondos.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinneado a `session.investor` por el `has_one`. Recibe los tokens
    /// (a su ATA derivada) y los rents de las huchas cerradas.
    #[account(mut)]
    pub investor: UncheckedAccount<'info>,

    /// CHECK: SOLO seeds del PDA de sesión (pinneado por `has_one`). NO se carga
    /// VaultGuard, NO se lee el status — es lo que quita al creador la palanca.
    pub vault: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [
            WITHDRAW_SESSION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump = withdraw_session.bump,
        has_one = investor @ WagonError::WithdrawSessionWrongInvestor,
        has_one = vault @ WagonError::WithdrawSessionWrongVault,
    )]
    pub withdraw_session: Box<Account<'info, WithdrawSession>>,

    pub token_program: Program<'info, Token>,

    /// CHECK: pubkey verificada == Token-2022 program id. Para patas cuyo mint
    /// vive en Token-2022 (xStocks, MetaDAO); ignorado en otro caso.
    pub token_program_2022: UncheckedAccount<'info>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, WithdrawClaimLegInKind<'info>>,
    args: WithdrawClaimLegInKindArgs,
) -> Result<()> {
    // ---- Validate batch shape ----------------------------------------------
    require!(!args.leg_indices.is_empty(), WagonError::EmptyBatch);
    require!(
        args.leg_indices.len() <= MAX_SWEEP_LEGS_PER_BATCH,
        WagonError::BatchTooLarge
    );
    require_keys_eq!(
        ctx.accounts.token_program_2022.key(),
        TOKEN_2022_PROGRAM_ID,
        WagonError::InvalidJupiterRoute
    );

    let session = &ctx.accounts.withdraw_session;

    // Una sesión en abort ya devolvió sus huchas al vault (o las está devolviendo);
    // pagar en especie ahora chocaría con el re-acuñado del abort.
    require!(session.aborting == 0, WagonError::WithdrawSessionAborting);

    // ---- Autorización: el RELOJ para todos; el tercero además, sesión vendida --
    // Refinamiento ① (ronda v3), en su forma ACOTADA. El cobro en especie es una
    // VÁLVULA DE EMERGENCIA para una pata sin comprador, no un camino de salida.
    // Sin candado, el inversor podía hacer en UNA sola tx: init → cobrar TODAS las
    // patas en especie → settle con `usdc_from_swaps == 0` → `profit_signed < 0` →
    // `perf_fee == 0`, volviendo OPCIONAL la comisión de éxito (el settle solo
    // cobra sobre el USDC de las ventas).
    //
    // El candado es SOLO EL RELOJ, deliberadamente. La versión que además exigía
    // `sold == 1` al inversor se DESCARTÓ (decisión de Juan, 2026-07-22) porque
    // creaba un círculo vicioso: los dos únicos sitios que ponen `sold` son la
    // venta —vetada mientras el creador sostenga `status == 4`, que puede
    // re-encadenar— y este claim, que ya exigiría `sold`. Bajo congelamiento el
    // inversor no podría vender NI cobrar en especie: se quedaría sin salida CON
    // VALOR (solo deshacer) = B-2 por la puerta de atrás. Con el reloj a secas esa
    // vía queda SIEMPRE abierta: esta instrucción no lee `status`, así que a las
    // 24 h se sale pase lo que pase. La fricción cumple su papel (deja de ser un
    // atajo cómodo) sin poder atrapar a nadie.
    //
    // ⚠️ El programa NO PUEDE verificar que la pata sea invendible: la liquidez
    // vive en Jupiter (fuera de la cadena) y una tx fallida se revierte sin dejar
    // rastro. El plazo es el PROXY de "lo has intentado y sigues sin poder salir".
    // La restricción de verdad a la válvula la pone el frontend (solo ofrece el
    // botón cuando la venta ha fallado); no es barrera de seguridad, pero cubre a
    // todos los usuarios reales. Cerrar el hueco de verdad = cobrar comisión
    // TAMBIÉN sobre lo retirado en especie, lo que exige valorar los tokens
    // (oráculo en la ruta de salida) y reabre la decisión sellada de que el retiro
    // nunca se atasque → tarea propia, fuera de esta ceremonia.
    let now = Clock::get()?.unix_timestamp;
    require!(
        now.saturating_sub(session.created_at) > WITHDRAW_INKIND_TIMEOUT_SECS,
        WagonError::WithdrawInKindTooEarly
    );
    let by_third_party = ctx.accounts.caller.key() != session.investor;
    // Anti-grifado: un TERCERO solo sobre una sesión ya COMPROMETIDA. Sin esto
    // podría forzar la salida EN ESPECIE de un inversor que quería vender a USDC
    // (los tokens van a la ATA derivada del inversor, así que el tercero no gana
    // nada — pero le elegiría la forma de cobrar, y eso ya es daño suficiente).
    require!(
        !by_third_party || session.sold == 1,
        WagonError::WithdrawInKindTooEarly
    );

    // ---- Session PDA signer seeds ------------------------------------------
    let vault_key = ctx.accounts.vault.key();
    let session_key = session.key();
    let investor_pk = session.investor;
    let session_ai = ctx.accounts.withdraw_session.to_account_info();
    let investor_ai = ctx.accounts.investor.to_account_info();
    let session_bump_arr = [session.bump];
    let seeds: &[&[u8]] = &[
        WITHDRAW_SESSION_SEED,
        vault_key.as_ref(),
        investor_pk.as_ref(),
        &session_bump_arr,
    ];
    let signer_seeds: &[&[&[u8]]] = &[seeds];

    // ---- Walk the [mint, escrow, investor_ata] triples ---------------------
    let remaining = ctx.remaining_accounts;
    require!(
        remaining.len() == 3 * args.leg_indices.len(),
        WagonError::InvalidJupiterRoute
    );

    let sweepable_mask = session.sweepable_mask();
    let legs_swept = session.legs_swept;
    let leg_count = session.leg_count;
    let leg_mints = session.leg_mints;

    let mut new_completed: u16 = 0;
    let mut new_swept: u16 = 0;
    let mut new_in_kind: u16 = 0;
    for (pos, &leg_idx) in args.leg_indices.iter().enumerate() {
        require!(
            (leg_idx as usize) < (leg_count as usize),
            WagonError::LegIndexOutOfRange
        );
        let bit = 1u16 << leg_idx;
        // Una pata trivial (USDC/peso 0) no tiene hucha; nada que cobrar.
        require!((sweepable_mask & bit) != 0, WagonError::LegNotSweepable);
        require!(
            (legs_swept & bit) == 0 && (new_swept & bit) == 0,
            WagonError::LegNotSweepable
        );

        let mint_ai = &remaining[3 * pos];
        let escrow_ai = &remaining[3 * pos + 1];
        let dest_ai = &remaining[3 * pos + 2];

        // Mint desde el snapshot del init (NO la tabla viva). NO se re-verifica
        // Tier B: el mint deslistado/peligroso es justo el que hay que evacuar.
        let leg_mint = leg_mints[leg_idx as usize];
        require_keys_eq!(mint_ai.key(), leg_mint, WagonError::AllocMintMismatch);

        let token_prog_id = *mint_ai.owner;
        require_keys_eq!(
            escrow_ai.key(),
            derive_live_ata(&session_key, &leg_mint, &token_prog_id),
            WagonError::EscrowAtaMismatch
        );
        verify_token_account(escrow_ai, &leg_mint, &session_key)?;

        // DESTINO = ATA canónica del INVERSOR (el caller NO lo elige). Es lo que
        // hace el pago value-neutral y sin incentivo para un tercero.
        require_keys_eq!(
            dest_ai.key(),
            derive_live_ata(&investor_pk, &leg_mint, &token_prog_id),
            WagonError::LegDestAtaMismatch
        );
        verify_token_account(dest_ai, &leg_mint, &investor_pk)?;

        let prog_ai = if token_prog_id == spl_token::ID {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        };

        let amount = read_token_amount(escrow_ai)?;
        if amount > 0 {
            let decimals = read_mint_decimals(mint_ai)?;
            transfer_checked_signed(
                &prog_ai,
                escrow_ai,
                mint_ai,
                dest_ai,
                &session_ai,
                signer_seeds,
                amount,
                decimals,
            )?;
        }
        // Cierra la hucha vaciada; rent → inversor.
        close_token_account_signed(&prog_ai, escrow_ai, &investor_ai, &session_ai, signer_seeds)?;

        new_completed |= bit;
        new_swept |= bit;
        new_in_kind |= bit;

        emit!(WithdrawLegClaimedInKind {
            vault: vault_key,
            investor: investor_pk,
            leg_index: leg_idx,
            mint: leg_mint,
            amount,
            by_third_party,
        });
    }

    // ---- Persist ------------------------------------------------------------
    let session = &mut ctx.accounts.withdraw_session;
    session.legs_completed |= new_completed;
    session.legs_swept |= new_swept;
    session.in_kind_mask |= new_in_kind;
    // ⚠️ INCONDICIONAL: cobrar COMPROMETE a asentar. Sin esta línea, cobrar todas
    // las patas + abort re-acuñaría las shares completas = el doble pago (test 1).
    session.sold = 1;

    Ok(())
}
