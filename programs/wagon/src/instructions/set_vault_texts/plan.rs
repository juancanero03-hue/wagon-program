//! Tabla de decisión de `set_vault_texts` (ceremonia USDC, D8): lógica PURA, sin
//! cuentas ni reloj, para poder fijarla entera con tests de unidad (el validador
//! de la CI no puede adelantar el reloj y probar la ventana cerrada). El handler
//! de `set_vault_texts.rs` solo valida longitudes, llama a `decide_texts` y aplica
//! lo decidido: no hay camino de escritura que no pase por esta tabla.

use crate::constants::{VAULT_DESC_LEN, VAULT_TAGS_LEN, VAULT_TEXTS_WINDOW_SECS};

/// Resultado de la tabla de decisión de `set_vault_texts` (ver `decide_texts`).
#[derive(Debug, PartialEq, Eq)]
pub enum TextsDecision {
    /// Escribir los campos marcados (al menos uno) y emitir el evento.
    Write { desc: bool, tags: bool },
    /// Todo lo dado ya está escrito con ese MISMO contenido: éxito sin efecto.
    NoOp,
    /// Los dos textos vienen vacíos (`VaultTextsEmpty`).
    Empty,
    /// Un campo ya escrito recibe un contenido DISTINTO (`VaultTextsAlreadySet`).
    AlreadySet,
    /// Hay algo que escribir y la ventana venció (`VaultTextsWindowClosed`).
    WindowClosed,
}

fn has_content(bytes: &[u8]) -> bool {
    bytes.iter().any(|b| *b != 0)
}

/// Tabla de decisión completa, sin tocar la cuenta. `given` = buffer recibido ya
/// rellenado a cero; `stored` = el guardado en el vault; «vacío» = todo a cero.
/// Orden: vacío → contenido distinto → nada que escribir → ventana. El contenido
/// distinto es verdad dentro y fuera de la ventana (error más útil) y el reenvío
/// idéntico es no-op sin mirar el reloj.
pub fn decide_texts(
    desc_given: &[u8; VAULT_DESC_LEN],
    tags_given: &[u8; VAULT_TAGS_LEN],
    desc_stored: &[u8; VAULT_DESC_LEN],
    tags_stored: &[u8; VAULT_TAGS_LEN],
    created_at: i64,
    now: i64,
) -> TextsDecision {
    let (dg, tg) = (has_content(desc_given), has_content(tags_given));
    if !dg && !tg {
        return TextsDecision::Empty;
    }
    let (ds, ts) = (has_content(desc_stored), has_content(tags_stored));
    if (dg && ds && desc_given != desc_stored) || (tg && ts && tags_given != tags_stored) {
        return TextsDecision::AlreadySet;
    }
    let (desc, tags) = (dg && !ds, tg && !ts);
    if !desc && !tags {
        return TextsDecision::NoOp;
    }
    if !texts_window_open(created_at, now, VAULT_TEXTS_WINDOW_SECS) {
        return TextsDecision::WindowClosed;
    }
    TextsDecision::Write { desc, tags }
}

/// Ventana de publicación: abierta mientras hayan pasado como mucho `window_secs`
/// desde `created_at` (un reloj por detrás de la creación cuenta como abierta).
pub fn texts_window_open(created_at: i64, now: i64, window_secs: i64) -> bool {
    now.saturating_sub(created_at) <= window_secs
}

#[cfg(test)]
mod tests {
    use super::TextsDecision::{AlreadySet, Empty, NoOp, WindowClosed, Write};
    use super::{decide_texts, texts_window_open};
    use crate::constants::{VAULT_DESC_LEN, VAULT_TAGS_LEN, VAULT_TEXTS_WINDOW_SECS};

    const T0: i64 = 1_800_000_000;
    const IN: i64 = T0 + VAULT_TEXTS_WINDOW_SECS; // último segundo abierto
    const OUT: i64 = T0 + VAULT_TEXTS_WINDOW_SECS + 1; // ventana cerrada

    fn d(s: &str) -> [u8; VAULT_DESC_LEN] {
        let mut b = [0u8; VAULT_DESC_LEN];
        b[..s.len()].copy_from_slice(s.as_bytes());
        b
    }
    fn t(s: &str) -> [u8; VAULT_TAGS_LEN] {
        let mut b = [0u8; VAULT_TAGS_LEN];
        b[..s.len()].copy_from_slice(s.as_bytes());
        b
    }

    #[test]
    fn ventana_de_24h_con_bordes_exactos() {
        assert_eq!(VAULT_TEXTS_WINDOW_SECS, 86_400);
        assert!(texts_window_open(T0, T0, VAULT_TEXTS_WINDOW_SECS));
        assert!(texts_window_open(T0, IN, VAULT_TEXTS_WINDOW_SECS));
        assert!(!texts_window_open(T0, OUT, VAULT_TEXTS_WINDOW_SECS));
        assert!(texts_window_open(T0, T0 - 5, VAULT_TEXTS_WINDOW_SECS), "reloj atrás");
        assert!(!texts_window_open(i64::MIN, i64::MAX, VAULT_TEXTS_WINDOW_SECS), "sin desbordar");
    }

    #[test]
    fn tabla_de_decision_completa() {
        let (z, zt, a, b, x, y) = (d(""), t(""), d("a"), d("b"), t("x"), t("y"));
        // Vacío gana a todo, también fuera de la ventana (un "\0" ya llega como z).
        assert_eq!(decide_texts(&z, &zt, &z, &zt, T0, IN), Empty);
        assert_eq!(decide_texts(&z, &zt, &a, &x, T0, OUT), Empty);
        // Nada guardado: se escribe lo dado dentro de la ventana (y con el reloj atrás).
        assert_eq!(decide_texts(&a, &x, &z, &zt, T0, IN), Write { desc: true, tags: true });
        assert_eq!(decide_texts(&a, &zt, &z, &zt, T0, T0 - 5), Write { desc: true, tags: false });
        assert_eq!(decide_texts(&z, &x, &z, &zt, T0, IN), Write { desc: false, tags: true });
        // Por campo: lo guardado idéntico no se reescribe; lo nuevo sí.
        assert_eq!(decide_texts(&a, &x, &a, &zt, T0, IN), Write { desc: false, tags: true });
        assert_eq!(decide_texts(&a, &x, &z, &x, T0, IN), Write { desc: true, tags: false });
        // Reenvío idéntico: no-op dentro y FUERA de la ventana (también parcial).
        assert_eq!(decide_texts(&a, &x, &a, &x, T0, IN), NoOp);
        assert_eq!(decide_texts(&a, &x, &a, &x, T0, OUT), NoOp);
        assert_eq!(decide_texts(&a, &zt, &a, &x, T0, OUT), NoOp);
        // Contenido distinto en un campo escrito: AlreadySet antes que la ventana,
        // aunque el otro campo sea nuevo (no se escribe nada).
        assert_eq!(decide_texts(&b, &zt, &a, &zt, T0, IN), AlreadySet);
        assert_eq!(decide_texts(&a, &y, &a, &x, T0, IN), AlreadySet);
        assert_eq!(decide_texts(&b, &x, &a, &zt, T0, IN), AlreadySet);
        assert_eq!(decide_texts(&b, &zt, &a, &zt, T0, OUT), AlreadySet);
        // Ventana cerrada: TODA escritura, también la mezcla idéntico + nuevo.
        assert_eq!(decide_texts(&a, &x, &z, &zt, T0, OUT), WindowClosed);
        assert_eq!(decide_texts(&a, &x, &a, &zt, T0, OUT), WindowClosed);
        assert_eq!(decide_texts(&z, &x, &z, &zt, T0, OUT), WindowClosed);
    }
}
