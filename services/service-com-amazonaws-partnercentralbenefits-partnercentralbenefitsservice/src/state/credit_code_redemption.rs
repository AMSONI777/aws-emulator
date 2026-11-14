// SPDX-License-Identifier: CC0-1.0

//! Redeeming one of the promotional credit codes this service has ISSUED.
//!
//! A credit code is issued against a benefit allocation HERE — the modelled
//! `CreditCode$AwsCreditCode` is "the actual credit code string that can be redeemed in the
//! AWS billing console" — and it is APPLIED to a bill THERE, on the billing service's
//! surface. So the record stays this service's own (every read still reports it from
//! `state.rs`), and this module is the one place that SPENDS one: the redeemer is an
//! in-process caller holding the shared engine, because no modelled operation of this
//! service redeems a code.

use super::*;

/// The terms of the promotion a redeemed promotional credit code names, as the service
/// that applies the credit to a bill needs them.
///
/// What the redeeming service is handed is the code's own record: the account it was issued
/// to, what it is worth, how long the promotion stays valid, and what the benefit it came
/// from is called.
#[derive(Debug, Clone)]
pub struct RedeemedCreditCode {
    /// The account the code was issued to, which is the account the credit belongs to.
    pub aws_account_id: String,
    /// What the code is worth ([`AllocatedCreditCode::value`]).
    pub value: Money,
    /// The end of the promotion's validity period: the code's own `ExpiresAt`.
    pub expires_at_millis: i64,
    /// How the benefit allocation the code was issued against describes itself.
    pub description: String,
}

/// Why a promotional credit code cannot be redeemed.
///
/// One variant per state a stored code can be in that is not redeemable, so the redeeming
/// service can word its own refusal from the record rather than guessing — and a code this
/// service never issued is one case, not three, so a caller cannot learn from the refusal
/// which account a code it does not hold was issued to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditCodeDefect {
    /// No code of that text was issued to the account presenting it.
    NotIssued,
    /// The code was issued to that account and has already been redeemed.
    AlreadyRedeemed,
    /// The code's own `ExpiresAt` has passed, so it can no longer be redeemed.
    Expired,
}

impl ComAmazonawsPartnercentralbenefitsPartnercentralbenefitsserviceState {
    /// Redeem the promotional credit code `code` on behalf of `account_id`, and answer the
    /// terms of the promotion it names.
    ///
    /// A code this service issued is redeemable exactly ONCE: redeeming it moves it to
    /// [`ALLOCATION_STATUS_FULFILLED`], which is what that status says of a code ("once it
    /// has been" redeemed, see [`AllocatedCreditCode::status`]), so a second presentation
    /// of the same code is refused [`CreditCodeDefect::AlreadyRedeemed`]. Every expiry the
    /// clock has already made due is materialised FIRST, so a code past its own
    /// `ExpiresAt` is refused [`CreditCodeDefect::Expired`] rather than redeemed — the same
    /// rule a read of the allocation applies ([`Self::expire_allocations_due`]).
    ///
    /// The lookup spans every catalog, because a code identifies itself: it carries no
    /// catalog, and the caller presenting one holds nothing but the code's text.
    ///
    /// No modelled operation of THIS service reaches it, and deliberately so: a
    /// promotional credit code is redeemed against an AWS bill, which is the billing
    /// service's surface and not this one's, so the redeemer is an in-process caller
    /// holding the shared engine. The codes stay this service's own records — every read of
    /// one still reports it from here, redeemed status included.
    pub fn redeem_credit_code(
        &mut self,
        code: &str,
        account_id: &str,
        now_millis: i64,
    ) -> Result<RedeemedCreditCode, CreditCodeDefect> {
        for catalog in self.catalogs.keys().cloned().collect::<Vec<String>>() {
            self.expire_allocations_due(&catalog, now_millis);
        }
        let mut outcome = Err(CreditCodeDefect::NotIssued);
        'search: for catalog in self.catalogs.values_mut() {
            for allocation in catalog.allocations.values_mut() {
                let Some(AllocationFulfillment::Credits { codes, .. }) =
                    allocation.fulfillment.as_mut()
                else {
                    continue;
                };
                let Some(issued) = codes
                    .iter_mut()
                    .find(|issued| issued.code == code && issued.aws_account_id == account_id)
                else {
                    continue;
                };
                let status = issued.status.clone();
                let terms = match status.as_str() {
                    ALLOCATION_STATUS_ACTIVE => {
                        issued.status = ALLOCATION_STATUS_FULFILLED.to_string();
                        Some((
                            issued.aws_account_id.clone(),
                            issued.value.clone(),
                            issued.expires_at_millis,
                        ))
                    }
                    ALLOCATION_STATUS_FULFILLED => {
                        outcome = Err(CreditCodeDefect::AlreadyRedeemed);
                        None
                    }
                    // Every other status a stored code can carry is the one an expiry
                    // leaves behind ([`AllocatedCreditCode::expire_due`]).
                    _ => {
                        outcome = Err(CreditCodeDefect::Expired);
                        None
                    }
                };
                if let Some((aws_account_id, value, expires_at_millis)) = terms {
                    outcome = Ok(RedeemedCreditCode {
                        aws_account_id,
                        value,
                        expires_at_millis,
                        // The promotion describes itself as the allocation it was issued
                        // against does. Read only once a code has matched, so the walk to
                        // it allocates nothing.
                        description: allocation
                            .description
                            .clone()
                            .unwrap_or_else(|| allocation.name.clone()),
                    });
                    allocation.updated_at_millis =
                        bump_millis(allocation.updated_at_millis, now_millis);
                }
                break 'search;
            }
        }
        outcome
    }
}
