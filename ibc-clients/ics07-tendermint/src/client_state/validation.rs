use ibc_client_tendermint_types::{
    ClientState as ClientStateType, ConsensusState as ConsensusStateType, Header as TmHeader,
    Misbehaviour as TmMisbehaviour, TENDERMINT_HEADER_TYPE_URL, TENDERMINT_MISBEHAVIOUR_TYPE_URL,
};
use ibc_core_client::context::client_state::{ClientStateCommon, ClientStateValidation};
use ibc_core_client::context::{Convertible, ExtClientValidationContext};
use ibc_core_client::types::error::{ClientError, UpgradeClientError};
use ibc_core_client::types::Status;
use ibc_core_commitment_types::commitment::{
    CommitmentPrefix, CommitmentProofBytes, CommitmentRoot,
};
use ibc_core_commitment_types::error::CommitmentError;
use ibc_core_commitment_types::merkle::{MerklePath, MerkleProof};
use ibc_core_commitment_types::proto::ics23::{HostFunctionsManager, HostFunctionsProvider};
use ibc_core_commitment_types::specs::ProofSpecs;
use ibc_core_host::types::identifiers::ClientId;
use ibc_core_host::types::path::{
    ClientConsensusStatePath, Path, PathBytes, UpgradeClientStatePath, UpgradeConsensusStatePath,
};
use ibc_primitives::prelude::*;
use ibc_primitives::proto::Any;
use ibc_primitives::ToVec;
use tendermint::crypto::default::Sha256;
use tendermint::crypto::Sha256 as Sha256Trait;
use tendermint::merkle::MerkleHash;
use tendermint_light_client_verifier::{ProdVerifier, Verifier};

use super::{
    check_for_misbehaviour_on_misbehavior, check_for_misbehaviour_on_update,
    consensus_state_status, ClientState,
};
use crate::client_state::{verify_header, verify_misbehaviour};
use crate::consensus_state::ConsensusState as TmConsensusState;

impl<V> ClientStateValidation<V> for ClientState
where
    V: ExtClientValidationContext,
    ConsensusStateType: Convertible<V::ConsensusStateRef>,
    <ConsensusStateType as TryFrom<V::ConsensusStateRef>>::Error: Into<ClientError>,
{
    /// The default verification logic exposed by ibc-rs simply delegates to a
    /// standalone `verify_client_message` function. This is to make it as
    /// simple as possible for those who merely need the default
    /// [`ProdVerifier`] behaviour, as well as those who require custom
    /// verification logic.
    ///
    /// In a situation where the Tendermint [`ProdVerifier`] doesn't provide the
    /// desired outcome, users should define a custom verifier struct and then
    /// implement the [`Verifier`] trait for it.
    ///
    /// In order to wire up the custom verifier, create a newtype `ClientState`
    /// wrapper similar to [`ClientState`] and implement all client state traits
    /// for it. For method implementation, the simplest way is to import and
    /// call their analogous standalone versions under the
    /// [`crate::client_state`] module, unless bespoke logic is desired for any
    /// of those functions. Then, when it comes to implementing the
    /// `verify_client_message` method, use the [`verify_client_message`]
    /// function and pass your custom verifier object as the `verifier`
    /// parameter.
    fn verify_client_message(
        &self,
        ctx: &V,
        client_id: &ClientId,
        client_message: Any,
    ) -> Result<(), ClientError> {
        verify_client_message::<V, Sha256>(
            self.inner(),
            ctx,
            client_id,
            client_message,
            &ProdVerifier::default(),
        )
    }

    fn check_for_misbehaviour(
        &self,
        ctx: &V,
        client_id: &ClientId,
        client_message: Any,
    ) -> Result<bool, ClientError> {
        check_for_misbehaviour(self.inner(), ctx, client_id, client_message)
    }

    fn status(&self, ctx: &V, client_id: &ClientId) -> Result<Status, ClientError> {
        status(self.inner(), ctx, client_id)
    }

    fn check_substitute(&self, _ctx: &V, substitute_client_state: Any) -> Result<(), ClientError> {
        check_substitute::<V>(self.inner(), substitute_client_state)
    }

    fn verify_upgrade_client(
        &self,
        _ctx: &V,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
        proof_upgrade_client: CommitmentProofBytes,
        proof_upgrade_consensus_state: CommitmentProofBytes,
        root: &CommitmentRoot,
    ) -> Result<(), ClientError> {
        let last_height = self.latest_height().revision_height();

        // The client state's upgrade path vector needs to parsed into a tuple in the form
        // of `(upgrade_path_prefix, upgrade_path)`. Given the length of the client
        // state's upgrade path vector, the following determinations are made:
        // 1: The commitment prefix is left empty and the upgrade path is used as-is.
        // 2: The commitment prefix and upgrade path are both taken as-is.
        let upgrade_path = &self.inner().upgrade_path;
        let (upgrade_path_prefix, upgrade_path) = match upgrade_path.len() {
            0 => {
                return Err(UpgradeClientError::MissingUpgradePath.into());
            }
            1 => (CommitmentPrefix::empty(), upgrade_path[0].clone()),
            2 => (
                upgrade_path[0].as_bytes().to_vec().into(),
                upgrade_path[1].clone(),
            ),
            _ => {
                return Err(UpgradeClientError::InvalidUpgradePath {
                    description: "upgrade path is too long".to_string(),
                }
                .into());
            }
        };

        let upgrade_client_path_bytes =
            self.serialize_path(Path::UpgradeClientState(UpgradeClientStatePath {
                upgrade_path: upgrade_path.clone(),
                height: last_height,
            }))?;

        let upgrade_consensus_path_bytes =
            self.serialize_path(Path::UpgradeConsensusState(UpgradeConsensusStatePath {
                upgrade_path,
                height: last_height,
            }))?;

        verify_upgrade_client::<HostFunctionsManager>(
            self.inner(),
            upgraded_client_state,
            upgraded_consensus_state,
            proof_upgrade_client,
            proof_upgrade_consensus_state,
            upgrade_path_prefix,
            upgrade_client_path_bytes,
            upgrade_consensus_path_bytes,
            root,
        )
    }

    fn verify_membership_raw(
        &self,
        _ctx: &V,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        path: PathBytes,
        value: Vec<u8>,
    ) -> Result<(), ClientError> {
        verify_membership::<HostFunctionsManager>(
            &self.inner().proof_specs,
            prefix,
            proof,
            root,
            path,
            value,
        )
    }

    fn verify_non_membership_raw(
        &self,
        _ctx: &V,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        path: PathBytes,
    ) -> Result<(), ClientError> {
        verify_non_membership::<HostFunctionsManager>(
            &self.inner().proof_specs,
            prefix,
            proof,
            root,
            path,
        )
    }
}

/// Verify the client message as part of the client state validation process.
///
/// Note that this function is typically implemented as part of the
/// [`ClientStateValidation`] trait, but has been made a standalone function in
/// order to make the ClientState APIs more flexible. It mostly adheres to the
/// same signature as the `ClientStateValidation::verify_client_message`
/// function, except for an additional `verifier` parameter that allows users
/// who require custom verification logic to easily pass in their own verifier
/// implementation.
pub fn verify_client_message<V, H>(
    client_state: &ClientStateType,
    ctx: &V,
    client_id: &ClientId,
    client_message: Any,
    verifier: &impl Verifier,
) -> Result<(), ClientError>
where
    V: ExtClientValidationContext,
    ConsensusStateType: Convertible<V::ConsensusStateRef>,
    <ConsensusStateType as TryFrom<V::ConsensusStateRef>>::Error: Into<ClientError>,
    H: MerkleHash + Sha256Trait + Default,
{
    match client_message.type_url.as_str() {
        TENDERMINT_HEADER_TYPE_URL => {
            let header = TmHeader::try_from(client_message)?;
            verify_header::<V, H>(
                ctx,
                &header,
                client_id,
                client_state.chain_id(),
                &client_state.as_light_client_options()?,
                verifier,
            )
        }
        TENDERMINT_MISBEHAVIOUR_TYPE_URL => {
            let misbehaviour = TmMisbehaviour::try_from(client_message)?;
            verify_misbehaviour::<V, H>(
                ctx,
                &misbehaviour,
                client_id,
                client_state.chain_id(),
                &client_state.as_light_client_options()?,
                verifier,
            )
        }
        _ => Err(ClientError::InvalidUpdateClientMessage),
    }
}

/// Check for misbehaviour on the client state as part of the client state
/// validation process.
///
/// Note that this function is typically implemented as part of the
/// [`ClientStateValidation`] trait, but has been made a standalone function
/// in order to make the ClientState APIs more flexible.
///
/// This method covers the following cases:
///
/// 1 - fork:
/// Assumes at least one consensus state before the fork point exists. Let
/// existing consensus states on chain B be: [Sn,.., Sf, Sf-1, S0] with
/// `Sf-1` being the most recent state before the fork. Chain A is queried for
/// a header `Hf'` at `Sf.height` and if it is different from the `Hf` in the
/// event for the client update (the one that has generated `Sf` on chain),
/// then the two headers are included in the evidence and submitted. Note
/// that in this case the headers are different but have the same height.
///
/// 2 - BFT time violation for unavailable header (a.k.a. Future Lunatic
/// Attack or FLA):
/// Some header with a height that is higher than the latest height on A has
/// been accepted and a consensus state was created on B. Note that this
/// implies that the timestamp of this header must be within the
/// `clock_drift` of the client. Assume the client on B has been updated
/// with `h2`(not present on/ produced by chain A) and it has a timestamp of
/// `t2` that is at most `clock_drift` in the future. Then the latest header
/// from A is fetched, let it be `h1`, with a timestamp of `t1`. If `t1 >=
/// t2` then evidence of misbehavior is submitted to A.
///
/// 3 - BFT time violation for existing headers:
/// Ensure that consensus state times are monotonically increasing with
/// height.
pub fn check_for_misbehaviour<V>(
    client_state: &ClientStateType,
    ctx: &V,
    client_id: &ClientId,
    client_message: Any,
) -> Result<bool, ClientError>
where
    V: ExtClientValidationContext,
    ConsensusStateType: Convertible<V::ConsensusStateRef>,
    <ConsensusStateType as TryFrom<V::ConsensusStateRef>>::Error: Into<ClientError>,
{
    match client_message.type_url.as_str() {
        TENDERMINT_HEADER_TYPE_URL => {
            let header = TmHeader::try_from(client_message)?;
            check_for_misbehaviour_on_update(ctx, header, client_id, &client_state.latest_height)
        }
        TENDERMINT_MISBEHAVIOUR_TYPE_URL => {
            let misbehaviour = TmMisbehaviour::try_from(client_message)?;
            check_for_misbehaviour_on_misbehavior(misbehaviour.header1(), misbehaviour.header2())
        }
        _ => Err(ClientError::InvalidUpdateClientMessage),
    }
}

/// Query the status of the client state.
///
/// Note that this function is typically implemented as part of the
/// [`ClientStateValidation`] trait, but has been made a standalone function
/// in order to make the ClientState APIs more flexible.
pub fn status<V>(
    client_state: &ClientStateType,
    ctx: &V,
    client_id: &ClientId,
) -> Result<Status, ClientError>
where
    V: ExtClientValidationContext,
    ConsensusStateType: Convertible<V::ConsensusStateRef>,
    <ConsensusStateType as TryFrom<V::ConsensusStateRef>>::Error: Into<ClientError>,
{
    if client_state.is_frozen() {
        return Ok(Status::Frozen);
    }

    let latest_consensus_state: ConsensusStateType = {
        match ctx.consensus_state(&ClientConsensusStatePath::new(
            client_id.clone(),
            client_state.latest_height.revision_number(),
            client_state.latest_height.revision_height(),
        )) {
            Ok(cs) => cs.try_into().map_err(Into::into)?,
            // if the client state does not have an associated consensus state for its latest height
            // then it must be expired
            Err(_) => return Ok(Status::Expired),
        }
    };

    // Note: if the `duration_since()` is `None`, indicating that the latest
    // consensus state is in the future, then we don't consider the client
    // to be expired.
    let now = ctx.host_timestamp()?;

    let status = consensus_state_status(
        &latest_consensus_state.into(),
        &now,
        client_state.trusting_period,
    )?;

    Ok(status)
}

/// Check that the subject and substitute client states match as part of
/// the client recovery validation step.
///
/// The subject and substitute client states match if all their respective
/// client state parameters match except for frozen height, latest height,
/// trusting period, and chain ID.
pub fn check_substitute<V>(
    subject_client_state: &ClientStateType,
    substitute_client_state: Any,
) -> Result<(), ClientError>
where
    V: ExtClientValidationContext,
    ConsensusStateType: Convertible<V::ConsensusStateRef>,
{
    let ClientStateType {
        latest_height: _,
        frozen_height: _,
        trusting_period: _,
        chain_id: _,
        allow_update: _,
        trust_level: subject_trust_level,
        unbonding_period: subject_unbonding_period,
        max_clock_drift: subject_max_clock_drift,
        proof_specs: subject_proof_specs,
        upgrade_path: subject_upgrade_path,
    } = subject_client_state;

    let substitute_client_state = ClientStateType::try_from(substitute_client_state)?;

    let ClientStateType {
        latest_height: _,
        frozen_height: _,
        trusting_period: _,
        chain_id: _,
        allow_update: _,
        trust_level: substitute_trust_level,
        unbonding_period: substitute_unbonding_period,
        max_clock_drift: substitute_max_clock_drift,
        proof_specs: substitute_proof_specs,
        upgrade_path: substitute_upgrade_path,
    } = substitute_client_state;

    (subject_trust_level == &substitute_trust_level
        && subject_unbonding_period == &substitute_unbonding_period
        && subject_max_clock_drift == &substitute_max_clock_drift
        && subject_proof_specs == &substitute_proof_specs
        && subject_upgrade_path == &substitute_upgrade_path)
        .then_some(())
        .ok_or(ClientError::FailedToVerifyClientRecoveryStates)
}

/// Perform client-specific verifications and check all data in the new
/// client state to be the same across all valid Tendermint clients for the
/// new chain.
///
/// You can learn more about how to upgrade IBC-connected SDK chains in
/// [this](https://ibc.cosmos.network/main/ibc/upgrades/quick-guide.html)
/// guide.
///
/// Note that this function is typically implemented as part of the
/// [`ClientStateCommon`] trait, but has been made a standalone function
/// in order to make the ClientState APIs more flexible.
#[allow(clippy::too_many_arguments)]
pub fn verify_upgrade_client<H: HostFunctionsProvider>(
    client_state: &ClientStateType,
    upgraded_client_state: Any,
    upgraded_consensus_state: Any,
    proof_upgrade_client: CommitmentProofBytes,
    proof_upgrade_consensus_state: CommitmentProofBytes,
    upgrade_path_prefix: CommitmentPrefix,
    upgrade_client_path_bytes: PathBytes,
    upgrade_consensus_path_bytes: PathBytes,
    root: &CommitmentRoot,
) -> Result<(), ClientError> {
    // Make sure that the client type is of Tendermint type `ClientState`
    let upgraded_tm_client_state = ClientState::try_from(upgraded_client_state.clone())?;

    // Make sure that the consensus type is of Tendermint type `ConsensusState`
    TmConsensusState::try_from(upgraded_consensus_state.clone())?;

    let latest_height = client_state.latest_height;
    let upgraded_tm_client_state_height = upgraded_tm_client_state.latest_height();

    // Make sure the latest height of the current client is not greater then
    // the upgrade height This condition checks both the revision number and
    // the height
    if latest_height >= upgraded_tm_client_state_height {
        Err(UpgradeClientError::InsufficientUpgradeHeight {
            upgraded_height: upgraded_tm_client_state_height,
            client_height: latest_height,
        })?
    }

    // Verify the proof of the upgraded client state
    verify_membership::<H>(
        &client_state.proof_specs,
        &upgrade_path_prefix,
        &proof_upgrade_client,
        root,
        upgrade_client_path_bytes,
        upgraded_client_state.to_vec(),
    )?;

    // Verify the proof of the upgraded consensus state
    verify_membership::<H>(
        &client_state.proof_specs,
        &upgrade_path_prefix,
        &proof_upgrade_consensus_state,
        root,
        upgrade_consensus_path_bytes,
        upgraded_consensus_state.to_vec(),
    )?;

    Ok(())
}

/// Verify membership of the given value against the client's merkle proof.
///
/// Note that this function is typically implemented as part of the
/// [`ClientStateCommon`] trait, but has been made a standalone function
/// in order to make the ClientState APIs more flexible.
pub fn verify_membership<H: HostFunctionsProvider>(
    proof_specs: &ProofSpecs,
    prefix: &CommitmentPrefix,
    proof: &CommitmentProofBytes,
    root: &CommitmentRoot,
    path: PathBytes,
    value: Vec<u8>,
) -> Result<(), ClientError> {
    if prefix.is_empty() {
        Err(CommitmentError::MissingCommitmentPrefix)?;
    }

    let merkle_path = MerklePath::new(vec![prefix.as_bytes().to_vec().into(), path]);

    let merkle_proof = MerkleProof::try_from(proof)?;

    merkle_proof.verify_membership::<H>(proof_specs, root.clone().into(), merkle_path, value, 0)?;

    Ok(())
}

/// Verify that the given value does not belong in the client's merkle proof.
///
/// Note that this function is typically implemented as part of the
/// [`ClientStateCommon`] trait, but has been made a standalone function
/// in order to make the ClientState APIs more flexible.
pub fn verify_non_membership<H: HostFunctionsProvider>(
    proof_specs: &ProofSpecs,
    prefix: &CommitmentPrefix,
    proof: &CommitmentProofBytes,
    root: &CommitmentRoot,
    path: PathBytes,
) -> Result<(), ClientError> {
    let merkle_path = MerklePath::new(vec![prefix.as_bytes().to_vec().into(), path]);

    let merkle_proof = MerkleProof::try_from(proof)?;

    merkle_proof.verify_non_membership::<H>(proof_specs, root.clone().into(), merkle_path)?;

    Ok(())
}
