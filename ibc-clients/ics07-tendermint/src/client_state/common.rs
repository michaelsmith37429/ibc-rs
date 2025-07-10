use core::time::Duration;

use ibc_client_tendermint_types::{client_type as tm_client_type, ClientState as ClientStateType};
use ibc_core_client::context::client_state::ClientStateCommon;
use ibc_core_client::context::consensus_state::ConsensusState;
use ibc_core_client::types::error::ClientError;
use ibc_core_client::types::{Height, Status};
use ibc_core_commitment_types::error::CommitmentError;
use ibc_core_host::types::identifiers::ClientType;
use ibc_core_host::types::path::{Path, PathBytes};
use ibc_primitives::prelude::*;
use ibc_primitives::proto::Any;
use ibc_primitives::Timestamp;

use super::ClientState;
use crate::consensus_state::ConsensusState as TmConsensusState;

impl ClientStateCommon for ClientState {
    fn verify_consensus_state(
        &self,
        consensus_state: Any,
        host_timestamp: &Timestamp,
    ) -> Result<(), ClientError> {
        verify_consensus_state(
            consensus_state,
            host_timestamp,
            self.inner().trusting_period,
        )
    }

    fn client_type(&self) -> ClientType {
        tm_client_type()
    }

    fn latest_height(&self) -> Height {
        self.0.latest_height
    }

    fn validate_proof_height(&self, proof_height: Height) -> Result<(), ClientError> {
        validate_proof_height(self.inner(), proof_height)
    }

    fn serialize_path(&self, path: Path) -> Result<PathBytes, ClientError> {
        Ok(path.to_string().into_bytes().into())
    }
}

/// Verify an `Any` consensus state by attempting to convert it to a `TmConsensusState`.
/// Also checks whether the converted consensus state's root is present.
///
/// Note that this function is typically implemented as part of the
/// [`ClientStateCommon`] trait, but has been made a standalone function
/// in order to make the ClientState APIs more flexible.
pub fn verify_consensus_state(
    consensus_state: Any,
    host_timestamp: &Timestamp,
    trusting_period: Duration,
) -> Result<(), ClientError> {
    let tm_consensus_state = TmConsensusState::try_from(consensus_state)?;

    if tm_consensus_state.root().is_empty() {
        Err(CommitmentError::MissingCommitmentRoot)?;
    };

    if consensus_state_status(&tm_consensus_state, host_timestamp, trusting_period)?.is_expired() {
        return Err(ClientError::InvalidStatus(Status::Expired));
    }

    Ok(())
}

/// Determines the `Status`, whether it is `Active` or `Expired`, of a consensus
/// state, using its timestamp, the host's timestamp, and the trusting period.
pub fn consensus_state_status<CS: ConsensusState>(
    consensus_state: &CS,
    host_timestamp: &Timestamp,
    trusting_period: Duration,
) -> Result<Status, ClientError> {
    // Note: if the `duration_since()` is `None`, indicating that the latest
    // consensus state is in the future, then we don't consider the client
    // to be expired.
    if let Some(elapsed_since_latest_consensus_state) =
        host_timestamp.duration_since(&consensus_state.timestamp()?)
    {
        // Note: The equality is considered as expired to stay consistent with
        // the check in tendermint-rs, where a header at `trusted_header_time +
        // trusting_period` is considered expired.
        if elapsed_since_latest_consensus_state >= trusting_period {
            return Ok(Status::Expired);
        }
    }

    Ok(Status::Active)
}

/// Validate the given proof height against the client state's latest height, returning
/// an error if the proof height is greater than the latest height of the client state.
///
/// Note that this function is typically implemented as part of the
/// [`ClientStateCommon`] trait, but has been made a standalone function
/// in order to make the ClientState APIs more flexible.
pub fn validate_proof_height(
    client_state: &ClientStateType,
    proof_height: Height,
) -> Result<(), ClientError> {
    let latest_height = client_state.latest_height;

    if latest_height < proof_height {
        return Err(ClientError::InsufficientProofHeight {
            actual: latest_height,
            expected: proof_height,
        });
    }

    Ok(())
}
