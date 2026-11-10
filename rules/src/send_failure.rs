//! What an outgoing message is after its send failed.
//!
//! A send that got no answer — our own deadline, the connection broke, the client was stopped
//! under the call, the VEIL tunnel still coming up — failed on the path, not on the message: it is
//! queued, and the same ciphertext goes out again once there is a path. So are the gRPC statuses
//! that say the same (`DEADLINE_EXCEEDED`, `UNAVAILABLE`, `CANCELLED`). Any other answer is the
//! server's about this message: it failed. iOS decided so (`SendFailure`, todo 165); Android marked
//! every failure failed, so a message lost to a dropped connection showed red where iOS showed it
//! waiting. A platform maps its own errors to `SendError`; the decision is here.

/// A failed send, as a platform reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// No answer came: a deadline of ours, a broken or replaced connection, the VEIL tunnel not
    /// up yet.
    NoAnswer,
    /// The server — or a relay on its behalf — answered with this gRPC status code.
    Status(u32),
}

/// What the message is after the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterSend {
    /// Waits for a path; the same ciphertext is sent again.
    Queued,
    /// The send was refused; the person sees it did not go.
    Failed,
}

/// gRPC codes that say "no answer about this message".
const CANCELLED: u32 = 1;
const DEADLINE_EXCEEDED: u32 = 4;
const UNAVAILABLE: u32 = 14;

/// The message after `error`.
pub fn after(error: SendError) -> AfterSend {
    match error {
        SendError::NoAnswer => AfterSend::Queued,
        SendError::Status(CANCELLED | DEADLINE_EXCEEDED | UNAVAILABLE) => AfterSend::Queued,
        SendError::Status(_) => AfterSend::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutations that redden it: fail on no answer; drop any of the three codes.
    #[test]
    fn no_answer_waits_for_a_path() {
        assert_eq!(after(SendError::NoAnswer), AfterSend::Queued);
        for code in [1, 4, 14] {
            assert_eq!(
                after(SendError::Status(code)),
                AfterSend::Queued,
                "code {code}"
            );
        }
    }

    /// Mutation that reddens it: queue every status — a refused message would wait forever.
    #[test]
    fn an_answer_about_the_message_fails_it() {
        for code in [2, 3, 5, 7, 8, 13, 16] {
            assert_eq!(
                after(SendError::Status(code)),
                AfterSend::Failed,
                "code {code}"
            );
        }
    }
}
