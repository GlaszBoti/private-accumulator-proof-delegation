//! Privacy-Preserving Accumulator Proofs
//!
//! This library provides implementations of cryptographic accumulators
//!
//! ## Features
//!
//! - `rsa`: RSA-based accumulator implementation
//! - `bilinear`: Bilinear pairing-based accumulator implementation
//!
//! ## Example
//!
//! ```rust,ignore
//! use privacy_preserving_accumulators::RsaAccumulator;
//!
//! let mut acc = RsaAccumulator::setup();
//! ```

#[cfg(feature = "rsa")]
pub mod rsa_accumulator;

#[cfg(feature = "rsa")]
pub mod groups;

#[cfg(feature = "bilinear")]
pub mod bilinear_accumulator;

pub mod math;
pub mod nizk;
pub mod traits;

pub use traits::{Accumulator, Group};

#[cfg(feature = "rsa")]
pub use rsa_accumulator::{GenericAccumulator, RsaAccumulator};

#[cfg(feature = "rsa")]
pub use groups::rsa_group;

#[cfg(feature = "bilinear")]
pub use bilinear_accumulator::BilinearAccumulator;
