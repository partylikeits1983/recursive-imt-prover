#[cfg(not(feature = "field192"))]
pub use ark_bn254::Fr;
#[cfg(feature = "field192")]
mod small {
    use ark_ff::{Fp192, MontBackend, MontConfig};
    #[derive(MontConfig)]
    #[modulus = "3801539170989320091464968600173246866371124347557388484609"]
    #[generator = "3"]
    pub struct Config;
    pub type Fr = Fp192<MontBackend<Config, 3>>;
}
#[cfg(feature = "field192")]
pub use small::Fr;
