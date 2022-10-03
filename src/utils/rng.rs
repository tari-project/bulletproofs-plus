use curve25519_dalek::scalar::Scalar;

pub trait Rng {
    fn create_random_scalar(&mut self) -> Scalar;
}

#[cfg(feature="rand")]
impl<T:RngCore>  Rng for T  {
   fn create_random_scalar(&mut self) -> Scalar {
        Scalar::random(self)
    }

}

