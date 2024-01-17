use curve25519_dalek::scalar::Scalar;

// Versions that just compute coefficients; these are used if you know
// all of your input points are correct

// Compute the Lagrange coefficient for the value at the given x
// coordinate, to interpolate the value at target_x.  The x coordinates
// in the coalition are allowed to include x itself, which will be
// ignored.
pub fn lagrange(coalition: &[u32], x: u32, target_x: u32) -> Scalar {
    let mut numer = Scalar::one();
    let mut denom = Scalar::one();
    let xscal = Scalar::from(x);
    let target_xscal = Scalar::from(target_x);
    for &c in coalition {
        if c != x {
            let cscal = Scalar::from(c);
            numer *= target_xscal - cscal;
            denom *= xscal - cscal;
        }
    }
    numer * denom.invert()
}

// Interpolate the given (x,y) coordinates at the target x value.
// target_x must _not_ be in the x slice
pub fn interpolate(x: &[u32], y: &[Scalar], target_x: u32) -> Scalar {
    assert!(x.len() == y.len());
    let mut res = Scalar::zero();
    for i in 0..x.len() {
        let lag_coeff = lagrange(x, x[i], target_x);
        res += lag_coeff * y[i];
    }
    res
}

// Versions that compute the entire Lagrange polynomials; these are used
// if need to _check_ that all of your input points are correct.

// A ScalarPoly represents a polynomial whose coefficients are scalars.
// The coeffs vector has length (deg+1), where deg is the degree of the
// polynomial.  coeffs[i] is the coefficient on x^i.
#[derive(Clone, Debug)]
pub struct ScalarPoly {
    pub coeffs: Vec<Scalar>,
}

impl ScalarPoly {
    pub fn zero() -> Self {
        Self { coeffs: vec![] }
    }

    pub fn one() -> Self {
        Self {
            coeffs: vec![Scalar::one()],
        }
    }

    // Multiply self by the polynomial (x+a), for the given a
    pub fn mult_x_plus_a(&mut self, a: &Scalar) {
        // The length of coeffs is (deg+1), which is what we want the
        // new degree to be
        let newdeg = self.coeffs.len();
        if newdeg == 0 {
            // self is the zero polynomial, so it doesn't change with
            // the multiplication by x+a
            return;
        }
        let newcoeffs = (0..newdeg + 1)
            .map(|i| {
                if i == 0 {
                    self.coeffs[i] * a
                } else if i == newdeg {
                    self.coeffs[i - 1]
                } else {
                    self.coeffs[i - 1] + self.coeffs[i] * a
                }
            })
            .collect();
        self.coeffs = newcoeffs;
    }

    // Multiply self by the constant c
    pub fn mult_scalar(&mut self, c: &Scalar) {
        for coeff in self.coeffs.iter_mut() {
            *coeff *= c;
        }
    }

    // Add another ScalarPoly to this one
    pub fn add(&mut self, other: &Self) {
        if other.coeffs.len() > self.coeffs.len() {
            self.coeffs.resize(other.coeffs.len(), Scalar::zero());
        }
        for i in 0..other.coeffs.len() {
            self.coeffs[i] += other.coeffs[i];
        }
    }
}

// Compute the Lagrange polynomial for the value at the given x
// coordinate.  The x coordinates in the coalition are allowed to
// include x itself, which will be ignored.
pub fn lagrange_poly(coalition: &[u32], x: u32) -> ScalarPoly {
    let mut numer = ScalarPoly::one();
    let mut denom = Scalar::one();
    let xscal = Scalar::from(x);
    for &c in coalition {
        if c != x {
            let cscal = Scalar::from(c);
            numer.mult_x_plus_a(&-cscal);
            denom *= xscal - cscal;
        }
    }
    numer.mult_scalar(&denom.invert());
    numer
}

// Compute the full set of Lagrange polynomials for the given coalition
pub fn lagrange_polys(coalition: &[u32]) -> Vec<ScalarPoly> {
    coalition
        .iter()
        .map(|&x| lagrange_poly(coalition, x))
        .collect()
}

// Check that the sum of the given polys is just x^i
#[cfg(test)]
fn sum_polys_is_x_to_the_i(polys: &Vec<ScalarPoly>, i: usize) {
    let mut sum = ScalarPoly::zero();
    for p in polys.iter() {
        sum.add(p);
    }
    println!("sum = {:?}", sum);
    for j in 0..sum.coeffs.len() {
        assert!(
            sum.coeffs[j]
                == if i == j {
                    Scalar::one()
                } else {
                    Scalar::zero()
                }
        );
    }
}

#[test]
pub fn test_lagrange_polys() {
    let coalition: Vec<u32> = vec![1, 2, 5, 8, 12, 14];

    let mut polys = lagrange_polys(&coalition);

    sum_polys_is_x_to_the_i(&polys, 0);

    for i in 0..coalition.len() {
        polys[i].mult_scalar(&Scalar::from(coalition[i]));
    }

    sum_polys_is_x_to_the_i(&polys, 1);

    for i in 0..coalition.len() {
        polys[i].mult_scalar(&Scalar::from(coalition[i]));
    }

    sum_polys_is_x_to_the_i(&polys, 2);
}
