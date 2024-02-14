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
// We never actually use this function, but it's here for completeness
#[allow(dead_code)]
pub fn interpolate(x: &[u32], y: &[Scalar], target_x: u32) -> Scalar {
    assert!(x.len() == y.len());
    (0..x.len())
        .map(|i| lagrange(x, x[i], target_x) * y[i])
        .sum()
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

    pub fn rand(degree: usize) -> Self {
        let mut rng = rand::thread_rng();
        let mut coeffs: Vec<Scalar> = Vec::new();
        coeffs.resize_with(degree + 1, || Scalar::random(&mut rng));
        Self { coeffs }
    }

    // Evaluate the polynomial at the given point (using Horner's
    // method)
    pub fn eval(&self, x: &Scalar) -> Scalar {
        let mut res = Scalar::zero();
        for coeff in self.coeffs.iter().rev() {
            res *= x;
            res += coeff;
        }
        res
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

#[test]
pub fn test_rand_poly() {
    let rpoly = ScalarPoly::rand(3);

    println!("randpoly = {:?}", rpoly);

    assert!(rpoly.coeffs.len() == 4);
    assert!(rpoly.coeffs[0] != Scalar::zero());
    assert!(rpoly.coeffs[0] != rpoly.coeffs[1]);
}

#[test]
pub fn test_eval() {
    let mut poly = ScalarPoly::one();
    poly.mult_x_plus_a(&Scalar::from(2u32));
    poly.mult_x_plus_a(&Scalar::from(3u32));

    // poly should now be (x+2)*(x+3) = x^2 + 5x + 6
    assert!(poly.coeffs.len() == 3);
    assert!(poly.coeffs[0] == Scalar::from(6u32));
    assert!(poly.coeffs[1] == Scalar::from(5u32));
    assert!(poly.coeffs[2] == Scalar::from(1u32));

    let f0 = poly.eval(&Scalar::zero());
    let f2 = poly.eval(&Scalar::from(2u32));
    let f7 = poly.eval(&Scalar::from(7u32));

    println!("f0 = {:?}", f0);
    println!("f2 = {:?}", f2);
    println!("f7 = {:?}", f7);

    assert!(f0 == Scalar::from(6u32));
    assert!(f2 == Scalar::from(20u32));
    assert!(f7 == Scalar::from(90u32));
}

// Check that the sum of the given polys is just x^i
#[cfg(test)]
fn sum_polys_is_x_to_the_i(polys: &[ScalarPoly], i: usize) {
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

// Interpolate values at x=0 given the pre-computed Lagrange polynomials
pub fn interpolate_polys_0(lag_polys: &[ScalarPoly], y: &[Scalar]) -> Scalar {
    assert!(lag_polys.len() == y.len());
    (0..y.len()).map(|i| lag_polys[i].coeffs[0] * y[i]).sum()
}
