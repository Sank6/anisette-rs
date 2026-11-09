use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Index, IndexMut, Mul, Not, Shl, Shr, Sub};

#[derive(Clone, Copy)]
pub(super) struct Num(pub u32);

pub(super) const fn n(value: u32) -> Num {
    Num(value)
}
pub(super) fn byte(value: Num) -> Num {
    Num(value.0 & 255)
}
pub(super) fn word(value: Num) -> Num {
    value
}
pub(super) fn cube_byte(value: Num) -> Num {
    byte(value * value * value)
}
pub(super) fn xor_shifts(value: Num, left: Num, right: Num) -> Num {
    byte((value << left) ^ (value >> right))
}
pub(super) fn rotl8(value: Num, count: Num) -> Num {
    Num(u32::from((value.0 as u8).rotate_left(count.0)))
}

macro_rules! binary {
    ($trait:ident, $method:ident, $body:expr) => {
        impl $trait for Num {
            type Output = Self;
            fn $method(self, other: Self) -> Self {
                Self($body(self.0, other.0))
            }
        }
    };
}
binary!(Add, add, u32::wrapping_add);
binary!(Sub, sub, u32::wrapping_sub);
binary!(Mul, mul, u32::wrapping_mul);
binary!(Shl, shl, u32::wrapping_shl);
binary!(Shr, shr, u32::wrapping_shr);
binary!(BitAnd, bitand, |a: u32, b| a & b);
binary!(BitOr, bitor, |a: u32, b| a | b);
binary!(BitXor, bitxor, |a: u32, b| a ^ b);
binary!(Div, div, |a: u32, b| a / b);
impl Not for Num {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

#[derive(Clone, Copy)]
pub(super) struct Buf<const N: usize>(pub [Num; N]);
impl<const N: usize> Buf<N> {
    pub fn new(values: [Num; N]) -> Self {
        Self(values)
    }
    pub fn zero() -> Self {
        Self([n(0); N])
    }
    pub fn from_bytes(values: [u8; N]) -> Self {
        Self(values.map(|x| n(u32::from(x))))
    }
    pub fn bytes(self) -> [u8; N] {
        self.0.map(|x| x.0 as u8)
    }
}
impl<const N: usize> Index<Num> for Buf<N> {
    type Output = Num;
    fn index(&self, index: Num) -> &Num {
        &self.0[index.0 as usize]
    }
}
impl<const N: usize> IndexMut<Num> for Buf<N> {
    fn index_mut(&mut self, index: Num) -> &mut Num {
        &mut self.0[index.0 as usize]
    }
}
