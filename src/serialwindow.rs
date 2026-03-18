use crate::serialwindow;

pub struct SerialWindow<T, const W: usize> {
    pub serials: [T; W]
}

pub trait DivByU8 {
    fn div_by_u8(self, other: u8) -> Self;
}

macro_rules! simple_div_by_u8_impl {
    ($int_type: ident) => {
        impl DivByU8 for $int_type {
            fn div_by_u8(self, other: u8) -> $int_type {
                self / other as $int_type
            }
        }
    };
}

simple_div_by_u8_impl!(u8);
simple_div_by_u8_impl!(u16);
simple_div_by_u8_impl!(u32);
simple_div_by_u8_impl!(u64);
simple_div_by_u8_impl!(u128);

impl DivByU8 for i8 {
    fn div_by_u8(self, other: u8) -> i8 {
        if other < 128 {
            self / other as i8
        } else if self != -128i8 {
            0
        } else {
            -1
        }
    }
}

macro_rules! signed_div_by_u8_impl {
    ($int_type: ident) => {
        impl DivByU8 for $int_type {
            fn div_by_u8(self, other: u8) -> $int_type {
                let o = other as $int_type;
                if (self >= (0 as $int_type)) {
                    self / o
                } else if other != 1 {
                    let temp = (0 as $int_type) - (self + (1 as $int_type));
                    let pass1 = temp / o;
                    let rem = (temp % o) + (1 as $int_type);
                    let pass2 = rem / o;
                    (0 as $int_type) - pass1 - pass2
                } else {
                    self
                }
            }
        }
    };
}

signed_div_by_u8_impl!(i16);
signed_div_by_u8_impl!(i32);
signed_div_by_u8_impl!(i64);
signed_div_by_u8_impl!(i128);

fn assert_div<T: DivByU8 + std::cmp::PartialEq>(a: T, b: u8, expect: T) {
    let c = a.div_by_u8(b);
    assert!(c == expect);
}

#[test]
fn test_divs() {
    assert_div(-7i16, 1, -7i16);
    assert_div(-3i16, 1, -3i16);
    assert_div(-2i16, 1, -2i16);
    assert_div(-1i16, 1, -1i16);
    assert_div(1i16, 1, 1i16);
    assert_div(2i16, 1, 2i16);
    assert_div(3i16, 1, 3i16);
    assert_div(7i16, 1, 7i16);
    assert_div(-7i16, 2, -3i16);
    assert_div(-3i16, 2, -1i16);
    assert_div(-2i16, 2, -1i16);
    assert_div(-1i16, 2, 0i16);
    assert_div(1i16, 2, 0i16);
    assert_div(2i16, 2, 1i16);
    assert_div(3i16, 2, 1i16);
    assert_div(7i16, 2, 3i16);
    assert_div(-7i16, 3, -2i16);
    assert_div(-3i16, 3, -1i16);
    assert_div(-2i16, 3, 0i16);
    assert_div(-1i16, 3, 0i16);
    assert_div(1i16, 3, 0i16);
    assert_div(2i16, 3, 0i16);
    assert_div(3i16, 3, 1i16);
    assert_div(7i16, 3, 2i16);
    assert_div(-7i16, 7, -1i16);
    assert_div(-3i16, 7, 0i16);
    assert_div(-2i16, 7, 0i16);
    assert_div(-1i16, 7, 0i16);
    assert_div(1i16, 7, 0i16);
    assert_div(2i16, 7, 0i16);
    assert_div(3i16, 7, 0i16);
    assert_div(7i16, 7, 1i16);
}

pub trait IntMinMaxValue {
    const MIN: Self;
    const MAX: Self;
}

macro_rules! type_const_impl {
    ($trait_name: ident, $int_type: ident, $min_const_name: ident, $const_name: ident) => {
        impl $trait_name for $int_type {
            const $min_const_name: $int_type = $int_type::$min_const_name;
            const $const_name: $int_type = $int_type::$const_name;
        }
    };
}

type_const_impl!(IntMinMaxValue, u8, MIN, MAX);
type_const_impl!(IntMinMaxValue, u16, MIN, MAX);
type_const_impl!(IntMinMaxValue, u32, MIN, MAX);
type_const_impl!(IntMinMaxValue, u64, MIN, MAX);
type_const_impl!(IntMinMaxValue, u128, MIN, MAX);
type_const_impl!(IntMinMaxValue, i8, MIN, MAX);
type_const_impl!(IntMinMaxValue, i16, MIN, MAX);
type_const_impl!(IntMinMaxValue, i32, MIN, MAX);
type_const_impl!(IntMinMaxValue, i64, MIN, MAX);
type_const_impl!(IntMinMaxValue, i128, MIN, MAX);

pub trait ZeroValue {
    fn zero_value() -> Self;
}

macro_rules! zero_value_impl {
    ($int_type: ident) => {
        impl ZeroValue for $int_type {
            fn zero_value() -> $int_type {
                0 as $int_type
            }
        }
    };
}

zero_value_impl!(u8);
zero_value_impl!(u16);
zero_value_impl!(u32);
zero_value_impl!(u64);
zero_value_impl!(u128);
zero_value_impl!(i8);
zero_value_impl!(i16);
zero_value_impl!(i32);
zero_value_impl!(i64);
zero_value_impl!(i128);

pub trait OneValue {
    fn one_value() -> Self;
}

macro_rules! one_value_impl {
    ($int_type: ident) => {
        impl OneValue for $int_type {
            fn one_value() -> $int_type {
                1 as $int_type
            }
        }
    };
}

one_value_impl!(u8);
one_value_impl!(u16);
one_value_impl!(u32);
one_value_impl!(u64);
one_value_impl!(u128);
one_value_impl!(i8);
one_value_impl!(i16);
one_value_impl!(i32);
one_value_impl!(i64);
one_value_impl!(i128);

impl<T: std::marker::Copy + std::cmp::PartialOrd + num_traits::ops::wrapping::WrappingSub + IntMinMaxValue + DivByU8 + ZeroValue + OneValue, const W: usize> SerialWindow<T, W> {
    pub fn new(init_value: T) -> Self {
        Self { serials: [init_value; W] }
    }
    pub fn reset(&mut self, value: T) {
        let mut v = value;
        let mut one = T::one_value();
        for i in 0..W {
            self.serials[W - i - 1] = v;
            v = v.wrapping_sub(&one);
        }
    }

    pub fn observe(&mut self, value: T) {
        let half_max = T::MAX.div_by_u8(2u8);
        let max_value = {
            let diff = value.wrapping_sub(&self.serials[W - 1]);
            let diff2 = self.serials[W - 1].wrapping_sub(&value);
            if diff == diff2 {
                return;
            }
            if diff >= T::zero_value() && diff < half_max {
                value
            } else if (diff2 >= T::zero_value() && diff2 < half_max) {
                self.serials[W - 1]
            } else {
                return;
            }
        };
        let base_value = max_value.wrapping_sub(&half_max);
        for i in 0..W {
            let windowed_value = self.serials[i].wrapping_sub(&base_value);
            if windowed_value > half_max {
                self.serials[i] = base_value;
            }
        }
        for i in 0..W {
            if self.serials[W-i-1].wrapping_sub(&base_value) < value.wrapping_sub(&base_value) {
                for j in 0..(W-i-1) {
                    self.serials[j] = self.serials[j+1];
                }
                self.serials[W-i-1] = value;
                return;
            } else if self.serials[W-i-1] == value {
                return;
            }
        }
    }
    pub fn observed(&self, value: T) -> bool {
        let half_max = T::MAX.div_by_u8(2u8);
        let mut base_value = value.wrapping_sub(&half_max);
        for i in 0..W {
            let s = self.serials[W - i - 1];
            let windowed_value = s.wrapping_sub(&base_value);
            if windowed_value > half_max {
                base_value = s.wrapping_sub(&half_max);
                let range_check = value.wrapping_sub(&base_value);
                if range_check > half_max {
                    return false;
                }
            }
            if s == value {
                return true;
            }
        }
        return false;
    }
}

#[test]
fn test_0_to_255_wrapping() {
    const TRACKED: usize = 16;
    const ITERATIONS: i32 = 512;
    let mut tracker: SerialWindow<u8,TRACKED> = SerialWindow::new(0u8);
    let mut log = [0u8; TRACKED];
    let mut serial = 0u8;
    for i in 0..ITERATIONS {
        for j in if i < TRACKED as i32 { TRACKED as i32 - i } else { TRACKED as i32 } as usize..TRACKED as usize {
            let serial = log[j];
            assert!(tracker.observed(serial));
        }
        serial = serial.wrapping_add(1);
        for j in 0..TRACKED-1 {
            log[j] = log[j+1];
        }
        log[TRACKED-1] = serial;
        tracker.observe(serial);
    }
}

#[test]
fn test_2() {
    const TRACKED: usize = 16;
    let mut tracker: SerialWindow<u8,TRACKED> = SerialWindow::new(0u8);
    assert!(tracker.observed(0));
    assert!(!tracker.observed(1));
    assert!(!tracker.observed(2));
    assert!(!tracker.observed(3));
    assert!(!tracker.observed(4));
    tracker.observe(3);
    assert!(tracker.observed(0));
    assert!(!tracker.observed(1));
    assert!(!tracker.observed(2));
    assert!(tracker.observed(3));
    assert!(!tracker.observed(4));
    tracker.observe(2);
    assert!(tracker.observed(0));
    assert!(!tracker.observed(1));
    assert!(tracker.observed(2));
    assert!(tracker.observed(3));
    assert!(!tracker.observed(4));
    tracker.observe(1);
    assert!(tracker.observed(0));
    assert!(tracker.observed(1));
    assert!(tracker.observed(2));
    assert!(tracker.observed(3));
    assert!(!tracker.observed(4));
    tracker.observe(4);
    assert!(tracker.observed(0));
    assert!(tracker.observed(1));
    assert!(tracker.observed(2));
    assert!(tracker.observed(3));
    assert!(tracker.observed(4));
}