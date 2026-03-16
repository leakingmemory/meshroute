
pub struct SerialWindow<T, const W: usize> {
    pub serials: [T; W]
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

impl<T: std::marker::Copy + std::cmp::PartialOrd + num_traits::ops::wrapping::WrappingSub + IntMinMaxValue + std::ops::Div<u8, Output = T> + ZeroValue, const W: usize> SerialWindow<T, W> {
    pub fn new(init_value: T) -> Self {
        Self { serials: [init_value; W] }
    }
    pub fn observe(&mut self, value: T) {
        let half_max = T::MAX / 2;
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
        let half_max = T::MAX / 2;
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