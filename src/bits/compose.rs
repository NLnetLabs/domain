
use bytes::{BigEndian, BufMut};

pub trait ComposeExt {
    const COMPOSE_LEN: usize;
    fn compose<B: BufMut>(&self, buf: &mut B);
}

impl ComposeExt for i8 {
    const COMPOSE_LEN: usize = 1;

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_i8(*self)
    }
}

impl ComposeExt for u8 {
    const COMPOSE_LEN: usize = 1;

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(*self)
    }
}

impl ComposeExt for i16 {
    const COMPOSE_LEN: usize = 2;

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_i16::<BigEndian>(*self)
    }
}

impl ComposeExt for u16 {
    const COMPOSE_LEN: usize = 2;

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16::<BigEndian>(*self)
    }
}

impl ComposeExt for i32 {
    const COMPOSE_LEN: usize = 4;

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_i32::<BigEndian>(*self)
    }
}

impl ComposeExt for u32 {
    const COMPOSE_LEN: usize = 4;

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u32::<BigEndian>(*self)
    }
}

