use crate::field::*;

use super::tag::Tag;

/// `Ptr` is the main piece of data LEMs operate on. We can think of a pointer
/// as a building block for trees that represent Lurk data. A pointer can be a
/// leaf that contains data encoded as an element of a `LurkField` or it can have
/// children. For performance, the children of a pointer are stored on an
/// `IndexSet` and the resulding index is carried by the pointer itself.
///
/// A pointer also has a tag, which says what kind of data it encodes. On
/// previous implementations, the tag would be used to infer the number of
/// children a pointer has. However, LEMs require extra flexibility because LEM
/// hashing operations can plug any tag to the resulting pointer. Thus, the
/// number of children have to be made explicit as the `Ptr` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ptr<F: LurkField> {
    Leaf(Tag, F),
    Tree2(Tag, usize),
    Tree3(Tag, usize),
    Tree4(Tag, usize),
}

impl<F: LurkField> std::hash::Hash for Ptr<F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Ptr::Leaf(tag, f) => (0, tag, f.to_repr().as_ref()).hash(state),
            Ptr::Tree2(tag, x) => (1, tag, x).hash(state),
            Ptr::Tree3(tag, x) => (2, tag, x).hash(state),
            Ptr::Tree4(tag, x) => (3, tag, x).hash(state),
        }
    }
}

impl<F: LurkField> Ptr<F> {
    pub fn tag(&self) -> &Tag {
        match self {
            Ptr::Leaf(tag, _) => tag,
            Ptr::Tree2(tag, _) => tag,
            Ptr::Tree3(tag, _) => tag,
            Ptr::Tree4(tag, _) => tag,
        }
    }

    pub fn sym_to_key(&self) -> Self {
        match self {
            Ptr::Leaf(Tag::Sym, f) => Ptr::Leaf(Tag::Key, *f),
            Ptr::Tree2(Tag::Sym, x) => Ptr::Tree2(Tag::Key, *x),
            _ => panic!("Malformed sym pointer"),
        }
    }

    pub fn key_to_sym(&self) -> Self {
        match self {
            Ptr::Leaf(Tag::Key, f) => Ptr::Leaf(Tag::Sym, *f),
            Ptr::Tree2(Tag::Key, x) => Ptr::Tree2(Tag::Sym, *x),
            _ => panic!("Malformed key pointer"),
        }
    }

    #[inline]
    pub fn num(f: F) -> Self {
        Ptr::Leaf(Tag::Num, f)
    }

    #[inline]
    pub fn char(c: char) -> Self {
        Ptr::Leaf(Tag::Char, F::from_char(c))
    }

    #[inline]
    pub fn comm(hash: F) -> Self {
        Ptr::Leaf(Tag::Comm, hash)
    }

    #[inline]
    pub fn null(tag: Tag) -> Self {
        Ptr::Leaf(tag, F::ZERO)
    }

    #[inline]
    pub fn get_index2(&self) -> Option<usize> {
        match self {
            Ptr::Tree2(_, x) => Some(*x),
            _ => None,
        }
    }

    #[inline]
    pub fn get_index3(&self) -> Option<usize> {
        match self {
            Ptr::Tree3(_, x) => Some(*x),
            _ => None,
        }
    }

    #[inline]
    pub fn get_index4(&self) -> Option<usize> {
        match self {
            Ptr::Tree4(_, x) => Some(*x),
            _ => None,
        }
    }
}

/// A `ZPtr` is the result of "hydrating" a `Ptr`. This process is better
/// explained in the store but, in short, we want to know the Poseidon hash of
/// the children of a `Ptr`.
///
/// `ZPtr`s are used mainly for proofs, but they're also useful when we want
/// to content-address a store.
///
/// An important note is that computing the respective `ZPtr` of a `Ptr` can be
/// expensive because of the Poseidon hashes. That's why we operate on `Ptr`s
/// when interpreting LEMs and delay the need for `ZPtr`s as much as possible.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZPtr<F: LurkField> {
    pub tag: Tag,
    pub hash: F,
}

/// `ZChildren` keeps track of the children of `ZPtr`s, in case they have any.
/// This information is saved during hydration and is needed to content-address
/// a store.
#[allow(dead_code)]
pub(crate) enum ZChildren<F: LurkField> {
    Tree2(ZPtr<F>, ZPtr<F>),
    Tree3(ZPtr<F>, ZPtr<F>, ZPtr<F>),
    Tree4(ZPtr<F>, ZPtr<F>, ZPtr<F>, ZPtr<F>),
}

impl<F: LurkField> ZPtr<F> {
    #[inline]
    pub fn dummy() -> Self {
        Self {
            tag: Tag::Dummy,
            hash: F::ZERO,
        }
    }
}

impl<F: LurkField> std::hash::Hash for ZPtr<F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.tag.hash(state);
        self.hash.to_repr().as_ref().hash(state);
    }
}
