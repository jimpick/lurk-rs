use crate::field::FWrap;
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use proptest::prelude::*;
#[cfg(not(target_arch = "wasm32"))]
use proptest_derive::Arbitrary;

use crate::hash::PoseidonCache;
use crate::ptr::Ptr;
use crate::store::Store;
use crate::tag::{ExprTag, Tag};
use crate::z_data::Encodable;
use crate::z_data::ZData;
use crate::z_ptr::{ZContPtr, ZExprPtr, ZPtr};
use crate::z_store::ZStore;
use crate::UInt;
use anyhow::anyhow;

use crate::field::LurkField;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Arbitrary))]
#[cfg_attr(not(target_arch = "wasm32"), proptest(no_bound))]
/// Enum to represent a z expression.
pub enum ZExpr<F: LurkField> {
    Nil,
    Cons(ZExprPtr<F>, ZExprPtr<F>),
    #[cfg_attr(
        not(target_arch = "wasm32"),
        proptest(
            strategy = "any::<(FWrap<F>, ZExprPtr<F>)>().prop_map(|(x, y)| Self::Comm(x.0, y))"
        )
    )]
    Comm(F, ZExprPtr<F>),
    SymNil,
    SymCons(ZExprPtr<F>, ZExprPtr<F>),
    Key(ZExprPtr<F>),
    Fun {
        arg: ZExprPtr<F>,
        body: ZExprPtr<F>,
        closed_env: ZExprPtr<F>,
    },
    #[cfg_attr(
        not(target_arch = "wasm32"),
        proptest(strategy = "any::<FWrap<F>>().prop_map(|x| Self::Num(x.0))")
    )]
    Num(F),
    StrNil,
    /// Contains a string and a pointer to the tail.
    StrCons(ZExprPtr<F>, ZExprPtr<F>),
    Thunk(ZExprPtr<F>, ZContPtr<F>),
    Char(char),
    Uint(UInt),
}

impl<F: LurkField> std::fmt::Display for ZExpr<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZExpr::Cons(x, y) => write!(f, "({} . {})", x, y),
            ZExpr::StrCons(x, y) => write!(f, "('{}' str. {})", x, y),
            ZExpr::SymCons(x, y) => write!(f, "({} sym. {})", x, y),
            ZExpr::Comm(ff, x) => {
                write!(f, "({} comm. {})", ff.trimmed_hex_digits(), x)
            }
            ZExpr::Nil => write!(f, "nil"),
            ZExpr::StrNil => write!(f, "strnil"),
            ZExpr::SymNil => write!(f, "symnil"),
            _ => todo!(),
        }
    }
}

impl<F: LurkField> ZExpr<F> {
    pub fn z_ptr(&self, cache: &PoseidonCache<F>) -> ZExprPtr<F> {
        match self {
            ZExpr::Nil => ZPtr(ExprTag::Nil, ZStore::new().nil_z_ptr(cache).1),
            ZExpr::Cons(x, y) => ZPtr(
                ExprTag::Cons,
                cache.hash4(&[x.0.to_field(), x.1, y.0.to_field(), y.1]),
            ),
            ZExpr::Comm(f, x) => ZPtr(ExprTag::Comm, cache.hash3(&[*f, x.0.to_field(), x.1])),
            ZExpr::SymNil => ZPtr(ExprTag::Sym, F::zero()),
            ZExpr::SymCons(x, y) => ZPtr(
                ExprTag::Sym,
                cache.hash4(&[x.0.to_field(), x.1, y.0.to_field(), y.1]),
            ),
            ZExpr::Key(sym) => ZPtr(ExprTag::Key, sym.1),
            ZExpr::Fun {
                arg,
                body,
                closed_env,
            } => ZPtr(
                ExprTag::Fun,
                cache.hash6(&[
                    arg.0.to_field(),
                    arg.1,
                    body.0.to_field(),
                    body.1,
                    closed_env.0.to_field(),
                    closed_env.1,
                ]),
            ),
            ZExpr::Num(f) => ZPtr(ExprTag::Num, *f),
            ZExpr::StrNil => ZPtr(ExprTag::Str, F::zero()),
            ZExpr::StrCons(x, y) => ZPtr(
                ExprTag::Str,
                cache.hash4(&[x.0.to_field(), x.1, y.0.to_field(), y.1]),
            ),
            ZExpr::Thunk(x, y) => ZPtr(
                ExprTag::Thunk,
                cache.hash4(&[x.0.to_field(), x.1, y.0.to_field(), y.1]),
            ),
            ZExpr::Char(f) => ZPtr(ExprTag::Char, F::from_char(*f)),
            ZExpr::Uint(x) => match x {
                UInt::U64(x) => ZPtr(ExprTag::U64, F::from_u64(*x)),
            },
        }
    }

    pub fn from_ptr(_store: &Store<F>, _ptr: &Ptr<F>) -> Option<Self> {
        todo!()
        // match ptr.tag {
        //   ExprTag::Nil => Some(ZExpr::Nil),
        //   ExprTag::Cons => store.fetch_cons(ptr).and_then(|(car, cdr)| {
        //     if let (Some(car), Some(cdr)) = (store.get_expr_hash(car), store.get_expr_hash(cdr))
        //     {
        //       Some(ZExpr::Cons(car, cdr))
        //     } else {
        //       None
        //     }
        //   }),
        //   ExprTag::Comm => store.fetch_comm(ptr).and_then(|(secret, payload)| {
        //     store
        //       .get_expr_hash(payload)
        //       .map(|payload| ScalarExpression::Comm(secret.0, payload))
        //   }),
        //   ExprTag::Sym | ExprTag::Key => store.fetch_sym(ptr).map(ScalarExpression::Sym),
        //   ExprTag::Fun => store.fetch_fun(ptr).and_then(|(arg, body, closed_env)| {
        //     if let (Some(arg), Some(body), Some(closed_env)) = (
        //       store.get_expr_hash(arg),
        //       store.get_expr_hash(body),
        //       store.get_expr_hash(closed_env),
        //     ) {
        //       Some(ScalarExpression::Fun {
        //         arg,
        //         body,
        //         closed_env,
        //       })
        //     } else {
        //       None
        //     }
        //   }),
        //   ExprTag::Num => store.fetch_num(ptr).map(|num| match num {
        //     Num::U64(x) => ScalarExpression::Num((*x).into()),
        //     Num::Scalar(x) => ScalarExpression::Num(*x),
        //   }),
        //   ExprTag::Str => store
        //     .fetch_str(ptr)
        //     .map(|str| ScalarExpression::Str(str.to_string())),
        //   ExprTag::Char => store.fetch_char(ptr).map(ScalarExpression::Char),
        //   ExprTag::U64 => store.fetch_uint(ptr).map(ScalarExpression::UInt),
        //   ExprTag::Thunk => unimplemented!(),
        // }
    }
}

impl<F: LurkField> TryFrom<ZData> for ZExpr<F> {
    type Error = anyhow::Error;

    fn try_from(value: &ZData) -> Result<Self, Error> {
        match value {
            ZData::Atom(v) => Err(anyhow!("ZExpr::Atom({:?})", v)),
            ZData::Cell(v) => match (*v).as_slice() {
                [ZData::Atom(u)] if *u == vec![0u8] => Ok(ZExpr::Nil),
                [ZData::Atom(u), x, y] if *u == vec![1u8] => {
                    Ok(ZExpr::Cons(ZExprPtr::de(x)?, ZExprPtr::de(y)?))
                }
                [ZData::Atom(u), x, y] if *u == vec![2u8] => {
                    Ok(ZExpr::Comm(FWrap::de(x)?.0, ZExprPtr::de(y)?))
                }
                [ZData::Atom(u)] if *u == vec![3u8] => Ok(ZExpr::SymNil),
                [ZData::Atom(u), x, y] if *u == vec![4u8] => {
                    Ok(ZExpr::SymCons(ZExprPtr::de(x)?, ZExprPtr::de(y)?))
                }
                [ZData::Atom(u), x] if *u == vec![5u8] => Ok(ZExpr::Key(ZExprPtr::de(x)?)),
                [ZData::Atom(u), x, y, z] if *u == vec![6u8] => Ok(ZExpr::Fun {
                    arg: ZExprPtr::de(x)?,
                    body: ZExprPtr::de(y)?,
                    closed_env: ZExprPtr::de(z)?,
                }),
                [ZData::Atom(u), x] if *u == vec![7u8] => Ok(ZExpr::Num(FWrap::de(x)?.0)),
                [ZData::Atom(u)] if *u == vec![8u8] => Ok(ZExpr::StrNil),
                [ZData::Atom(u), x, y] if *u == vec![9u8] => {
                    Ok(ZExpr::StrCons(ZExprPtr::de(x)?, ZExprPtr::de(y)?))
                }
                [ZData::Atom(u), x, y] if *u == vec![10u8] => {
                    Ok(ZExpr::Thunk(ZExprPtr::de(x)?, ZContPtr::de(y)?))
                }
                [ZData::Atom(u), x] if *u == vec![11u8] => Ok(ZExpr::Char(char::de(x)?)),
                [ZData::Atom(u), x] if *u == vec![12u8] => Ok(ZExpr::Uint(UInt::de(x)?)),
                _ => Err(anyhow!("ZExpr::Cell({:?})", v)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::pallas::Scalar;

    proptest! {
          #[test]
          fn prop_z_expr(x in any::<ZExpr<Scalar>>()) {
              let ser = x.ser();
              let de  = ZExpr::de(&ser).expect("read ZExpr");
              assert_eq!(x, de)
          }
    }
}
