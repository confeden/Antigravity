//! Internationalisation (Russian and English).

use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    Ru,
    En,
}

impl<'de> Deserialize<'de> for Lang {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(if s.eq_ignore_ascii_case("en") {
            Self::En
        } else {
            Self::Ru
        })
    }
}

impl Lang {
    pub const ALL: [Self; 2] = [Self::Ru, Self::En];

    pub fn code(self) -> &'static str {
        match self {
            Self::Ru => "ru",
            Self::En => "en",
        }
    }

    pub fn short_label(self) -> &'static str {
        match self {
            Self::Ru => "RU",
            Self::En => "EN",
        }
    }

    pub fn native_name(self) -> &'static str {
        match self {
            Self::Ru => "Русский",
            Self::En => "English",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Self::Ru => Self::En,
            Self::En => Self::Ru,
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Self::Ru => 0,
            Self::En => 1,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::En,
            _ => Self::Ru,
        }
    }
}

static CURRENT_LANG: AtomicU8 = AtomicU8::new(0);

pub fn current() -> Lang {
    Lang::from_u8(CURRENT_LANG.load(Ordering::Relaxed))
}

pub fn set_current(lang: Lang) {
    CURRENT_LANG.store(lang.to_u8(), Ordering::Relaxed);
}

#[inline]
pub fn tr(ru: &'static str, en: &'static str) -> &'static str {
    tr_for(current(), ru, en)
}

#[inline]
pub fn tr_for(lang: Lang, ru: &'static str, en: &'static str) -> &'static str {
    match lang {
        Lang::Ru => ru,
        Lang::En => en,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lang_cycle_covers_both() {
        assert_eq!(Lang::Ru.next(), Lang::En);
        assert_eq!(Lang::En.next(), Lang::Ru);
    }

    #[test]
    fn unknown_saved_lang_falls_back_to_ru() {
        let parsed: Lang = serde_json::from_str("\"fa\"").unwrap();
        assert_eq!(parsed, Lang::Ru);
        let en: Lang = serde_json::from_str("\"en\"").unwrap();
        assert_eq!(en, Lang::En);
    }
}
