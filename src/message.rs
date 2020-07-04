use crate::{header::Header, type_container::DbusTypeContainer};

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub header: Header,
    pub message: Vec<DbusTypeContainer>,
}

impl std::ops::Deref for Message {
    type Target = Vec<DbusTypeContainer>;
    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl std::ops::DerefMut for Message {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}
