use landscape_common::lan_service::lan_ipv6::LanIPv6ServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    LanIPv6ServiceConfigActiveModel, LanIPv6ServiceConfigEntity, LanIPv6ServiceConfigModel,
};

#[derive(Clone)]
pub struct LanIPv6ServiceRepository {
    db: DatabaseConnection,
}

impl LanIPv6ServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    LanIPv6ServiceRepository,
    LanIPv6ServiceConfigModel,
    LanIPv6ServiceConfigEntity,
    LanIPv6ServiceConfigActiveModel,
    LanIPv6ServiceConfig,
    String
);
