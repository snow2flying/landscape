use landscape_common::lan_service::lan_ipv6::IPV6RAServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    IPV6RAServiceConfigActiveModel, IPV6RAServiceConfigEntity, IPV6RAServiceConfigModel,
};

#[derive(Clone)]
pub struct IPV6RAServiceRepository {
    db: DatabaseConnection,
}

impl IPV6RAServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    IPV6RAServiceRepository,
    IPV6RAServiceConfigModel,
    IPV6RAServiceConfigEntity,
    IPV6RAServiceConfigActiveModel,
    IPV6RAServiceConfig,
    String
);
