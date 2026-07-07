use landscape_common::wan_service::ip_config::IfaceIpServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    IfaceIpServiceConfigActiveModel, IfaceIpServiceConfigEntity, IfaceIpServiceConfigModel,
};

#[derive(Clone)]
pub struct IfaceIpServiceRepository {
    db: DatabaseConnection,
}

impl IfaceIpServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    IfaceIpServiceRepository,
    IfaceIpServiceConfigModel,
    IfaceIpServiceConfigEntity,
    IfaceIpServiceConfigActiveModel,
    IfaceIpServiceConfig,
    String
);
