use crate::repository::UpdateActiveModel;
use landscape_common::lan_service::lan_ipv6::IPV6RAServiceConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBJson, DBTimestamp};

pub type IPV6RAServiceConfigModel = Model;
pub type IPV6RAServiceConfigEntity = Entity;
pub type IPV6RAServiceConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "ipv6_ra_service_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub iface_name: String,
    pub enable: bool,

    // 新增的
    pub config: DBJson,

    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for IPV6RAServiceConfig {
    fn from(entity: Model) -> Self {
        IPV6RAServiceConfig {
            iface_name: entity.iface_name,
            enable: entity.enable,
            update_at: entity.update_at,
            config: serde_json::from_value(entity.config).unwrap(),
        }
    }
}

impl Into<ActiveModel> for IPV6RAServiceConfig {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel {
            iface_name: Set(self.iface_name.clone()),
            ..Default::default()
        };
        self.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for IPV6RAServiceConfig {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.update_at = Set(self.update_at);

        active.config = Set(serde_json::to_value(self.config).unwrap().into());
    }
}
