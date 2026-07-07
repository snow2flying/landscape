use crate::repository::UpdateActiveModel;
use landscape_common::lan_service::lan_ipv6::LanIPv6ServiceConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBJson, DBTimestamp};

pub type LanIPv6ServiceConfigModel = Model;
pub type LanIPv6ServiceConfigEntity = Entity;
pub type LanIPv6ServiceConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "lan_ipv6_service_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub iface_name: String,
    pub enable: bool,

    pub config: DBJson,

    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for LanIPv6ServiceConfig {
    fn from(entity: Model) -> Self {
        LanIPv6ServiceConfig {
            iface_name: entity.iface_name,
            enable: entity.enable,
            update_at: entity.update_at,
            config: serde_json::from_value(entity.config).unwrap(),
        }
    }
}

impl Into<ActiveModel> for LanIPv6ServiceConfig {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel {
            iface_name: Set(self.iface_name.clone()),
            ..Default::default()
        };
        self.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for LanIPv6ServiceConfig {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.update_at = Set(self.update_at);

        active.config = Set(serde_json::to_value(self.config).unwrap().into());
    }
}
