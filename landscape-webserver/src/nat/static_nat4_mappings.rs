use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::iface::nat::{StaticNatError, StaticNatMappingV4Config};
use landscape_common::service::ServiceConfigError;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_static_nat_mapping_v4_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_static_nat_mappings_v4, add_static_nat_mapping_v4))
        .routes(routes!(get_static_nat_mapping_v4, del_static_nat_mapping_v4))
        .routes(routes!(add_many_static_nat_mappings_v4))
}

#[utoipa::path(
    get,
    path = "/static_mappings/v4",
    tag = "Static NAT Mappings",
    responses((status = 200, body = CommonApiResp<Vec<StaticNatMappingV4Config>>))
)]
async fn get_static_nat_mappings_v4(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<StaticNatMappingV4Config>> {
    let result = state.static_nat4_mapping_service.list().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/static_mappings/v4/{id}",
    tag = "Static NAT Mappings",
    params(("id" = Uuid, Path, description = "Static NAT mapping v4 ID")),
    responses(
        (status = 200, body = CommonApiResp<StaticNatMappingV4Config>),
        (status = 404, description = "Not found")
    )
)]
async fn get_static_nat_mapping_v4(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<StaticNatMappingV4Config> {
    let result = state.static_nat4_mapping_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(StaticNatError::NotFound(id))?
    }
}

#[utoipa::path(
    post,
    path = "/static_mappings/v4",
    tag = "Static NAT Mappings",
    request_body = StaticNatMappingV4Config,
    responses((status = 200, body = CommonApiResp<StaticNatMappingV4Config>))
)]
async fn add_static_nat_mapping_v4(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<StaticNatMappingV4Config>,
) -> LandscapeApiResult<StaticNatMappingV4Config> {
    config.validate()?;
    state
        .static_nat4_mapping_service
        .validate_runtime_target(&config)
        .await
        .map_err(|error| ServiceConfigError::InvalidConfig { reason: error.to_string() })?;
    state
        .static_nat4_mapping_service
        .validate_no_dynamic_port_conflict(&config)
        .await
        .map_err(|error| ServiceConfigError::InvalidConfig { reason: error.to_string() })?;
    let result = state.static_nat4_mapping_service.checked_set(config).await?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/static_mappings/v4/batch",
    tag = "Static NAT Mappings",
    request_body = Vec<StaticNatMappingV4Config>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_static_nat_mappings_v4(
    State(state): State<LandscapeApp>,
    JsonBody(configs): JsonBody<Vec<StaticNatMappingV4Config>>,
) -> LandscapeApiResult<()> {
    for m in &configs {
        m.validate()?;
        state
            .static_nat4_mapping_service
            .validate_runtime_target(m)
            .await
            .map_err(|error| ServiceConfigError::InvalidConfig { reason: error.to_string() })?;
        state
            .static_nat4_mapping_service
            .validate_no_dynamic_port_conflict(m)
            .await
            .map_err(|error| ServiceConfigError::InvalidConfig { reason: error.to_string() })?;
    }
    state.static_nat4_mapping_service.checked_set_list(configs).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/static_mappings/v4/{id}",
    tag = "Static NAT Mappings",
    params(("id" = Uuid, Path, description = "Static NAT mapping v4 ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_static_nat_mapping_v4(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.static_nat4_mapping_service.delete(id).await;
    LandscapeApiResp::success(())
}
