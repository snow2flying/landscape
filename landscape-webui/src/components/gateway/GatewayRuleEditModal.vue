<script setup lang="ts">
import { useMessage } from "naive-ui";
import type {
  ClientIpHeaderPolicy,
  HttpPathGroup,
  HttpUpstreamConfig,
  HttpUpstreamRuleConfig,
  HttpUpstreamTarget,
  LoadBalanceMethod,
  PathRewriteMode,
  ProxyHeaderConflictMode,
  ProxyRequestHeader,
} from "@landscape-router/types/api/schemas";
import { computed, ref } from "vue";
import ConfigModal from "@/components/common/ConfigModal.vue";
import { get_gateway_rule, push_gateway_rule } from "@/api/gateway";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useI18n } from "vue-i18n";

type Props = {
  rule_id?: string;
};

const props = defineProps<Props>();

const message = useMessage();
const { t } = useI18n();
const frontEndStore = useFrontEndStore();

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const origin_rule_json = ref<string>("");
const rule = ref<HttpUpstreamRuleConfig>();
const pathGroupDraft = ref<HttpPathGroup>();
const pathGroupEditIndex = ref<number | null>(null);
const showPathGroupModal = ref(false);
const commit_spin = ref(false);

const isLegacyRule = computed(
  () => rule.value?.match_rule.t === "legacy_path_prefix",
);
const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_rule_json.value;
});
const rule_enabled = computed({
  get() {
    return rule.value?.enable ?? false;
  },
  set(value: boolean) {
    if (rule.value && !isLegacyRule.value) {
      rule.value.enable = value;
    }
  },
});
const domainItems = computed(() => rule.value?.domains ?? []);

const matchTypeOptions = [
  { label: () => t("gateway.type_host"), value: "host" },
  { label: () => t("gateway.type_sni_proxy"), value: "sni_proxy" },
];

const lbOptions = [
  { label: () => t("gateway.lb_round_robin"), value: "round_robin" },
  { label: () => t("gateway.lb_random"), value: "random" },
  { label: () => t("gateway.lb_consistent"), value: "consistent" },
];

const headerModeOptions = [
  { label: () => t("gateway.header_mode_set"), value: "set" },
  { label: () => t("gateway.header_mode_append"), value: "append" },
];

const rewriteModeOptions = [
  { label: () => t("gateway.rewrite_preserve"), value: "preserve" },
  { label: () => t("gateway.rewrite_strip_prefix"), value: "strip_prefix" },
];

function cloneData<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function defaultTarget() {
  return {
    address: "",
    port: 80,
    weight: 1,
    tls: false,
    skip_cert_verify: false,
  };
}

function defaultUpstreamConfig(
  clientIpHeaders: ClientIpHeaderPolicy = "standard" as ClientIpHeaderPolicy,
): HttpUpstreamConfig {
  return {
    targets: [defaultTarget()],
    load_balance: "round_robin" as LoadBalanceMethod,
    health_check: null,
    request_headers: [],
    header_conflict_mode: "set" as ProxyHeaderConflictMode,
    client_ip_headers: clientIpHeaders,
  };
}

function defaultPathGroup(): HttpPathGroup {
  return {
    prefix: "/",
    rewrite_mode: "preserve" as PathRewriteMode,
    upstream: defaultUpstreamConfig(),
  };
}

function defaultRule(): HttpUpstreamRuleConfig {
  return {
    enable: true,
    name: "",
    domains: [""],
    match_rule: { t: "host", path_groups: [] },
    upstream: defaultUpstreamConfig(),
  };
}

function ensureUpstream(upstream: HttpUpstreamConfig, isSniProxy = false) {
  upstream.targets ??= [defaultTarget()];
  upstream.load_balance ??= "round_robin" as LoadBalanceMethod;
  upstream.request_headers ??= [];
  upstream.header_conflict_mode ??= "set" as ProxyHeaderConflictMode;
  upstream.client_ip_headers ??= isSniProxy
    ? ("none" as ClientIpHeaderPolicy)
    : ("standard" as ClientIpHeaderPolicy);

  if (isSniProxy) {
    upstream.request_headers = [];
    upstream.client_ip_headers = "none" as ClientIpHeaderPolicy;
  }
}

function normalizeRule() {
  if (!rule.value) return;

  rule.value.domains ??= [""];
  ensureUpstream(rule.value.upstream, rule.value.match_rule.t === "sni_proxy");

  if (rule.value.match_rule.t === "host") {
    rule.value.match_rule.path_groups ??= [];
    for (const group of rule.value.match_rule.path_groups) {
      group.rewrite_mode ??= "preserve" as PathRewriteMode;
      ensureUpstream(group.upstream, false);
    }
  }
}

async function enter() {
  if (props.rule_id) {
    rule.value = await get_gateway_rule(props.rule_id);
  } else {
    rule.value = defaultRule();
  }

  normalizeRule();
  origin_rule_json.value = JSON.stringify(rule.value);
}

function onMatchTypeChange(newType: string) {
  if (!rule.value || isLegacyRule.value) return;
  if (rule.value.match_rule.t === newType) return;

  if (newType === "host") {
    rule.value.match_rule = { t: "host", path_groups: [] };
    ensureUpstream(rule.value.upstream, false);
  } else if (newType === "sni_proxy") {
    rule.value.match_rule = { t: "sni_proxy" };
    ensureUpstream(rule.value.upstream, true);
  }
}

function addDomain() {
  if (!rule.value) return;
  rule.value.domains ??= [];
  rule.value.domains.push("");
}

function removeDomain(index: number) {
  if (!rule.value) return;
  rule.value.domains ??= [];
  if (rule.value.domains.length > 1) {
    rule.value.domains.splice(index, 1);
  }
}

function updateDomain(index: number, value: string) {
  if (!rule.value) return;
  rule.value.domains ??= [];
  rule.value.domains[index] = value;
}

function pathGroups(): HttpPathGroup[] {
  if (!rule.value || rule.value.match_rule.t !== "host") return [];
  rule.value.match_rule.path_groups ??= [];
  return rule.value.match_rule.path_groups;
}

function addTarget(upstream: HttpUpstreamConfig) {
  upstream.targets.push(defaultTarget());
}

function removeTarget(upstream: HttpUpstreamConfig, index: number) {
  if (upstream.targets.length > 1) {
    upstream.targets.splice(index, 1);
  }
}

function setTargetTls(target: HttpUpstreamTarget, value: boolean) {
  target.tls = value;
  if (!value) {
    target.skip_cert_verify = false;
  }
}

function addHeader(upstream: HttpUpstreamConfig) {
  upstream.request_headers ??= [];
  upstream.request_headers.push({ name: "", value: "" });
}

function removeHeader(upstream: HttpUpstreamConfig, index: number) {
  upstream.request_headers ??= [];
  upstream.request_headers.splice(index, 1);
}

function onClientIpToggle(upstream: HttpUpstreamConfig, val: boolean) {
  upstream.client_ip_headers = val
    ? ("standard" as ClientIpHeaderPolicy)
    : ("none" as ClientIpHeaderPolicy);
}

function onHealthCheckToggle(upstream: HttpUpstreamConfig, val: boolean) {
  if (val) {
    upstream.health_check = {
      interval_secs: 10,
      timeout_secs: 5,
      healthy_threshold: 3,
      unhealthy_threshold: 3,
    };
  } else {
    upstream.health_check = null;
  }
}

function updateRuleClientIp(val: boolean) {
  if (!rule.value) return;
  onClientIpToggle(rule.value.upstream, val);
}

function updateRuleHealthCheck(val: boolean) {
  if (!rule.value) return;
  onHealthCheckToggle(rule.value.upstream, val);
}

function updateDraftClientIp(val: boolean) {
  if (!pathGroupDraft.value) return;
  onClientIpToggle(pathGroupDraft.value.upstream, val);
}

function updateDraftHealthCheck(val: boolean) {
  if (!pathGroupDraft.value) return;
  onHealthCheckToggle(pathGroupDraft.value.upstream, val);
}

function upstreamSummary(upstream: HttpUpstreamConfig): string {
  if (upstream.targets.length === 0) return "-";
  if (upstream.targets.length === 1) {
    const target = upstream.targets[0];
    return `${frontEndStore.MASK_INFO(target.address)}:${target.port}${target.tls ? " (TLS)" : ""}`;
  }
  return `${upstream.targets.length} targets`;
}

function openPathGroupModal(index?: number) {
  if (!rule.value || rule.value.match_rule.t !== "host") return;

  if (typeof index === "number") {
    pathGroupDraft.value = cloneData(pathGroups()[index]);
    pathGroupEditIndex.value = index;
  } else {
    pathGroupDraft.value = defaultPathGroup();
    pathGroupEditIndex.value = null;
  }

  ensureUpstream(pathGroupDraft.value.upstream, false);
  showPathGroupModal.value = true;
}

function deletePathGroup(index: number) {
  pathGroups().splice(index, 1);
}

function sanitizeHeaders(
  upstream: HttpUpstreamConfig,
  allowHeaders: boolean,
): ProxyRequestHeader[] | null {
  if (!allowHeaders) {
    upstream.request_headers = [];
    upstream.client_ip_headers = "none" as ClientIpHeaderPolicy;
    return [];
  }

  const validHeaders: ProxyRequestHeader[] = [];
  for (const header of upstream.request_headers ?? []) {
    const name = header.name.trim();
    if (!name && header.value === "") {
      continue;
    }
    if (!name) {
      message.error(t("gateway.header_name_required"));
      return null;
    }
    validHeaders.push({ name, value: header.value });
  }

  return validHeaders;
}

function sanitizeUpstream(
  upstream: HttpUpstreamConfig,
  allowHeaders: boolean,
): boolean {
  const validTargets = upstream.targets.filter(
    (target) => target.address.trim() !== "",
  );
  if (validTargets.length === 0) {
    message.error(t("gateway.target_required"));
    return false;
  }
  upstream.targets = validTargets;

  const validHeaders = sanitizeHeaders(upstream, allowHeaders);
  if (!validHeaders) {
    return false;
  }
  upstream.request_headers = validHeaders;
  return true;
}

function savePathGroup() {
  if (!pathGroupDraft.value || rule.value?.match_rule.t !== "host") return;

  const prefix = pathGroupDraft.value.prefix.trim();
  if (!prefix || !prefix.startsWith("/")) {
    message.error(t("gateway.path_prefix_required"));
    return;
  }

  pathGroupDraft.value.prefix = prefix;
  if (!sanitizeUpstream(pathGroupDraft.value.upstream, true)) {
    return;
  }

  const next = cloneData(pathGroupDraft.value);
  if (pathGroupEditIndex.value === null) {
    pathGroups().push(next);
  } else {
    pathGroups()[pathGroupEditIndex.value] = next;
  }

  showPathGroupModal.value = false;
  pathGroupDraft.value = undefined;
  pathGroupEditIndex.value = null;
}

async function saveRule() {
  if (!rule.value || isLegacyRule.value) return;

  const name = rule.value.name.trim();
  if (!name) {
    message.error(t("gateway.name_required"));
    return;
  }
  rule.value.name = name;

  const domains = (rule.value.domains ?? [])
    .map((domain) => domain.trim())
    .filter((domain) => domain !== "");
  if (domains.length === 0) {
    message.error(t("gateway.domains_required"));
    return;
  }
  rule.value.domains = domains;

  const isSniProxy = rule.value.match_rule.t === "sni_proxy";
  if (!sanitizeUpstream(rule.value.upstream, !isSniProxy)) {
    return;
  }

  if (rule.value.match_rule.t === "host") {
    for (const group of rule.value.match_rule.path_groups ?? []) {
      group.prefix = group.prefix.trim();
      if (!group.prefix || !group.prefix.startsWith("/")) {
        message.error(t("gateway.path_prefix_required"));
        return;
      }
      if (!sanitizeUpstream(group.upstream, true)) {
        return;
      }
    }
  }

  commit_spin.value = true;
  try {
    await push_gateway_rule(rule.value);
    show.value = false;
    emit("refresh");
  } finally {
    commit_spin.value = false;
  }
}
</script>

<template>
  <ConfigModal
    v-model:show="show"
    v-model:enabled="rule_enabled"
    :title="t('gateway.edit_title')"
    :switch-disabled="!rule || isLegacyRule"
    width="1100px"
    @after-enter="enter"
  >
    <div v-if="rule" class="editor-shell">
      <n-scrollbar class="editor-scrollbar" :x-scrollable="false">
        <div class="editor-content">
          <n-alert v-if="isLegacyRule" type="warning" :bordered="false">
            {{ t("gateway.legacy_read_only") }}
          </n-alert>

          <div
            class="editor-columns"
            :class="{ 'editor-columns--single': rule.match_rule.t !== 'host' }"
          >
            <div class="editor-sidebar">
              <n-card class="editor-panel" embedded :bordered="false">
                <n-form label-placement="top">
                  <n-grid :cols="1" :x-gap="12">
                    <n-form-item-gi :label="t('gateway.name')">
                      <n-input v-model:value="rule.name" />
                    </n-form-item-gi>

                    <n-form-item-gi
                      v-if="!isLegacyRule"
                      :label="t('gateway.match_type')"
                    >
                      <n-radio-group
                        :value="rule.match_rule.t"
                        @update:value="onMatchTypeChange"
                      >
                        <n-radio-button
                          v-for="opt in matchTypeOptions"
                          :key="opt.value"
                          :value="opt.value"
                          :label="opt.label()"
                        />
                      </n-radio-group>
                    </n-form-item-gi>

                    <n-form-item-gi :label="t('gateway.domains')">
                      <n-flex vertical style="width: 100%; gap: 8px">
                        <n-flex
                          v-for="(domain, index) in domainItems"
                          :key="index"
                          align="center"
                          style="gap: 8px"
                        >
                          <n-input
                            :value="domain"
                            @update:value="
                              (value: string) => updateDomain(index, value)
                            "
                            :placeholder="t('gateway.domain_placeholder')"
                            style="flex: 1"
                            :disabled="isLegacyRule"
                          />
                          <n-button
                            v-if="domainItems.length > 1 && !isLegacyRule"
                            size="small"
                            @click="removeDomain(index)"
                            secondary
                            type="error"
                          >
                            {{ t("common.delete") }}
                          </n-button>
                        </n-flex>
                        <n-button
                          v-if="!isLegacyRule"
                          @click="addDomain"
                          dashed
                          block
                          size="small"
                        >
                          {{ t("gateway.add_domain") }}
                        </n-button>
                      </n-flex>
                    </n-form-item-gi>
                  </n-grid>
                </n-form>
              </n-card>

              <n-card class="editor-panel" embedded :bordered="false">
                <n-flex vertical style="gap: 12px">
                  <div class="section-title">
                    {{
                      rule.match_rule.t === "host"
                        ? t("gateway.default_upstream")
                        : t("gateway.upstream")
                    }}
                  </div>

                  <n-grid :cols="3" :x-gap="12">
                    <n-form-item-gi :label="t('gateway.targets')" :span="3">
                      <n-flex vertical style="width: 100%; gap: 8px">
                        <n-flex
                          v-for="(target, index) in rule.upstream.targets"
                          :key="index"
                          align="center"
                          style="gap: 8px"
                        >
                          <n-input
                            v-model:value="target.address"
                            :placeholder="t('gateway.target_address')"
                            style="flex: 2"
                            :disabled="isLegacyRule"
                          />
                          <n-input-number
                            v-model:value="target.port"
                            :min="1"
                            :max="65535"
                            :placeholder="t('gateway.target_port')"
                            style="flex: 1"
                            :disabled="isLegacyRule"
                          />
                          <n-input-number
                            v-model:value="target.weight"
                            :min="1"
                            :max="100"
                            :placeholder="t('gateway.target_weight')"
                            style="width: 80px"
                            :disabled="isLegacyRule"
                          />
                          <n-tooltip
                            trigger="hover"
                            :style="{ maxWidth: '240px' }"
                          >
                            <template #trigger>
                              <n-checkbox
                                :checked="target.tls"
                                :disabled="isLegacyRule"
                                @update:checked="
                                  (v: boolean) => setTargetTls(target, v)
                                "
                              >
                                TLS
                              </n-checkbox>
                            </template>
                            {{ t("gateway.target_tls_tip") }}
                          </n-tooltip>
                          <n-tooltip
                            trigger="hover"
                            :style="{ maxWidth: '240px' }"
                          >
                            <template #trigger>
                              <n-checkbox
                                v-model:checked="target.skip_cert_verify"
                                :disabled="isLegacyRule || !target.tls"
                              >
                                {{ t("gateway.target_skip_cert_verify") }}
                              </n-checkbox>
                            </template>
                            {{ t("gateway.target_skip_cert_verify_tip") }}
                          </n-tooltip>
                          <n-button
                            v-if="
                              rule.upstream.targets.length > 1 && !isLegacyRule
                            "
                            size="small"
                            @click="removeTarget(rule.upstream, index)"
                            secondary
                            type="error"
                          >
                            {{ t("common.delete") }}
                          </n-button>
                        </n-flex>
                        <n-button
                          v-if="!isLegacyRule"
                          @click="addTarget(rule.upstream)"
                          dashed
                          block
                          size="small"
                        >
                          {{ t("gateway.add_target") }}
                        </n-button>
                      </n-flex>
                    </n-form-item-gi>

                    <n-form-item-gi
                      :label="t('gateway.load_balance')"
                      :span="1"
                    >
                      <n-radio-group
                        v-model:value="rule.upstream.load_balance"
                        :disabled="isLegacyRule"
                      >
                        <n-radio-button
                          v-for="opt in lbOptions"
                          :key="opt.value"
                          :value="opt.value"
                          :label="opt.label()"
                        />
                      </n-radio-group>
                    </n-form-item-gi>

                    <template v-if="rule.match_rule.t === 'host'">
                      <n-form-item-gi
                        :label="t('gateway.client_ip_headers')"
                        :span="1"
                        :offset="1"
                      >
                        <n-switch
                          :value="rule.upstream.client_ip_headers !== 'none'"
                          @update:value="updateRuleClientIp"
                          :disabled="isLegacyRule"
                        >
                          <template #checked>
                            {{ t("gateway.client_ip_standard") }}
                          </template>
                          <template #unchecked>
                            {{ t("gateway.client_ip_disabled") }}
                          </template>
                        </n-switch>
                      </n-form-item-gi>

                      <n-form-item-gi
                        :label="t('gateway.request_headers')"
                        :span="3"
                      >
                        <n-flex vertical style="width: 100%; gap: 8px">
                          <n-flex
                            v-for="(header, index) in rule.upstream
                              .request_headers ?? []"
                            :key="index"
                            align="center"
                            style="gap: 8px"
                          >
                            <n-input
                              v-model:value="header.name"
                              :placeholder="t('gateway.header_name')"
                              style="flex: 1"
                              :disabled="isLegacyRule"
                            />
                            <n-input
                              v-model:value="header.value"
                              :placeholder="t('gateway.header_value')"
                              style="flex: 1.2"
                              :disabled="isLegacyRule"
                            />
                            <n-button
                              v-if="!isLegacyRule"
                              size="small"
                              @click="removeHeader(rule.upstream, index)"
                              secondary
                              type="error"
                            >
                              {{ t("common.delete") }}
                            </n-button>
                          </n-flex>
                          <n-button
                            v-if="!isLegacyRule"
                            @click="addHeader(rule.upstream)"
                            dashed
                            block
                            size="small"
                          >
                            {{ t("gateway.add_header") }}
                          </n-button>
                        </n-flex>
                      </n-form-item-gi>

                      <n-form-item-gi
                        v-if="(rule.upstream.request_headers ?? []).length > 0"
                        :label="t('gateway.header_mode')"
                        :span="2"
                      >
                        <n-radio-group
                          v-model:value="rule.upstream.header_conflict_mode"
                          :disabled="isLegacyRule"
                        >
                          <n-radio-button
                            v-for="opt in headerModeOptions"
                            :key="opt.value"
                            :value="opt.value"
                            :label="opt.label()"
                          />
                        </n-radio-group>
                      </n-form-item-gi>
                    </template>

                    <n-form-item-gi
                      :label="t('gateway.health_check')"
                      :span="2"
                    >
                      <n-switch
                        :value="!!rule.upstream.health_check"
                        @update:value="updateRuleHealthCheck"
                        :disabled="isLegacyRule"
                      >
                        <template #checked> {{ t("common.enable") }} </template>
                        <template #unchecked>
                          {{ t("common.disable") }}
                        </template>
                      </n-switch>
                    </n-form-item-gi>

                    <template v-if="rule.upstream.health_check">
                      <n-form-item-gi :label="t('gateway.hc_interval')">
                        <n-input-number
                          v-model:value="
                            rule.upstream.health_check.interval_secs
                          "
                          :min="1"
                          :disabled="isLegacyRule"
                        />
                      </n-form-item-gi>
                      <n-form-item-gi :label="t('gateway.hc_timeout')">
                        <n-input-number
                          v-model:value="
                            rule.upstream.health_check.timeout_secs
                          "
                          :min="1"
                          :disabled="isLegacyRule"
                        />
                      </n-form-item-gi>
                      <n-form-item-gi
                        :label="t('gateway.hc_healthy_threshold')"
                      >
                        <n-input-number
                          v-model:value="
                            rule.upstream.health_check.healthy_threshold
                          "
                          :min="1"
                          :disabled="isLegacyRule"
                        />
                      </n-form-item-gi>
                      <n-form-item-gi
                        :label="t('gateway.hc_unhealthy_threshold')"
                      >
                        <n-input-number
                          v-model:value="
                            rule.upstream.health_check.unhealthy_threshold
                          "
                          :min="1"
                          :disabled="isLegacyRule"
                        />
                      </n-form-item-gi>
                    </template>
                  </n-grid>
                </n-flex>
              </n-card>
            </div>

            <div v-if="rule.match_rule.t === 'host'" class="editor-main">
              <n-card class="editor-panel" embedded :bordered="false">
                <n-flex vertical style="gap: 12px">
                  <n-flex justify="space-between" align="center">
                    <div class="section-title">
                      {{ t("gateway.path_groups") }}
                    </div>
                    <n-button
                      size="small"
                      type="primary"
                      @click="openPathGroupModal()"
                    >
                      {{ t("gateway.add_path_group") }}
                    </n-button>
                  </n-flex>

                  <n-empty
                    v-if="pathGroups().length === 0"
                    size="small"
                    :description="t('gateway.no_path_groups')"
                  />

                  <n-grid v-else :cols="1" :y-gap="10">
                    <n-gi
                      v-for="(group, index) in pathGroups()"
                      :key="`${group.prefix}-${index}`"
                    >
                      <n-card
                        size="small"
                        embedded
                        :bordered="false"
                        class="path-group-card"
                      >
                        <n-flex justify="space-between" align="center">
                          <n-flex vertical size="small">
                            <n-flex align="center" size="small">
                              <n-tag size="small" :bordered="false">
                                {{ frontEndStore.MASK_INFO(group.prefix) }}
                              </n-tag>
                              <n-tag size="small" type="info" :bordered="false">
                                {{
                                  group.rewrite_mode === "strip_prefix"
                                    ? t("gateway.rewrite_strip_prefix")
                                    : t("gateway.rewrite_preserve")
                                }}
                              </n-tag>
                            </n-flex>
                            <n-text depth="3" style="font-size: 12px">
                              {{ upstreamSummary(group.upstream) }}
                            </n-text>
                          </n-flex>

                          <n-flex size="small">
                            <n-button
                              size="small"
                              secondary
                              @click="openPathGroupModal(index)"
                            >
                              {{ t("common.edit") }}
                            </n-button>
                            <n-button
                              size="small"
                              secondary
                              type="error"
                              @click="deletePathGroup(index)"
                            >
                              {{ t("common.delete") }}
                            </n-button>
                          </n-flex>
                        </n-flex>
                      </n-card>
                    </n-gi>
                  </n-grid>
                </n-flex>
              </n-card>
            </div>
          </div>
        </div>
      </n-scrollbar>
    </div>

    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{ t("common.cancel") }}</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveRule"
          :disabled="!isModified || isLegacyRule"
        >
          {{ t("common.save") }}
        </n-button>
      </n-flex>
    </template>
  </ConfigModal>

  <n-modal
    v-model:show="showPathGroupModal"
    style="width: 760px"
    class="custom-card"
    preset="card"
    :title="t('gateway.path_group_editor')"
    :bordered="false"
  >
    <n-scrollbar class="path-group-scrollbar" :x-scrollable="false">
      <n-form v-if="pathGroupDraft" label-placement="top">
        <n-grid :cols="2" :x-gap="12">
          <n-form-item-gi :label="t('gateway.path_prefix')" :span="2">
            <n-input
              v-model:value="pathGroupDraft.prefix"
              :placeholder="t('gateway.path_prefix_placeholder')"
            />
          </n-form-item-gi>

          <n-form-item-gi :label="t('gateway.rewrite_mode')" :span="2">
            <n-radio-group v-model:value="pathGroupDraft.rewrite_mode">
              <n-radio-button
                v-for="opt in rewriteModeOptions"
                :key="opt.value"
                :value="opt.value"
                :label="opt.label()"
              />
            </n-radio-group>
          </n-form-item-gi>

          <n-divider style="margin: 4px 0; grid-column: span 2" />

          <n-form-item-gi :label="t('gateway.targets')" :span="2">
            <n-flex vertical style="width: 100%; gap: 8px">
              <n-flex
                v-for="(target, index) in pathGroupDraft.upstream.targets"
                :key="index"
                align="center"
                style="gap: 8px"
              >
                <n-input
                  v-model:value="target.address"
                  :placeholder="t('gateway.target_address')"
                  style="flex: 2"
                />
                <n-input-number
                  v-model:value="target.port"
                  :min="1"
                  :max="65535"
                  :placeholder="t('gateway.target_port')"
                  style="flex: 1"
                />
                <n-input-number
                  v-model:value="target.weight"
                  :min="1"
                  :max="100"
                  :placeholder="t('gateway.target_weight')"
                  style="width: 80px"
                />
                <n-tooltip trigger="hover" :style="{ maxWidth: '240px' }">
                  <template #trigger>
                    <n-checkbox
                      :checked="target.tls"
                      @update:checked="(v: boolean) => setTargetTls(target, v)"
                    >
                      TLS
                    </n-checkbox>
                  </template>
                  {{ t("gateway.target_tls_tip") }}
                </n-tooltip>
                <n-tooltip trigger="hover" :style="{ maxWidth: '240px' }">
                  <template #trigger>
                    <n-checkbox
                      v-model:checked="target.skip_cert_verify"
                      :disabled="!target.tls"
                    >
                      {{ t("gateway.target_skip_cert_verify") }}
                    </n-checkbox>
                  </template>
                  {{ t("gateway.target_skip_cert_verify_tip") }}
                </n-tooltip>
                <n-button
                  v-if="pathGroupDraft.upstream.targets.length > 1"
                  size="small"
                  @click="removeTarget(pathGroupDraft.upstream, index)"
                  secondary
                  type="error"
                >
                  {{ t("common.delete") }}
                </n-button>
              </n-flex>
              <n-button
                @click="addTarget(pathGroupDraft.upstream)"
                dashed
                block
                size="small"
              >
                {{ t("gateway.add_target") }}
              </n-button>
            </n-flex>
          </n-form-item-gi>

          <n-form-item-gi :label="t('gateway.load_balance')" :span="2">
            <n-radio-group v-model:value="pathGroupDraft.upstream.load_balance">
              <n-radio-button
                v-for="opt in lbOptions"
                :key="opt.value"
                :value="opt.value"
                :label="opt.label()"
              />
            </n-radio-group>
          </n-form-item-gi>

          <n-form-item-gi :label="t('gateway.client_ip_headers')" :span="2">
            <n-switch
              :value="pathGroupDraft.upstream.client_ip_headers !== 'none'"
              @update:value="updateDraftClientIp"
            >
              <template #checked>
                {{ t("gateway.client_ip_standard") }}
              </template>
              <template #unchecked>
                {{ t("gateway.client_ip_disabled") }}
              </template>
            </n-switch>
          </n-form-item-gi>

          <n-form-item-gi :label="t('gateway.request_headers')" :span="2">
            <n-flex vertical style="width: 100%; gap: 8px">
              <n-flex
                v-for="(header, index) in pathGroupDraft.upstream
                  .request_headers ?? []"
                :key="index"
                align="center"
                style="gap: 8px"
              >
                <n-input
                  v-model:value="header.name"
                  :placeholder="t('gateway.header_name')"
                  style="flex: 1"
                />
                <n-input
                  v-model:value="header.value"
                  :placeholder="t('gateway.header_value')"
                  style="flex: 1.2"
                />
                <n-button
                  size="small"
                  @click="removeHeader(pathGroupDraft.upstream, index)"
                  secondary
                  type="error"
                >
                  {{ t("common.delete") }}
                </n-button>
              </n-flex>
              <n-button
                @click="addHeader(pathGroupDraft.upstream)"
                dashed
                block
                size="small"
              >
                {{ t("gateway.add_header") }}
              </n-button>
            </n-flex>
          </n-form-item-gi>

          <n-form-item-gi
            v-if="(pathGroupDraft.upstream.request_headers ?? []).length > 0"
            :label="t('gateway.header_mode')"
            :span="2"
          >
            <n-radio-group
              v-model:value="pathGroupDraft.upstream.header_conflict_mode"
            >
              <n-radio-button
                v-for="opt in headerModeOptions"
                :key="opt.value"
                :value="opt.value"
                :label="opt.label()"
              />
            </n-radio-group>
          </n-form-item-gi>

          <n-form-item-gi :label="t('gateway.health_check')" :span="2">
            <n-switch
              :value="!!pathGroupDraft.upstream.health_check"
              @update:value="updateDraftHealthCheck"
            >
              <template #checked> {{ t("common.enable") }} </template>
              <template #unchecked> {{ t("common.disable") }} </template>
            </n-switch>
          </n-form-item-gi>

          <template v-if="pathGroupDraft.upstream.health_check">
            <n-form-item-gi :label="t('gateway.hc_interval')">
              <n-input-number
                v-model:value="
                  pathGroupDraft.upstream.health_check.interval_secs
                "
                :min="1"
              />
            </n-form-item-gi>
            <n-form-item-gi :label="t('gateway.hc_timeout')">
              <n-input-number
                v-model:value="
                  pathGroupDraft.upstream.health_check.timeout_secs
                "
                :min="1"
              />
            </n-form-item-gi>
            <n-form-item-gi :label="t('gateway.hc_healthy_threshold')">
              <n-input-number
                v-model:value="
                  pathGroupDraft.upstream.health_check.healthy_threshold
                "
                :min="1"
              />
            </n-form-item-gi>
            <n-form-item-gi :label="t('gateway.hc_unhealthy_threshold')">
              <n-input-number
                v-model:value="
                  pathGroupDraft.upstream.health_check.unhealthy_threshold
                "
                :min="1"
              />
            </n-form-item-gi>
          </template>
        </n-grid>
      </n-form>
    </n-scrollbar>

    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="showPathGroupModal = false">
          {{ t("common.cancel") }}
        </n-button>
        <n-button type="primary" @click="savePathGroup">
          {{ t("common.save") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>

<style scoped>
.editor-shell {
  display: flex;
  flex-direction: column;
}

.editor-scrollbar {
  max-height: 72vh;
}

.editor-content {
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding-right: 6px;
}

.editor-columns {
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
  gap: 16px;
  align-items: start;
}

.editor-columns--single {
  grid-template-columns: minmax(0, 1fr);
}

.editor-sidebar,
.editor-main {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.editor-panel {
  border-radius: 14px;
}

.path-group-card {
  background: rgba(255, 255, 255, 0.72);
}

.path-group-scrollbar {
  max-height: 70vh;
}

.section-title {
  font-size: 14px;
  font-weight: 600;
}

@media (max-width: 960px) {
  .editor-scrollbar,
  .path-group-scrollbar {
    max-height: none;
  }

  .editor-content {
    padding-right: 0;
  }

  .editor-columns {
    grid-template-columns: 1fr;
  }
}
</style>
