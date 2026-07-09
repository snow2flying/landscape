import { ServiceStatus } from "./services";

export enum ZoneType {
  Undefined = "undefined",
  Lan = "lan",
  Wan = "wan",
}
// 准备移除
export enum IfaceServiceType {
  Undefined = "undefined",
  Lan = "lan",
  Wan = "wan",
}

export type WanIpConfigMode =
  | { t: "nothing" }
  | { t: "static"; ipv4: number[]; ipv4_mask: number; ipv6: number[] }
  | { t: "pppoe"; username: string; password: string; mtu: number }
  | { t: "dhcpclient" };

export type LanIpConfigMode =
  | { t: "nothing" }
  | { t: "static"; ipv4: number[]; ipv4_mask: number; ipv6: number[] };

export type IfaceServiceConfig =
  | { t: IfaceServiceType.Undefined }
  | {
      t: IfaceServiceType.Lan;
      ip_config_enable: boolean;
      ip_config_mode: LanIpConfigMode;
    }
  | {
      t: IfaceServiceType.Wan;
      ip_config_enable: boolean;
      ip_config_mode: WanIpConfigMode;
    };

export type IfaceServiceStatus =
  | { t: IfaceServiceType.Undefined }
  | { t: IfaceServiceType.Wan; ip_config_status: ServiceStatus };

export enum IfaceIpMode {
  Nothing = "nothing",
  Static = "static",
  PPPoE = "pppoe",
  DHCPClient = "dhcpclient",
}
export type IfaceIpModelConfig =
  | { t: "nothing" }
  | {
      t: "static";
      default_router_ip: string | undefined;
      default_router: boolean;
      ipv4: string;
      ipv4_mask: number;
      ipv6: string | undefined;
    }
  | {
      t: "pppoe";
      default_router: boolean;
      username: string;
      password: string;
      mtu: number;
      ac_name?: string;
    }
  | { t: "dhcpclient"; default_router: boolean; hostname: string | undefined };

export class IfaceIpServiceConfig {
  iface_name: string;
  enable: boolean;
  ip_model: IfaceIpModelConfig;
  update_at?: number;

  constructor(obj?: {
    iface_name?: string;
    enable?: boolean;
    ip_model?: IfaceIpModelConfig;
    update_at?: number;
  }) {
    this.iface_name = obj?.iface_name ?? "";
    this.enable = obj?.enable ?? true;
    this.update_at = obj?.update_at;
    if (obj?.ip_model !== undefined) {
      switch (obj?.ip_model.t) {
        case IfaceIpMode.Nothing:
        case IfaceIpMode.Static:
        case IfaceIpMode.PPPoE:
        case IfaceIpMode.DHCPClient:
          this.ip_model = obj.ip_model;
          break;
        default:
          this.ip_model = obj?.ip_model ?? { t: "nothing" };
      }
    } else {
      this.ip_model = obj?.ip_model ?? { t: "nothing" };
    }
  }
}

export class StaticIpConfig {
  t: IfaceIpMode.Static;
  ipv4: number[];
  ipv4_mask: number;
  ipv6: number[];

  constructor(obj?: {
    ipv4?: [number, number, number, number];
    ipv4_mask?: number;
    ipv6?: number[];
  }) {
    this.t = IfaceIpMode.Static;
    this.ipv4 = obj?.ipv4 ?? [1, 1, 1, 1];
    this.ipv4_mask = obj?.ipv4_mask ?? 24;
    this.ipv6 = obj?.ipv6 ?? [];
  }
}
