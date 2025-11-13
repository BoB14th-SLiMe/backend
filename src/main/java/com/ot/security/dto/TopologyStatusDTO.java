package com.ot.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TopologyStatusDTO {
    private List<DeviceStatus> controlDevices;
    private List<DeviceStatus> devices;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DeviceStatus {
        private String assetId;
        private String name;
        private String ip;
        private String status;
        private String assetType;
    }
}
