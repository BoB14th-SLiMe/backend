package com.ot.security.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SystemMetricsDTO {

    @JsonProperty("cpu_usage")
    private Double cpuUsage;

    @JsonProperty("ram_usage")
    private Double ramUsage;

    @JsonProperty("gpu_usage")
    private Double gpuUsage;

    private String source;
}
