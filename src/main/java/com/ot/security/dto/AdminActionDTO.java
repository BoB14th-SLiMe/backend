package com.ot.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminActionDTO {
    private Long id;
    private String threatId;
    private String status;      // 미작성, 작성중, 완료
    private String author;
    private String content;
    private String completedAt; // ISO 8601 format
    private String createdAt;
    private String updatedAt;
}