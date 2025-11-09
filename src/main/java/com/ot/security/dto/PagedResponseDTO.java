package com.ot.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 페이징 응답 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PagedResponseDTO<T> {
    private java.util.List<T> content;
    private long totalElements;
    private int totalPages;
    private int number;         // 현재 페이지 번호
    private int size;           // 페이지 크기
    
    @Builder.Default
    private boolean first = false;
    
    @Builder.Default
    private boolean last = false;
}
