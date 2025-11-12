package com.ot.security.repository;

import com.ot.security.entity.XaiAnalysis;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface XaiAnalysisRepository extends JpaRepository<XaiAnalysis, Long> {
}