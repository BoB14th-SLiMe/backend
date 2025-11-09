package com.ot.security.repository;

import com.ot.security.entity.AdminAction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface AdminActionRepository extends JpaRepository<AdminAction, Long> {
    Optional<AdminAction> findByThreatId(String threatId);
    boolean existsByThreatId(String threatId);
}