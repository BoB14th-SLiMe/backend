package com.ot.security.repository;

import com.ot.security.entity.Threat;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface ThreatRepository extends JpaRepository<Threat, String>, JpaSpecificationExecutor<Threat> {
    Optional<Threat> findByThreatIndex(Integer threatIndex);
    Optional<Threat> findByEventTimestamp(Instant eventTimestamp);
    Optional<Threat> findByEventTimestampAndThreatType(Instant eventTimestamp, String threatType);
    Optional<Threat> findTopByOrderByThreatIndexDesc();

    long countByEventTimestampAfter(Instant since);
    long countByEventTimestampBetween(Instant start, Instant end);
    long countByThreatLevelAndEventTimestampAfter(String threatLevel, Instant since);

    @Query("SELECT COUNT(t) FROM Threat t WHERE LOWER(t.status) IN :statuses")
    long countByStatusInIgnoreCase(@Param("statuses") Collection<String> statuses);

    @Query("SELECT COUNT(t) FROM Threat t WHERE LOWER(t.threatLevel) = LOWER(:level) AND LOWER(t.status) IN :statuses")
    long countByThreatLevelAndStatusInIgnoreCase(@Param("level") String level,
                                                 @Param("statuses") Collection<String> statuses);

    @Query("SELECT DISTINCT t.sourceIp FROM Threat t WHERE t.eventTimestamp >= :since AND t.sourceIp IS NOT NULL")
    List<String> findDistinctSourceIpSince(@Param("since") Instant since);

    @Query(value = "SELECT t FROM Threat t WHERE LOWER(t.status) IN :statuses ORDER BY t.eventTimestamp DESC",
            countQuery = "SELECT COUNT(t) FROM Threat t WHERE LOWER(t.status) IN :statuses")
    Page<Threat> findByStatusInIgnoreCase(@Param("statuses") Collection<String> statuses, Pageable pageable);
}
