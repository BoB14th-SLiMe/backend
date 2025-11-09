package com.ot.security.repository;

import com.ot.security.entity.Alarm;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface AlarmRepository extends JpaRepository<Alarm, Long> {
    Optional<Alarm> findByThreatId(String threatId);
    List<Alarm> findByStatus(String status);

    @Query("SELECT COUNT(a) FROM Alarm a WHERE a.status = 'unconfirmed'")
    long countUnconfirmed();

    @Query("SELECT COUNT(a) FROM Alarm a WHERE a.severity = 'critical' AND a.status != 'resolved'")
    long countCriticalUnresolved();
}