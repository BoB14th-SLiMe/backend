package com.ot.security.repository;

import com.ot.security.entity.AssetStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface AssetStatusRepository extends JpaRepository<AssetStatus, String> {
    List<AssetStatus> findByStatus(String status);
}