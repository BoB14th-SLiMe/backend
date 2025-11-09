package com.ot.security.repository;

import com.ot.security.entity.Asset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface AssetRepository extends JpaRepository<Asset, Long> {
    Optional<Asset> findByAssetId(String assetId);
    List<Asset> findByAssetType(String assetType);
    List<Asset> findByIsVisible(Boolean isVisible);

    @Query("SELECT a FROM Asset a WHERE a.ipAddress = :ipAddress")
    Optional<Asset> findByIpAddress(String ipAddress);

    @Query("SELECT a FROM Asset a WHERE a.isVisible = true ORDER BY a.positionX, a.positionY")
    List<Asset> findVisibleAssetsOrdered();
}