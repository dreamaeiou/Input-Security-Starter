package org.example.input_security_starter.tracker;

import org.example.input_security_starter.event.SecurityEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory global attacker index for cross-session tracking.
 */
public class AttackerIndex {

    private final ConcurrentHashMap<String, AttackerProfile> profileMap = new ConcurrentHashMap<String, AttackerProfile>();
    private final ConcurrentHashMap<Integer, Set<String>> asnIndex = new ConcurrentHashMap<Integer, Set<String>>();
    private final ConcurrentHashMap<String, Set<String>> countryIndex = new ConcurrentHashMap<String, Set<String>>();
    private final ConcurrentHashMap<String, Long> recentlyActiveIps = new ConcurrentHashMap<String, Long>();

    private final int maxProfiles;
    private final int profileTtlDays;
    private final int evictionBatchSize;
    private final int statsUpdateInterval;
    private final int maxRecentSessions;
    private final int relatedTimeWindowMinutes;

    private final AtomicLong updateCounter = new AtomicLong(0L);
    private final Object evictionLock = new Object();

    public AttackerIndex(
        int maxProfiles,
        int profileTtlDays,
        int evictionBatchSize,
        int statsUpdateInterval,
        int maxRecentSessions,
        int relatedTimeWindowMinutes
    ) {
        this.maxProfiles = Math.max(1, maxProfiles);
        this.profileTtlDays = Math.max(1, profileTtlDays);
        this.evictionBatchSize = Math.max(1, evictionBatchSize);
        this.statsUpdateInterval = Math.max(1, statsUpdateInterval);
        this.maxRecentSessions = Math.max(1, maxRecentSessions);
        this.relatedTimeWindowMinutes = Math.max(1, relatedTimeWindowMinutes);
    }

    public AttackerProfile recordGlobalProfile(SecurityEvent event, AttackPhase phase, double riskScore, String threatLevel) {
        if (event == null || event.getIpAddress() == null || event.getIpAddress().trim().isEmpty()) {
            return null;
        }
        String ip = event.getIpAddress().trim();
        long now = System.currentTimeMillis();

        AttackerProfile profile = getOrCreateProfile(ip, now);
        if (profile == null) {
            return null;
        }

        profile.recordEvent(event, phase, riskScore, threatLevel, maxRecentSessions);
        recentlyActiveIps.put(ip, profile.getLastSeenTimestamp());
        refreshStaticIndexes(ip, profile);

        long count = updateCounter.incrementAndGet();
        if (count % statsUpdateInterval == 0) {
            evictExpiredAndOverflow();
        }
        return profile;
    }

    private AttackerProfile getOrCreateProfile(String ip, long now) {
        AttackerProfile existing = profileMap.get(ip);
        if (existing != null) {
            return existing;
        }

        if (profileMap.size() >= maxProfiles) {
            evictExpiredAndOverflow();
            if (profileMap.size() >= maxProfiles) {
                return null;
            }
        }

        AttackerProfile created = new AttackerProfile(ip, now);
        AttackerProfile winner = profileMap.putIfAbsent(ip, created);
        return winner != null ? winner : created;
    }

    private void refreshStaticIndexes(String ip, AttackerProfile profile) {
        Integer asn = profile.getAsn();
        if (asn != null && asn > 0) {
            asnIndex.computeIfAbsent(asn, k -> ConcurrentHashMap.newKeySet()).add(ip);
        }

        String country = profile.getCountry();
        if (country != null && !country.trim().isEmpty()) {
            countryIndex.computeIfAbsent(country.trim().toUpperCase(), k -> ConcurrentHashMap.newKeySet()).add(ip);
        }
    }

    public void evictExpiredAndOverflow() {
        synchronized (evictionLock) {
            long now = System.currentTimeMillis();
            long ttlMs = profileTtlDays * 24L * 60L * 60L * 1000L;
            if (ttlMs > 0) {
                for (Map.Entry<String, AttackerProfile> entry : profileMap.entrySet()) {
                    AttackerProfile profile = entry.getValue();
                    if (profile == null) {
                        continue;
                    }
                    if (now - profile.getLastSeenTimestamp() > ttlMs) {
                        removeProfile(entry.getKey(), profile);
                    }
                }
            }

            int overflow = profileMap.size() - maxProfiles;
            if (overflow > 0) {
                int toEvict = Math.min(Math.max(overflow, 1), evictionBatchSize);
                List<String> oldestIps = findOldestIps(toEvict);
                for (String ip : oldestIps) {
                    AttackerProfile profile = profileMap.get(ip);
                    if (profile != null) {
                        removeProfile(ip, profile);
                    }
                }
            }
        }
    }

    private List<String> findOldestIps(int limit) {
        List<Map.Entry<String, Long>> entries = new ArrayList<Map.Entry<String, Long>>(recentlyActiveIps.entrySet());
        entries.sort(Comparator.comparingLong(Map.Entry::getValue));
        int max = Math.min(limit, entries.size());
        List<String> oldest = new ArrayList<String>(max);
        for (int i = 0; i < max; i++) {
            oldest.add(entries.get(i).getKey());
        }
        return oldest;
    }

    private void removeProfile(String ip, AttackerProfile profile) {
        AttackerProfile removed = profileMap.remove(ip);
        if (removed == null) {
            return;
        }
        recentlyActiveIps.remove(ip);

        Integer asn = profile.getAsn();
        if (asn != null) {
            removeFromIndex(asnIndex, asn, ip);
        }

        String country = profile.getCountry();
        if (country != null) {
            removeFromIndex(countryIndex, country.trim().toUpperCase(), ip);
        }
    }

    private <K> void removeFromIndex(ConcurrentHashMap<K, Set<String>> index, K key, String ip) {
        Set<String> ips = index.get(key);
        if (ips == null) {
            return;
        }
        ips.remove(ip);
        if (ips.isEmpty()) {
            index.remove(key);
        }
    }

    public AttackerProfile getProfile(String ip) {
        if (ip == null) {
            return null;
        }
        return profileMap.get(ip.trim());
    }

    public Map<String, Object> getProfileSnapshot(String ip) {
        AttackerProfile profile = getProfile(ip);
        return profile != null ? profile.toMap() : Collections.<String, Object>emptyMap();
    }

    public List<RelatedAttacker> findRelatedAttackers(String ip, int limit) {
        AttackerProfile profile = getProfile(ip);
        if (profile == null) {
            return Collections.emptyList();
        }

        Map<String, RelatedScore> scores = new HashMap<String, RelatedScore>();

        Set<String> byAsn = findByAsn(profile.getAsn());
        for (String candidate : byAsn) {
            if (ip.equals(candidate)) {
                continue;
            }
            addScore(scores, candidate, 0.45, "same_asn");
        }

        List<String> topTypes = profile.getTopAttackTypes(3);
        if (!topTypes.isEmpty()) {
            for (Map.Entry<String, AttackerProfile> entry : profileMap.entrySet()) {
                String candidateIp = entry.getKey();
                if (ip.equals(candidateIp)) {
                    continue;
                }
                AttackerProfile candidate = entry.getValue();
                if (candidate == null) {
                    continue;
                }
                Map<String, Integer> candidateTypes = candidate.getAttackTypeCounts();
                int overlap = 0;
                for (String type : topTypes) {
                    if (candidateTypes.containsKey(type)) {
                        overlap++;
                    }
                }
                if (overlap > 0) {
                    double similarity = 0.35 * ((double) overlap / (double) topTypes.size());
                    addScore(scores, candidateIp, similarity, "same_attack_type");
                }
            }
        }

        long since = profile.getLastSeenTimestamp() - relatedTimeWindowMinutes * 60L * 1000L;
        for (Map.Entry<String, Long> entry : recentlyActiveIps.entrySet()) {
            if (ip.equals(entry.getKey())) {
                continue;
            }
            if (entry.getValue() >= since) {
                addScore(scores, entry.getKey(), 0.20, "same_time_window");
            }
        }

        List<RelatedAttacker> related = new ArrayList<RelatedAttacker>();
        for (Map.Entry<String, RelatedScore> entry : scores.entrySet()) {
            RelatedScore score = entry.getValue();
            double normalized = Math.max(0D, Math.min(1D, score.score));
            related.add(new RelatedAttacker(entry.getKey(), normalized, new ArrayList<String>(score.reasons)));
        }

        related.sort(new Comparator<RelatedAttacker>() {
            @Override
            public int compare(RelatedAttacker a, RelatedAttacker b) {
                return Double.compare(b.getSimilarity(), a.getSimilarity());
            }
        });

        int max = Math.min(Math.max(0, limit), related.size());
        if (max == related.size()) {
            return related;
        }
        return new ArrayList<RelatedAttacker>(related.subList(0, max));
    }

    private void addScore(Map<String, RelatedScore> scores, String ip, double add, String reason) {
        RelatedScore score = scores.computeIfAbsent(ip, k -> new RelatedScore());
        score.score += add;
        score.reasons.add(reason);
    }

    public Set<String> findByAsn(Integer asn) {
        if (asn == null) {
            return Collections.emptySet();
        }
        Set<String> ips = asnIndex.get(asn);
        return ips != null ? new HashSet<String>(ips) : Collections.<String>emptySet();
    }

    public Set<String> findByCountry(String country) {
        if (country == null || country.trim().isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> ips = countryIndex.get(country.trim().toUpperCase());
        return ips != null ? new HashSet<String>(ips) : Collections.<String>emptySet();
    }

    public int getProfileCount() {
        return profileMap.size();
    }

    public static class RelatedAttacker {
        private final String ip;
        private final double similarity;
        private final List<String> reasons;

        public RelatedAttacker(String ip, double similarity, List<String> reasons) {
            this.ip = ip;
            this.similarity = similarity;
            this.reasons = reasons != null ? reasons : Collections.<String>emptyList();
        }

        public String getIp() { return ip; }
        public double getSimilarity() { return similarity; }
        public List<String> getReasons() { return reasons; }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<String, Object>();
            map.put("ip", ip);
            map.put("similarity", similarity);
            map.put("reasons", new ArrayList<String>(new LinkedHashSet<String>(reasons)));
            return map;
        }
    }

    private static class RelatedScore {
        private double score;
        private final List<String> reasons = new ArrayList<String>();
    }
}
