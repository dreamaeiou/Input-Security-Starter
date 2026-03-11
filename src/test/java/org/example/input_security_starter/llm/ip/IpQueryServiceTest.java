package org.example.input_security_starter.llm.ip;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class IpQueryServiceTest {

    @Test
    void shouldReturnCachedIntelligenceWhenAvailable(@TempDir Path tempDir) throws Exception {
        File logDir = tempDir.toFile();
        String logDirPath = logDir.getAbsolutePath();

        MockAbuseIpDbClient mockClient = new MockAbuseIpDbClient();
        mockClient.setIntelligence("1.2.3.4", createIntelligence("1.2.3.4", 85, 10, true));

        IpQueryService service = new IpQueryService(mockClient, logDirPath);

        java.util.Set<String> ips = new java.util.HashSet<String>();
        ips.add("1.2.3.4");

        java.util.Map<String, AbuseIpDbClient.IpIntelligence> result = service.getIpIntelligenceForAnalysis(ips);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertTrue(result.containsKey("1.2.3.4"));
        assertEquals(85, result.get("1.2.3.4").getAbuseConfidenceScore());
        assertTrue(result.get("1.2.3.4").isTor());
    }

    @Test
    void shouldReturnEmptyMapWhenNoIpsProvided(@TempDir Path tempDir) {
        IpQueryService service = new IpQueryService(null, tempDir.toString());

        java.util.Map<String, AbuseIpDbClient.IpIntelligence> result = 
            service.getIpIntelligenceForAnalysis(new java.util.HashSet<String>());

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void shouldHandleNullIpAddress(@TempDir Path tempDir) {
        IpQueryService service = new IpQueryService(null, tempDir.toString());

        java.util.Set<String> ips = new java.util.HashSet<String>();
        ips.add(null);
        ips.add("");
        ips.add("5.6.7.8");

        java.util.Map<String, AbuseIpDbClient.IpIntelligence> result = 
            service.getIpIntelligenceForAnalysis(ips);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void shouldPersistIndexAfterQuery(@TempDir Path tempDir) throws Exception {
        MockAbuseIpDbClient mockClient = new MockAbuseIpDbClient();
        mockClient.setIntelligence("10.20.30.40", createIntelligence("10.20.30.40", 50, 5, false));

        IpQueryService service = new IpQueryService(mockClient, tempDir.toString());

        java.util.Set<String> ips = new java.util.HashSet<String>();
        ips.add("10.20.30.40");
        service.getIpIntelligenceForAnalysis(ips);

        File indexFile = new File(tempDir.toFile(), "ip_index.json");
        assertTrue(indexFile.exists(), "Index file should be created");

        service.shutdown();
    }

    @Test
    void shouldReadFromLogWhenCached(@TempDir Path tempDir) throws Exception {
        String today = new java.text.SimpleDateFormat("yyyy-MM-dd").format(new java.util.Date());
        String logFileName = "ip_" + today + ".log";
        File logFile = new File(tempDir.toFile(), logFileName);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(logFile))) {
            writer.write("{\"ip\":\"192.168.1.1\",\"abuse_score\":75,\"total_reports\":3,\"is_tor\":false}");
            writer.newLine();
        }

        MockAbuseIpDbClient mockClient = new MockAbuseIpDbClient();
        IpQueryService service = new IpQueryService(mockClient, tempDir.toString());

        java.util.Set<String> ips = new java.util.HashSet<String>();
        ips.add("192.168.1.1");

        java.util.Map<String, AbuseIpDbClient.IpIntelligence> result = 
            service.getIpIntelligenceForAnalysis(ips);

        assertEquals(0, mockClient.getCallCount(), "Should read from log, not call API");
        assertNull(result.get("192.168.1.1"), "Index entry not found, so will query API");

        service.shutdown();
    }

    private AbuseIpDbClient.IpIntelligence createIntelligence(String ip, int abuseScore, 
                                                               int totalReports, boolean isTor) {
        AbuseIpDbClient.IpIntelligence intel = new AbuseIpDbClient.IpIntelligence();
        intel.setIpAddress(ip);
        intel.setAbuseConfidenceScore(abuseScore);
        intel.setTotalReports(totalReports);
        intel.setTor(isTor);
        intel.setFetchedAt(System.currentTimeMillis());
        return intel;
    }

    private static class MockAbuseIpDbClient extends AbuseIpDbClient {
        private final java.util.Map<String, IpIntelligence> intelligences = new java.util.HashMap<String, IpIntelligence>();
        private int callCount = 0;

        MockAbuseIpDbClient() {
            super("http://mock", "mock-key", 90);
        }

        void setIntelligence(String ip, IpIntelligence intel) {
            intelligences.put(ip, intel);
        }

        int getCallCount() {
            return callCount;
        }

        @Override
        public IpIntelligence checkIp(String ipAddress) {
            callCount++;
            return intelligences.get(ipAddress);
        }
    }
}
