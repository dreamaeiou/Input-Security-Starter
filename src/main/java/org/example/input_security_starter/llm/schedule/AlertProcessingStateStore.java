package org.example.input_security_starter.llm.schedule;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

public class AlertProcessingStateStore {

    private static final Logger log = LoggerFactory.getLogger(AlertProcessingStateStore.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final File stateFile;

    public AlertProcessingStateStore(String alertLogPath) {
        this.stateFile = new File(alertLogPath + ".state.json");
    }

    public synchronized AlertProcessingState load() {
        if (!stateFile.exists() || stateFile.length() == 0) {
            return new AlertProcessingState();
        }

        try {
            return OBJECT_MAPPER.readValue(stateFile, AlertProcessingState.class);
        } catch (IOException e) {
            log.warn("Failed to load alert processing state from {}: {}", stateFile.getAbsolutePath(), e.getMessage());
            return new AlertProcessingState();
        }
    }

    public synchronized void save(AlertProcessingState state) {
        if (state == null) {
            return;
        }

        File parent = stateFile.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            log.warn("Failed to create state directory: {}", parent.getAbsolutePath());
        }

        try {
            OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValue(stateFile, state);
        } catch (IOException e) {
            log.error("Failed to persist alert processing state to {}: {}", stateFile.getAbsolutePath(), e.getMessage());
        }
    }

    public File getStateFile() {
        return stateFile;
    }
}
