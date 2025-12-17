package org.example.input_security_starter.event;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class EventRecorder {

    private final List<SecurityEvent> events = new ArrayList<>();

    public void record(SecurityEvent event) {
        events.add(event);
    }

    public List<SecurityEvent> getRecentEvents(int limit) {
        int from = Math.max(0, events.size() - limit);
        return new ArrayList<>(events.subList(from, events.size()));
    }
}