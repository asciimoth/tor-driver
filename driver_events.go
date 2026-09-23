package tordriver

import (
	"strconv"
	"strings"

	"github.com/asciimoth/tor-driver/internal/control"
)

func (d *Driver) controlEventLoop() {
	for {
		select {
		case event := <-d.control.Events():
			d.handleControlEvent(event)
		case <-d.control.Done():
			return
		case <-d.done:
			return
		}
	}
}

func (d *Driver) handleControlEvent(event control.Event) {
	if len(event.Lines) == 0 {
		return
	}
	words, err := controlWords(event.Lines[0])
	if err != nil || len(words) == 0 {
		return
	}
	switch words[0] {
	case "STATUS_CLIENT":
		d.handleStatusClient(words)
	case "HS_DESC":
		d.handleDescriptorEvent(words)
	case "TRANSPORT_LAUNCHED":
		if len(words) >= 3 && words[1] == "client" {
			d.publishTransport(words[2], TransportReady, EventNotice)
		}
	case "PT_LOG":
		args := eventArguments(words[1:])
		severity, ok := eventSeverity(args["SEVERITY"])
		if ok && severity == EventError {
			d.publishTransport("", TransportFailed, severity)
		}
	case "PT_STATUS":
		args := eventArguments(words[1:])
		state := TransportReady
		severity := EventNotice
		for key, value := range args {
			if key == "PT" || key == "TRANSPORT" {
				continue
			}
			upper := strings.ToUpper(value)
			if strings.Contains(upper, "FAIL") || strings.Contains(upper, "ERROR") {
				state = TransportFailed
				severity = EventError
				break
			}
		}
		d.publishTransport(args["TRANSPORT"], state, severity)
	}
}

func (d *Driver) handleStatusClient(words []string) {
	if len(words) < 3 || words[2] != "BOOTSTRAP" {
		return
	}
	severity, ok := eventSeverity(words[1])
	if !ok {
		return
	}
	args := eventArguments(words[3:])
	progress, err := strconv.ParseUint(args["PROGRESS"], 10, 8)
	if err != nil || progress > 100 || !safeEventToken(args["TAG"]) {
		return
	}
	event := BootstrapEvent{
		Progress: uint8(progress),
		Stage:    BootstrapStage(args["TAG"]),
		Severity: severity,
	}
	if reason := args["REASON"]; safeEventToken(reason) {
		event.Problem = BootstrapProblem(reason)
	}
	d.mu.Lock()
	d.bootstrap = event
	d.haveBootstrap = true
	d.events.publish(event)
	d.mu.Unlock()
	if severity != EventNotice && strings.Contains(strings.ToUpper(string(event.Problem)), "PT") {
		d.publishTransport("", TransportFailed, severity)
	}
}

func (d *Driver) publishTransport(name string, state TransportState, severity EventSeverity) {
	kind := Transport(name)
	if kind != Obfs4 {
		if len(d.cfg.Transports) != 1 {
			return
		}
		kind = d.cfg.Transports[0].Kind
	}
	d.events.publish(TransportEvent{Transport: kind, State: state, Severity: severity})
}

func (d *Driver) handleDescriptorEvent(words []string) {
	if len(words) < 3 || !validServiceID(words[2]) {
		return
	}
	event := PublicationEvent{}
	switch words[1] {
	case "CREATED", "UPLOAD":
		event.State = PublicationPending
	case "UPLOADED":
		event.State = PublicationPublished
	case "FAILED":
		event.State = PublicationFailed
		args := eventArguments(words[3:])
		if reason := args["REASON"]; safeEventToken(reason) {
			event.Problem = PublicationProblem(reason)
		}
	default:
		return
	}
	id := words[2]
	d.mu.Lock()
	if len(d.descriptors) < 256 {
		d.descriptors[id] = event
	}
	var service *Service
	for candidate := range d.services {
		if candidate.id == id {
			service = candidate
			break
		}
	}
	d.mu.Unlock()
	if service != nil {
		service.handlePublication(event)
	}
}

func validServiceID(id string) bool {
	return len(id) == 56 && strings.Trim(id, "abcdefghijklmnopqrstuvwxyz234567") == ""
}
