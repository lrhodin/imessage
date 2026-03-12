package connector

import "strings"

func isGroupPortalID(portalID string) bool {
	return strings.HasPrefix(portalID, "gid:") || strings.Contains(portalID, ",")
}

// normalizeUUID strips dashes and lowercases a UUID for comparison.
// APNs sends dashless (520464eb701340d7bd9e7ae51684e430) while CloudKit
// uses dashed (520464eb-7013-40d7-bd9e-7ae51684e430). This normalizes both.
func normalizeUUID(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "-", ""))
}

// groupPortalDedupKey returns a stable dedupe key for group portals.
// Prefer protocol group UUID when available; otherwise fall back to a
// normalized participant signature.
func groupPortalDedupKey(portalID, groupID string, participants []string) string {
	groupID = strings.TrimSpace(groupID)
	if groupID != "" {
		return "group:" + normalizeUUID(groupID)
	}
	if strings.HasPrefix(portalID, "gid:") {
		return "group:" + normalizeUUID(strings.TrimPrefix(portalID, "gid:"))
	}
	normalized := normalizeRecoverableParticipants(participants)
	if len(normalized) == 0 && strings.Contains(portalID, ",") {
		normalized = normalizeRecoverableParticipants(strings.Split(portalID, ","))
	}
	if len(normalized) > 0 {
		return "parts:" + strings.Join(normalized, ",")
	}
	return "portal:" + portalID
}
