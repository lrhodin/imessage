package connector

import (
	"context"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
)

func (c *IMClient) setContactsReady(log zerolog.Logger) {
	firstTime := false
	c.contactsReadyLock.Lock()
	if !c.contactsReady {
		c.contactsReady = true
		firstTime = true
		readyCh := c.contactsReadyCh
		c.contactsReadyLock.Unlock()
		if readyCh != nil {
			close(readyCh)
		}
		log.Info().Msg("Contacts readiness gate satisfied")
	} else {
		c.contactsReadyLock.Unlock()
	}

	// Re-resolve ghost and group names from contacts on every sync,
	// not just the first time. Contacts may have been added/edited in iCloud.
	if firstTime {
		log.Info().Msg("Running initial contact name resolution for ghosts and group portals")
	} else {
		log.Info().Msg("Re-syncing contact names for ghosts and group portals")
	}
	go c.refreshGhostNamesFromContacts(log)
	go c.refreshGroupPortalNamesFromContacts(log)
}

func (c *IMClient) refreshGhostNamesFromContacts(log zerolog.Logger) {
	if c.cloudContacts == nil {
		return
	}
	ctx := context.Background()

	// Get all ghost IDs from the database via the raw DB handle
	rows, err := c.Main.Bridge.DB.RawDB.QueryContext(ctx, "SELECT id, name FROM ghost")
	if err != nil {
		log.Err(err).Msg("Failed to query ghosts for contact name refresh")
		return
	}
	defer rows.Close()

	updated := 0
	total := 0
	for rows.Next() {
		var ghostID, ghostName string
		if err := rows.Scan(&ghostID, &ghostName); err != nil {
			continue
		}
		total++
		localID := stripIdentifierPrefix(ghostID)
		if localID == "" {
			continue
		}
		contact, _ := c.cloudContacts.GetContactInfo(localID)
		if contact == nil || !contact.HasName() {
			continue
		}
		name := c.Main.Config.FormatDisplayname(DisplaynameParams{
			FirstName: contact.FirstName,
			LastName:  contact.LastName,
			Nickname:  contact.Nickname,
			ID:        localID,
		})
		if ghostName != name {
			ghost, err := c.Main.Bridge.GetGhostByID(ctx, networkid.UserID(ghostID))
			if err != nil || ghost == nil {
				continue
			}
			ghost.UpdateInfo(ctx, &bridgev2.UserInfo{Name: &name})
			updated++
		}
	}
	log.Info().Int("updated", updated).Int("total", total).Msg("Refreshed ghost names from contacts")
}

// refreshGroupPortalNamesFromContacts re-resolves group portal names using
// contact data. Portals created before contacts loaded may have raw phone
// numbers / email addresses as the room name. This also picks up contact
// edits on subsequent periodic syncs.
func (c *IMClient) refreshGroupPortalNamesFromContacts(log zerolog.Logger) {
	if c.cloudContacts == nil {
		return
	}
	ctx := context.Background()

	portals, err := c.Main.Bridge.GetAllPortalsWithMXID(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to load portals for group name refresh")
		return
	}

	updated := 0
	total := 0
	for _, portal := range portals {
		if portal.Receiver != c.UserLogin.ID {
			continue
		}
		portalID := string(portal.ID)
		isGroup := strings.HasPrefix(portalID, "gid:") || strings.Contains(portalID, ",")
		if !isGroup {
			continue
		}
		total++

		newName := c.resolveGroupName(ctx, portalID)
		if newName == "" || newName == portal.Name {
			continue
		}

		c.UserLogin.QueueRemoteEvent(&simplevent.ChatInfoChange{
			EventMeta: simplevent.EventMeta{
				Type: bridgev2.RemoteEventChatInfoChange,
				PortalKey: networkid.PortalKey{
					ID:       portal.ID,
					Receiver: c.UserLogin.ID,
				},
				LogContext: func(lc zerolog.Context) zerolog.Context {
					return lc.Str("portal_id", portalID).Str("source", "group_name_refresh")
				},
			},
			ChatInfoChange: &bridgev2.ChatInfoChange{
				ChatInfo: &bridgev2.ChatInfo{
					Name: &newName,
				},
			},
		})
		updated++
	}
	log.Info().Int("updated", updated).Int("total_groups", total).Msg("Refreshed group portal names from contacts")
}
