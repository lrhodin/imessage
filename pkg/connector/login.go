// mautrix-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2024 Ludvig Rhodin
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package connector

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/status"

	"github.com/lrhodin/imessage/pkg/rustpushgo"
)

const (
	LoginFlowIDAppleID       = "apple-id"
	LoginFlowIDExternalKey   = "external-key"
	LoginStepAppleIDPassword = "fi.mau.imessage.login.appleid"
	LoginStepExternalKey     = "fi.mau.imessage.login.externalkey"
	LoginStepTwoFactor       = "fi.mau.imessage.login.2fa"
	LoginStepSelectDevice    = "fi.mau.imessage.login.select_device"
	LoginStepDevicePasscode  = "fi.mau.imessage.login.device_passcode"
	LoginStepSelectHandle    = "fi.mau.imessage.login.select_handle"
	LoginStepBackfillChoice  = "fi.mau.imessage.login.backfill_choice"
	LoginStepHWKeySource     = "fi.mau.imessage.login.hw_key_source"
	LoginStepComplete        = "fi.mau.imessage.login.complete"
)

// Backfill select option values (matched against input["backfill"] at runtime).
const (
	backfillOptionYes = "Yes, enable message history backfill"
	backfillOptionNo  = "No, real-time messages only"
)

// Hardware key source select option values (ExternalKeyLogin only).
const (
	hwKeySourceDefault = "Use pre-shared hardware key"
	hwKeySourceCustom  = "Provide my own hardware key"
)

// backfillChoiceStep returns the login step that asks the user whether they
// want to enable CloudKit message history backfill. Only shown when the server
// has cloudkit_backfill enabled in config.
func backfillChoiceStep() *bridgev2.LoginStep {
	return &bridgev2.LoginStep{
		Type:   bridgev2.LoginStepTypeUserInput,
		StepID: LoginStepBackfillChoice,
		Instructions: "Do you want to enable message history backfill?\n\n" +
			"When enabled, the bridge will sync past messages from iCloud during setup. " +
			"This requires entering your device PIN to join the iCloud Keychain trust circle.\n\n" +
			"When disabled, only real-time messages are bridged — no PIN needed.",
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{{
				Type:    bridgev2.LoginInputFieldTypeSelect,
				ID:      "backfill",
				Name:    "Message history backfill",
				Options: []string{backfillOptionYes, backfillOptionNo},
			}},
		},
	}
}

// hwKeySourceStep returns the login step that lets the user choose between the
// server's pre-shared hardware key and supplying their own.
func hwKeySourceStep() *bridgev2.LoginStep {
	return &bridgev2.LoginStep{
		Type:   bridgev2.LoginStepTypeUserInput,
		StepID: LoginStepHWKeySource,
		Instructions: "A pre-shared hardware key is available for this bridge.\n\n" +
			"You may use it instead of extracting your own key from a Mac.\n\n" +
			"Warning: the pre-shared key is shared among all users of this bridge. " +
			"Apple may restrict or flag Apple IDs that register using a shared hardware identity. " +
			"If you have a Mac available, providing your own key is safer.",
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{{
				Type:    bridgev2.LoginInputFieldTypeSelect,
				ID:      "hw_key_source",
				Name:    "Hardware key source",
				Options: []string{hwKeySourceDefault, hwKeySourceCustom},
			}},
		},
	}
}

// hwKeyInputStep returns the login step that prompts the user to paste their
// hardware key (base64-encoded JSON extracted from a real Mac).
func hwKeyInputStep() *bridgev2.LoginStep {
	return &bridgev2.LoginStep{
		Type:   bridgev2.LoginStepTypeUserInput,
		StepID: LoginStepExternalKey,
		Instructions: "Enter your hardware key (base64-encoded JSON).\n\n" +
			"This is extracted once from a real Mac using the key extraction tool.\n" +
			"It contains hardware identifiers needed for iMessage registration.",
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{{
				Type: bridgev2.LoginInputFieldTypePassword,
				ID:   "hardware_key",
				Name: "Hardware Key (base64)",
			}},
		},
	}
}

// appleIDPasswordStep returns the Apple ID + password login step.
// extraInstructions is appended after the main prompt (e.g. NAC notes).
func appleIDPasswordStep(extraInstructions string) *bridgev2.LoginStep {
	instructions := "Enter your Apple ID credentials."
	if extraInstructions != "" {
		instructions += "\n\n" + extraInstructions
	}
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeUserInput,
		StepID:       LoginStepAppleIDPassword,
		Instructions: instructions,
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{{
				Type: bridgev2.LoginInputFieldTypeEmail,
				ID:   "username",
				Name: "Apple ID",
			}, {
				Type: bridgev2.LoginInputFieldTypePassword,
				ID:   "password",
				Name: "Password",
			}},
		},
	}
}

// twoFactorStepDetailed returns the 2FA step with per-device instructions
// (used in the macOS Apple ID flow where the user is more likely to have a device handy).
func twoFactorStepDetailed() *bridgev2.LoginStep {
	return &bridgev2.LoginStep{
		Type:   bridgev2.LoginStepTypeUserInput,
		StepID: LoginStepTwoFactor,
		Instructions: "Enter your Apple ID verification code.\n\n" +
			"You may see a notification on your trusted Apple devices. " +
			"If not, you can generate a code manually:\n" +
			"• iPhone/iPad: Settings → [Your Name] → Sign-In & Security → Two-Factor Authentication → Get Verification Code\n" +
			"• Mac: System Settings → [Your Name] → Sign-In & Security → Two-Factor Authentication → Get Verification Code",
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{{
				ID:   "code",
				Name: "2FA Code",
			}},
		},
	}
}

// twoFactorStepShort returns the 2FA step with brief instructions
// (used in the external key flow).
func twoFactorStepShort() *bridgev2.LoginStep {
	return &bridgev2.LoginStep{
		Type:   bridgev2.LoginStepTypeUserInput,
		StepID: LoginStepTwoFactor,
		Instructions: "Enter your Apple ID verification code.\n\n" +
			"You may see a notification on your trusted Apple devices.",
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{{
				ID:   "code",
				Name: "2FA Code",
			}},
		},
	}
}

// ============================================================================
// Apple ID Login (macOS only)
// ============================================================================

// AppleIDLogin implements the multi-step login flow:
//
//	[backfill choice →] Apple ID + password → [2FA →] IDS registration →
//	[device selection → passcode →] handle selection → connected.
//
// The backfill choice step is only shown when the server has cloudkit_backfill
// enabled. When disabled, cloudKitBackfill is always false and the flow is
// identical to the previous behaviour.
type AppleIDLogin struct {
	User             *bridgev2.User
	Main             *IMConnector
	backfillChosen   bool // true once the backfill preference step has been answered
	cloudKitBackfill bool // the user's backfill preference
	username         string
	cfg              *rustpushgo.WrappedOsConfig
	conn             *rustpushgo.WrappedApsConnection
	session          *rustpushgo.LoginSession
	result           *rustpushgo.IdsUsersWithIdentityRecord // set after IDS registration
	handle           string                                  // chosen handle
	devices          []rustpushgo.EscrowDeviceInfo           // escrow devices (fetched after IDS registration)
	selectedDevice   int                                     // index into devices (-1 = not yet selected)
}

var _ bridgev2.LoginProcessUserInput = (*AppleIDLogin)(nil)

func (l *AppleIDLogin) Cancel() {}

func (l *AppleIDLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	rustpushgo.InitLogger()

	cfg, err := rustpushgo.CreateLocalMacosConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize local NAC config: %w", err)
	}
	l.cfg = cfg

	log := l.Main.Bridge.Log.With().Str("component", "imessage").Logger()
	session := loadCachedSession(l.User, log)
	if !session.validate(log) {
		session = nil
	}
	apsState := getExistingAPSState(session, log)
	l.conn = rustpushgo.Connect(cfg, apsState)

	// When cloudkit_backfill is disabled server-wide, skip the choice step and
	// go straight to credentials — behaviour is identical to before this change.
	if !l.Main.Config.CloudKitBackfill {
		l.backfillChosen = true
		l.cloudKitBackfill = false
		return appleIDPasswordStep("Registration uses local NAC (no relay needed)."), nil
	}

	return backfillChoiceStep(), nil
}

func (l *AppleIDLogin) SubmitUserInput(ctx context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	// Device passcode step (after device selection, before handle selection)
	if passcode, ok := input["passcode"]; ok && l.result != nil {
		return l.handlePasscodeAndContinue(ctx, passcode)
	}

	// Device selection step (after IDS registration, before passcode)
	if device, ok := input["device"]; ok && l.result != nil {
		return l.handleDeviceSelection(device)
	}

	// Handle selection step (after device passcode or when backfill is skipped)
	if l.result != nil {
		l.handle = input["handle"]
		return l.completeLogin(ctx)
	}

	// Backfill choice step — only reached when cloudkit_backfill is enabled server-wide.
	if !l.backfillChosen {
		l.backfillChosen = true
		l.cloudKitBackfill = input["backfill"] == backfillOptionYes
		return appleIDPasswordStep("Registration uses local NAC (no relay needed)."), nil
	}

	// Apple ID + password step
	if l.session == nil {
		username := input["username"]
		if username == "" {
			return nil, fmt.Errorf("Apple ID is required")
		}
		password := input["password"]
		if password == "" {
			return nil, fmt.Errorf("Password is required")
		}
		l.username = username

		session, err := rustpushgo.LoginStart(username, password, l.cfg, l.conn)
		if err != nil {
			l.Main.Bridge.Log.Error().Err(err).Str("username", username).Msg("Login failed")
			return nil, fmt.Errorf("login failed: %w", err)
		}
		l.session = session

		if session.Needs2fa() {
			l.Main.Bridge.Log.Info().Str("username", username).Msg("Login succeeded, waiting for 2FA")
			return twoFactorStepDetailed(), nil
		}

		l.Main.Bridge.Log.Info().Str("username", username).Msg("Login succeeded without 2FA, finishing registration")
		return l.finishLogin(ctx)
	}

	// 2FA step
	code := input["code"]
	if code == "" {
		return nil, fmt.Errorf("2FA code is required")
	}

	success, err := l.session.Submit2fa(code)
	if err != nil {
		return nil, fmt.Errorf("2FA verification failed: %w", err)
	}
	if !success {
		return nil, fmt.Errorf("2FA verification failed — invalid code")
	}

	return l.finishLogin(ctx)
}

func (l *AppleIDLogin) finishLogin(ctx context.Context) (*bridgev2.LoginStep, error) {
	log := l.Main.Bridge.Log.With().Str("component", "imessage").Logger()

	session := loadCachedSession(l.User, log)
	if !session.validate(log) {
		session = nil
	}

	var existingIdentityArg **rustpushgo.WrappedIdsngmIdentity
	if existing := getExistingIdentity(session, log); existing != nil {
		existingIdentityArg = &existing
	} else {
		log.Info().Msg("No existing identity found, will generate new one (first login)")
	}

	var existingUsersArg **rustpushgo.WrappedIdsUsers
	if existing := getExistingUsers(session, log); existing != nil {
		existingUsersArg = &existing
	} else {
		log.Info().Msg("No existing users found, will register fresh (first login)")
	}

	result, err := l.session.Finish(l.cfg, l.conn, existingIdentityArg, existingUsersArg)
	if err != nil {
		l.Main.Bridge.Log.Error().Err(err).Msg("IDS registration failed during finishLogin")
		return nil, fmt.Errorf("login completion failed: %w", err)
	}
	l.result = &result
	l.selectedDevice = -1

	// Device selection and passcode are only needed to join the iCloud Keychain
	// trust circle for CloudKit record decryption. Skip them when the user has
	// not opted in to backfill.
	if !l.cloudKitBackfill {
		log.Info().Msg("CloudKit backfill not enabled for this user, skipping device selection and passcode")
		handles := l.result.Users.GetHandles()
		if step := handleSelectionStep(handles); step != nil {
			return step, nil
		}
		if len(handles) > 0 {
			l.handle = handles[0]
		}
		return l.completeLogin(ctx)
	}

	return fetchDevicesAndPrompt(log, l.result.TokenProvider, &l.devices, &l.selectedDevice)
}

func (l *AppleIDLogin) handleDeviceSelection(device string) (*bridgev2.LoginStep, error) {
	l.selectedDevice = parseDeviceSelection(device, l.devices)
	return devicePasscodeStepForDevice(l.devices, l.selectedDevice), nil
}

func (l *AppleIDLogin) handlePasscodeAndContinue(ctx context.Context, passcode string) (*bridgev2.LoginStep, error) {
	log := l.Main.Bridge.Log.With().Str("component", "imessage").Logger()
	if err := joinKeychainWithPasscode(log, l.result.TokenProvider, passcode, l.devices, l.selectedDevice); err != nil {
		return nil, err
	}

	handles := l.result.Users.GetHandles()
	if step := handleSelectionStep(handles); step != nil {
		return step, nil
	}
	if len(handles) > 0 {
		l.handle = handles[0]
	}
	return l.completeLogin(ctx)
}

func (l *AppleIDLogin) completeLogin(ctx context.Context) (*bridgev2.LoginStep, error) {
	meta := &UserLoginMetadata{
		Platform:         "rustpush-local",
		APSState:         l.conn.State().ToString(),
		IDSUsers:         l.result.Users.ToString(),
		IDSIdentity:      l.result.Identity.ToString(),
		DeviceID:         l.cfg.GetDeviceId(),
		PreferredHandle:  l.handle,
		CloudKitBackfill: l.cloudKitBackfill,
	}

	return completeLoginWithMeta(ctx, l.User, l.Main, l.username, l.cfg, l.conn, l.result, meta)
}

// ============================================================================
// External Key Login (cross-platform)
// ============================================================================

// ExternalKeyLogin implements the multi-step login flow for non-macOS platforms:
//
//	[backfill choice →] [hw key source →] [hardware key →]
//	Apple ID + password → [2FA →] IDS registration →
//	[device selection → passcode →] handle selection → connected.
//
// Steps in brackets are conditional:
//   - backfill choice: shown when cloudkit_backfill is enabled server-wide
//   - hw key source: shown when default_hardware_key is set in config
//   - hardware key input: shown when using a custom key (or no default exists)
//   - device selection + passcode: shown only when the user opted in to backfill
type ExternalKeyLogin struct {
	User             *bridgev2.User
	Main             *IMConnector
	backfillChosen   bool   // true once the backfill preference step has been answered
	cloudKitBackfill bool   // the user's backfill preference
	hwKeySource      string // "" | hwKeySourceDefault | hwKeySourceCustom
	hardwareKey      string
	username         string
	cfg              *rustpushgo.WrappedOsConfig
	conn             *rustpushgo.WrappedApsConnection
	session          *rustpushgo.LoginSession
	result           *rustpushgo.IdsUsersWithIdentityRecord // set after IDS registration
	handle           string                                  // chosen handle
	devices          []rustpushgo.EscrowDeviceInfo           // escrow devices (fetched after IDS registration)
	selectedDevice   int                                     // index into devices (-1 = not yet selected)
}

var _ bridgev2.LoginProcessUserInput = (*ExternalKeyLogin)(nil)

func (l *ExternalKeyLogin) Cancel() {}

func (l *ExternalKeyLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	// When cloudkit_backfill is disabled server-wide, skip the choice step —
	// behaviour is identical to before this change.
	if !l.Main.Config.CloudKitBackfill {
		l.backfillChosen = true
		l.cloudKitBackfill = false
		return l.nextHardwareKeyStep(), nil
	}

	return backfillChoiceStep(), nil
}

func (l *ExternalKeyLogin) SubmitUserInput(ctx context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	// Device passcode step (after device selection, before handle selection)
	if passcode, ok := input["passcode"]; ok && l.result != nil {
		return l.handlePasscodeAndContinue(ctx, passcode)
	}

	// Device selection step (after IDS registration, before passcode)
	if device, ok := input["device"]; ok && l.result != nil {
		return l.handleDeviceSelection(device)
	}

	// Handle selection step (after device passcode or when backfill is skipped)
	if l.result != nil {
		l.handle = input["handle"]
		return l.completeLogin(ctx)
	}

	// Backfill choice step — only reached when cloudkit_backfill is enabled server-wide.
	if !l.backfillChosen {
		l.backfillChosen = true
		l.cloudKitBackfill = input["backfill"] == backfillOptionYes
		return l.nextHardwareKeyStep(), nil
	}

	// Hardware key steps — cfg being nil means we haven't accepted a key yet.
	if l.cfg == nil {
		// If the server has a default key and the user hasn't chosen a source yet,
		// process the source selection answer.
		if l.Main.Config.DefaultHardwareKey != "" && l.hwKeySource == "" {
			l.hwKeySource = input["hw_key_source"]
			if l.hwKeySource == hwKeySourceDefault {
				l.hardwareKey = stripNonBase64(l.Main.Config.DefaultHardwareKey)
				return l.createConfigAndConnect()
			}
			// User chose to provide their own key — show the input step.
			return hwKeyInputStep(), nil
		}

		// No default key configured, or user already chose "provide my own" —
		// accept the hardware key input.
		hwKey := input["hardware_key"]
		if hwKey == "" {
			return nil, fmt.Errorf("hardware key is required")
		}
		l.hardwareKey = stripNonBase64(hwKey)
		return l.createConfigAndConnect()
	}

	// Apple ID + password step
	if l.session == nil {
		username := input["username"]
		if username == "" {
			return nil, fmt.Errorf("Apple ID is required")
		}
		password := input["password"]
		if password == "" {
			return nil, fmt.Errorf("Password is required")
		}
		l.username = username

		session, err := rustpushgo.LoginStart(username, password, l.cfg, l.conn)
		if err != nil {
			l.Main.Bridge.Log.Error().Err(err).Str("username", username).Msg("Login failed")
			return nil, fmt.Errorf("login failed: %w", err)
		}
		l.session = session

		if session.Needs2fa() {
			l.Main.Bridge.Log.Info().Str("username", username).Msg("Login succeeded, waiting for 2FA")
			return twoFactorStepShort(), nil
		}

		l.Main.Bridge.Log.Info().Str("username", username).Msg("Login succeeded without 2FA")
		return l.finishLogin(ctx)
	}

	// 2FA step
	code := input["code"]
	if code == "" {
		return nil, fmt.Errorf("2FA code is required")
	}

	success, err := l.session.Submit2fa(code)
	if err != nil {
		return nil, fmt.Errorf("2FA verification failed: %w", err)
	}
	if !success {
		return nil, fmt.Errorf("2FA verification failed — invalid code")
	}

	return l.finishLogin(ctx)
}

// nextHardwareKeyStep returns the appropriate first hardware-key step:
// the source-selection step when a default key is available, or the direct
// key-input step otherwise.
func (l *ExternalKeyLogin) nextHardwareKeyStep() *bridgev2.LoginStep {
	if l.Main.Config.DefaultHardwareKey != "" {
		return hwKeySourceStep()
	}
	return hwKeyInputStep()
}

// createConfigAndConnect initialises the NAC config from the accepted hardware
// key, creates the APS connection, and returns the Apple ID + password step.
// It is called from two paths: default key and custom key.
func (l *ExternalKeyLogin) createConfigAndConnect() (*bridgev2.LoginStep, error) {
	rustpushgo.InitLogger()

	cfg, err := rustpushgo.CreateConfigFromHardwareKey(l.hardwareKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hardware key: %w", err)
	}
	l.cfg = cfg

	extLog := l.Main.Bridge.Log.With().Str("component", "imessage").Logger()
	session := loadCachedSession(l.User, extLog)
	if !session.validate(extLog) {
		session = nil
	}
	apsState := getExistingAPSState(session, extLog)
	l.conn = rustpushgo.Connect(cfg, apsState)

	return appleIDPasswordStep("Registration uses the hardware key for NAC validation (no Mac needed at runtime)."), nil
}

func (l *ExternalKeyLogin) finishLogin(ctx context.Context) (*bridgev2.LoginStep, error) {
	log := l.Main.Bridge.Log.With().Str("component", "imessage").Logger()

	session := loadCachedSession(l.User, log)
	if !session.validate(log) {
		session = nil
	}

	var existingIdentityArg **rustpushgo.WrappedIdsngmIdentity
	if existing := getExistingIdentity(session, log); existing != nil {
		existingIdentityArg = &existing
	} else {
		log.Info().Msg("No existing identity found, will generate new one (first login)")
	}

	var existingUsersArg **rustpushgo.WrappedIdsUsers
	if existing := getExistingUsers(session, log); existing != nil {
		existingUsersArg = &existing
	} else {
		log.Info().Msg("No existing users found, will register fresh (first login)")
	}

	result, err := l.session.Finish(l.cfg, l.conn, existingIdentityArg, existingUsersArg)
	if err != nil {
		l.Main.Bridge.Log.Error().Err(err).Msg("IDS registration failed during finishLogin")
		return nil, fmt.Errorf("login completion failed: %w", err)
	}
	l.result = &result
	l.selectedDevice = -1

	// Device selection and passcode are only needed to join the iCloud Keychain
	// trust circle for CloudKit record decryption. Skip them when the user has
	// not opted in to backfill.
	if !l.cloudKitBackfill {
		log.Info().Msg("CloudKit backfill not enabled for this user, skipping device selection and passcode")
		handles := l.result.Users.GetHandles()
		if step := handleSelectionStep(handles); step != nil {
			return step, nil
		}
		if len(handles) > 0 {
			l.handle = handles[0]
		}
		return l.completeLogin(ctx)
	}

	return fetchDevicesAndPrompt(log, l.result.TokenProvider, &l.devices, &l.selectedDevice)
}

func (l *ExternalKeyLogin) handleDeviceSelection(device string) (*bridgev2.LoginStep, error) {
	l.selectedDevice = parseDeviceSelection(device, l.devices)
	return devicePasscodeStepForDevice(l.devices, l.selectedDevice), nil
}

func (l *ExternalKeyLogin) handlePasscodeAndContinue(ctx context.Context, passcode string) (*bridgev2.LoginStep, error) {
	log := l.Main.Bridge.Log.With().Str("component", "imessage").Logger()
	if err := joinKeychainWithPasscode(log, l.result.TokenProvider, passcode, l.devices, l.selectedDevice); err != nil {
		return nil, err
	}

	handles := l.result.Users.GetHandles()
	if step := handleSelectionStep(handles); step != nil {
		return step, nil
	}
	if len(handles) > 0 {
		l.handle = handles[0]
	}
	return l.completeLogin(ctx)
}

func (l *ExternalKeyLogin) completeLogin(ctx context.Context) (*bridgev2.LoginStep, error) {
	meta := &UserLoginMetadata{
		Platform:         "rustpush-external-key",
		APSState:         l.conn.State().ToString(),
		IDSUsers:         l.result.Users.ToString(),
		IDSIdentity:      l.result.Identity.ToString(),
		DeviceID:         l.cfg.GetDeviceId(),
		HardwareKey:      l.hardwareKey,
		PreferredHandle:  l.handle,
		CloudKitBackfill: l.cloudKitBackfill,
	}

	return completeLoginWithMeta(ctx, l.User, l.Main, l.username, l.cfg, l.conn, l.result, meta)
}

// ============================================================================
// Existing session state lookup
// ============================================================================

// cachedSessionState holds the raw strings for all three session components.
// They are validated as a group against the keystore before use, since they
// reference each other's keys and are only useful together.
type cachedSessionState struct {
	IDSIdentity     string
	APSState        string
	IDSUsers        string
	PreferredHandle string
	source          string // "database" or "backup file", for logging
}

// loadCachedSession looks up all three session components (identity, APS state,
// IDS users) from the bridge database or backup session file. Returns nil if
// nothing is found. The returned state has NOT been validated against the
// keystore yet — call validate() before using.
func loadCachedSession(user *bridgev2.User, log zerolog.Logger) *cachedSessionState {
	// Check DB first
	for _, login := range user.GetCachedUserLogins() {
		if meta, ok := login.Metadata.(*UserLoginMetadata); ok {
			if meta.IDSUsers != "" || meta.IDSIdentity != "" || meta.APSState != "" {
				log.Info().Msg("Found existing session state in database")
				return &cachedSessionState{
					IDSIdentity:     meta.IDSIdentity,
					APSState:        meta.APSState,
					IDSUsers:        meta.IDSUsers,
					PreferredHandle: meta.PreferredHandle,
					source:          "database",
				}
			}
		}
	}
	return nil
}

// validate checks that the cached IDS users state references keys that exist
// in the keystore. If the keystore was wiped, never migrated, or belongs to a
// different installation, this returns false and all cached state should be
// discarded (they are a coupled set).
func (c *cachedSessionState) validate(log zerolog.Logger) bool {
	if c == nil || c.IDSUsers == "" {
		return true // nothing to validate
	}
	users := rustpushgo.NewWrappedIdsUsers(&c.IDSUsers)
	if !users.ValidateKeystore() {
		log.Warn().
			Str("source", c.source).
			Msg("Cached session state references missing keystore keys — discarding (will register fresh)")
		return false
	}
	log.Info().Str("source", c.source).Msg("Cached session state validated against keystore")
	return true
}

// getExistingIdentity returns the cached IDSNGMIdentity for reuse during
// re-authentication (avoiding "new Mac" notifications).
// The session must have been validated before calling this.
func getExistingIdentity(session *cachedSessionState, log zerolog.Logger) *rustpushgo.WrappedIdsngmIdentity {
	if session != nil && session.IDSIdentity != "" {
		log.Info().Str("source", session.source).Msg("Reusing existing identity")
		identityStr := session.IDSIdentity
		return rustpushgo.NewWrappedIdsngmIdentity(&identityStr)
	}
	return nil
}

// getExistingAPSState returns the cached APS connection state for reuse during
// re-authentication (preserves push token, avoids new device registration).
// The session must have been validated before calling this.
func getExistingAPSState(session *cachedSessionState, log zerolog.Logger) *rustpushgo.WrappedApsState {
	if session != nil && session.APSState != "" {
		log.Info().Str("source", session.source).Msg("Reusing existing APS state")
		return rustpushgo.NewWrappedApsState(&session.APSState)
	}
	log.Info().Msg("No existing APS state found, will create new connection")
	return rustpushgo.NewWrappedApsState(nil)
}

// getExistingUsers returns the cached IDSUsers for reuse during
// re-authentication (avoids calling register() which triggers notifications).
// The session must have been validated before calling this.
func getExistingUsers(session *cachedSessionState, log zerolog.Logger) *rustpushgo.WrappedIdsUsers {
	if session != nil && session.IDSUsers != "" {
		log.Info().Str("source", session.source).Msg("Reusing existing IDS users")
		return rustpushgo.NewWrappedIdsUsers(&session.IDSUsers)
	}
	return nil
}

// ============================================================================
// Shared login helpers
// ============================================================================

// formatDeviceLabel returns a human-readable label for a device, e.g.
// "Ludvig's iPhone (iPhone15,2)".
func formatDeviceLabel(d rustpushgo.EscrowDeviceInfo) string {
	if d.DeviceName != "" && d.DeviceModel != "" {
		return fmt.Sprintf("%s (%s)", d.DeviceName, d.DeviceModel)
	}
	if d.DeviceName != "" {
		return d.DeviceName
	}
	if d.DeviceModel != "" {
		return fmt.Sprintf("Device (%s)", d.DeviceModel)
	}
	return fmt.Sprintf("Device (serial: %s)", d.Serial)
}

// fetchDevicesAndPrompt fetches escrow devices from the token provider and returns
// either a device selection step (multiple devices) or skips straight to the
// passcode step (single device, auto-selected). On failure, falls back to a
// generic passcode step.
func fetchDevicesAndPrompt(log zerolog.Logger, tp **rustpushgo.WrappedTokenProvider, devices *[]rustpushgo.EscrowDeviceInfo, selectedDevice *int) (*bridgev2.LoginStep, error) {
	if tp == nil || *tp == nil {
		log.Warn().Msg("No TokenProvider available, skipping device discovery")
		return devicePasscodeStepForDevice(nil, -1), nil
	}

	devs, err := (*tp).GetEscrowDevices()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch escrow devices, falling back to generic passcode prompt")
		return devicePasscodeStepForDevice(nil, -1), nil
	}
	*devices = devs

	if len(devs) == 1 {
		// Auto-select the only device and go straight to passcode
		*selectedDevice = 0
		log.Info().Str("device", formatDeviceLabel(devs[0])).Msg("Single escrow device found, auto-selected")
		return devicePasscodeStepForDevice(devs, 0), nil
	}

	// Multiple devices — let the user choose
	options := make([]string, len(devs))
	for i, d := range devs {
		options[i] = formatDeviceLabel(d)
	}

	return &bridgev2.LoginStep{
		Type:   bridgev2.LoginStepTypeUserInput,
		StepID: LoginStepSelectDevice,
		Instructions: "Multiple Apple devices were found on your account.\n" +
			"Choose which device's passcode you want to use to join the iCloud Keychain.\n\n" +
			"Pick the device whose lock-screen passcode you know.",
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{{
				Type:    bridgev2.LoginInputFieldTypeSelect,
				ID:      "device",
				Name:    "Device",
				Options: options,
			}},
		},
	}, nil
}

// parseDeviceSelection converts the user's device selection (the label string)
// back to an index into the devices list.
func parseDeviceSelection(selected string, devices []rustpushgo.EscrowDeviceInfo) int {
	for i, d := range devices {
		if formatDeviceLabel(d) == selected {
			return i
		}
	}
	// Shouldn't happen with a select field, but default to first device
	if len(devices) > 0 {
		return 0
	}
	return -1
}

// devicePasscodeStepForDevice returns a login step prompting for the passcode,
// with context about which device the passcode is for.
func devicePasscodeStepForDevice(devices []rustpushgo.EscrowDeviceInfo, selectedDevice int) *bridgev2.LoginStep {
	var instructions string
	if selectedDevice >= 0 && selectedDevice < len(devices) {
		d := devices[selectedDevice]
		instructions = fmt.Sprintf(
			"Enter the passcode for %s.\n\n"+
				"This is the PIN or password you use to unlock this device. "+
				"It's needed to join the iCloud Keychain trust circle, which gives the bridge "+
				"access to your Messages in iCloud for backfilling chat history.\n\n"+
				"Your passcode is only used once during setup and is not stored.",
			formatDeviceLabel(d),
		)
	} else {
		instructions = "Enter the passcode you use to unlock your iPhone or Mac.\n\n" +
			"This is needed to join the iCloud Keychain trust circle, which gives the bridge " +
			"access to your Messages in iCloud for backfilling chat history.\n\n" +
			"Your passcode is only used once during setup and is not stored."
	}

	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeUserInput,
		StepID:       LoginStepDevicePasscode,
		Instructions: instructions,
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{{
				Type: bridgev2.LoginInputFieldTypePassword,
				ID:   "passcode",
				Name: "Device Passcode",
			}},
		},
	}
}

// joinKeychainWithPasscode calls the Rust FFI to join the iCloud Keychain trust
// circle using the provided device passcode. This is required for PCS-encrypted
// CloudKit records (Messages in iCloud).
// If a specific device was selected, the corresponding bottle is tried first.
func joinKeychainWithPasscode(log zerolog.Logger, tp **rustpushgo.WrappedTokenProvider, passcode string, devices []rustpushgo.EscrowDeviceInfo, selectedDevice int) error {
	if tp == nil || *tp == nil {
		log.Warn().Msg("No TokenProvider available, skipping keychain join")
		return nil
	}
	log.Info().Msg("Joining iCloud Keychain trust circle...")

	var result string
	var err error
	if selectedDevice >= 0 && selectedDevice < len(devices) {
		deviceIndex := devices[selectedDevice].Index
		log.Info().Uint32("device_index", deviceIndex).Str("device", formatDeviceLabel(devices[selectedDevice])).Msg("Using preferred device bottle")
		result, err = (*tp).JoinKeychainCliqueForDevice(passcode, deviceIndex)
	} else {
		result, err = (*tp).JoinKeychainClique(passcode)
	}

	if err != nil {
		log.Error().Err(err).Msg("Failed to join keychain trust circle")
		return fmt.Errorf("failed to join iCloud Keychain: %w", err)
	}
	log.Info().Str("result", result).Msg("Successfully joined iCloud Keychain trust circle")
	return nil
}

// handleSelectionStep returns a login step prompting the user to pick a handle,
// or nil if there are no handles. Always prompts (even with 1 handle) so the
// preferred handle is explicitly chosen and persisted.
func handleSelectionStep(handles []string) *bridgev2.LoginStep {
	if len(handles) == 0 {
		return nil
	}
	return &bridgev2.LoginStep{
		Type:   bridgev2.LoginStepTypeUserInput,
		StepID: LoginStepSelectHandle,
		Instructions: "Choose which identity to use for outgoing iMessages.\n" +
			"This is what recipients will see your messages \"from\".",
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{{
				Type:    bridgev2.LoginInputFieldTypeSelect,
				ID:      "handle",
				Name:    "Send messages as",
				Options: handles,
			}},
		},
	}
}

// completeLoginWithMeta is the shared tail of both login flows: creates the
// IMClient, persists metadata, saves the identity backup file, and starts the
// bridge connection.
func completeLoginWithMeta(
	ctx context.Context,
	user *bridgev2.User,
	main *IMConnector,
	username string,
	cfg *rustpushgo.WrappedOsConfig,
	conn *rustpushgo.WrappedApsConnection,
	result *rustpushgo.IdsUsersWithIdentityRecord,
	meta *UserLoginMetadata,
) (*bridgev2.LoginStep, error) {
	log := main.Bridge.Log.With().Str("component", "imessage").Logger()

	// Store iCloud account persist data for TokenProvider restoration
	if result.AccountPersist != nil {
		meta.AccountUsername = result.AccountPersist.Username
		meta.AccountHashedPasswordHex = result.AccountPersist.HashedPasswordHex
		meta.AccountPET = result.AccountPersist.Pet
		meta.AccountADSID = result.AccountPersist.Adsid
		meta.AccountDSID = result.AccountPersist.Dsid
		meta.AccountSPDBase64 = result.AccountPersist.SpdBase64
		log.Info().Str("dsid", meta.AccountDSID).Msg("iCloud account credentials available for TokenProvider")
		if result.TokenProvider != nil && *result.TokenProvider != nil {
			tp := *result.TokenProvider
			if delegateJSON, mmeErr := tp.GetMmeDelegateJson(); mmeErr == nil && delegateJSON != nil {
				meta.MmeDelegateJSON = *delegateJSON
				log.Info().Msg("Captured MobileMe delegate for persistence")
			}
		}
	} else {
		log.Warn().Msg("No account persist data from login — cloud services will not be available")
	}

	loginID := networkid.UserLoginID(result.Users.LoginId(0))

	client := &IMClient{
		Main:                  main,
		config:                cfg,
		users:                 result.Users,
		identity:              result.Identity,
		connection:            conn,
		tokenProvider:         result.TokenProvider,
		contactsReady:         false,
		contactsReadyCh:       make(chan struct{}),
		cloudStore:            newCloudBackfillStore(main.Bridge.DB.Database, loginID),
		recentUnsends:         make(map[string]time.Time),
		recentOutboundUnsends: make(map[string]time.Time),
		smsPortals:            make(map[string]bool),
		imGroupNames:          make(map[string]string),
		imGroupGuids:          make(map[string]string),
		imGroupParticipants:   make(map[string][]string),
		gidAliases:            make(map[string]string),
		lastGroupForMember:    make(map[string]networkid.PortalKey),
	}

	ul, err := user.NewLogin(ctx, &database.UserLogin{
		ID:         loginID,
		RemoteName: username,
		RemoteProfile: status.RemoteProfile{
			Name: username,
		},
		Metadata: meta,
	}, &bridgev2.NewLoginParams{
		DeleteOnConflict: true,
		LoadUserLogin: func(ctx context.Context, login *bridgev2.UserLogin) error {
			client.UserLogin = login
			login.Client = client
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user login: %w", err)
	}

	go client.Connect(context.Background())

	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeComplete,
		StepID:       LoginStepComplete,
		Instructions: "Successfully logged in to iMessage. Bridge is starting.",
		CompleteParams: &bridgev2.LoginCompleteParams{
			UserLoginID: ul.ID,
			UserLogin:   ul,
		},
	}, nil
}
