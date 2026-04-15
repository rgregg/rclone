# Device Flow (RFC 8628) Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add device code flow as an interactive auth method choice during `rclone config`, available for any backend that provides a device auth URL.

**Architecture:** Extend `lib/oauthutil.Config` with a `DeviceAuthURL` field. Replace the binary yes/no browser prompt in `ConfigOAuth()` with a multi-choice menu when device flow is available. Add a new `*oauth-device` state that uses `golang.org/x/oauth2`'s built-in `DeviceAuth()` / `DeviceAccessToken()` to complete the flow. OneDrive opts in by setting the URL.

**Tech Stack:** Go, `golang.org/x/oauth2` v0.36.0 (already a dependency — has `DeviceAuth` / `DeviceAccessToken` built in)

---

### Task 1: Add DeviceAuthURL to oauthutil.Config and wire into oauth2.Config

**Files:**
- Modify: `lib/oauthutil/oauthutil.go:94-118`

- [ ] **Step 1: Add DeviceAuthURL field to Config struct**

In `lib/oauthutil/oauthutil.go`, add `DeviceAuthURL` to the `Config` struct:

```go
type Config struct {
	ClientID             string
	ClientSecret         string
	TokenURL             string
	AuthURL              string
	DeviceAuthURL        string
	Scopes               []string
	EndpointParams       url.Values
	RedirectURL          string
	ClientCredentialFlow bool
	AuthStyle            oauth2.AuthStyle
}
```

- [ ] **Step 2: Wire DeviceAuthURL into MakeOauth2Config**

Update `MakeOauth2Config()` to pass the field through to the `oauth2.Endpoint`:

```go
func (conf *Config) MakeOauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		RedirectURL:  conf.RedirectURL,
		Scopes:       conf.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:       conf.AuthURL,
			TokenURL:      conf.TokenURL,
			DeviceAuthURL: conf.DeviceAuthURL,
			AuthStyle:     conf.AuthStyle,
		},
	}
}
```

- [ ] **Step 3: Verify it compiles**

Run: `go build ./lib/oauthutil/...`
Expected: success, no errors

- [ ] **Step 4: Commit**

```bash
git add lib/oauthutil/oauthutil.go
git commit -m "oauthutil: add DeviceAuthURL field to Config struct"
```

---

### Task 2: Replace binary browser prompt with multi-choice auth method menu

**Files:**
- Modify: `lib/oauthutil/oauthutil.go:630-648` (the `*oauth-confirm` and `*oauth-islocal` states)

- [ ] **Step 1: Update `*oauth-confirm` to go to a new `*oauth-method` state**

Replace the existing `*oauth-islocal` prompt in the `*oauth-confirm` case. When client credentials flow is not active, go to `*oauth-method` instead of `*oauth-islocal`:

```go
	case "*oauth-confirm":
		if in.Result == "false" {
			return fs.ConfigGoto(newState("*oauth-done"))
		}
		opt, err := getOAuth()
		if err != nil {
			return nil, err
		}
		oauthConfig, _ := OverrideCredentials(name, m, opt.OAuth2Config)
		if oauthConfig.ClientCredentialFlow {
			return fs.ConfigGoto(newState("*oauth-do"))
		}
		return fs.ConfigGoto(newState("*oauth-method"))
```

- [ ] **Step 2: Add `*oauth-method` state with multi-choice menu**

Add a new case after `*oauth-confirm`. When the backend supports device flow (has `DeviceAuthURL`), show a 3-option menu. Otherwise, fall back to the original yes/no prompt for backward compatibility:

```go
	case "*oauth-method":
		opt, err := getOAuth()
		if err != nil {
			return nil, err
		}
		oauthConfig, _ := OverrideCredentials(name, m, opt.OAuth2Config)
		if oauthConfig.DeviceAuthURL != "" {
			// Backend supports device flow - show full menu
			items := []fs.OptionExample{
				{Value: "browser", Help: "Use a web browser to automatically authenticate (recommended if available)"},
				{Value: "device", Help: "Enter a code on a different device to authenticate"},
				{Value: "remote", Help: "Use rclone authorize on a different machine"},
			}
			return fs.ConfigChooseExclusiveFixed(newState("*oauth-method-choice"), "config_auth_method", "Choose how to authenticate:", items)
		}
		// No device flow - use original yes/no browser prompt
		return fs.ConfigConfirm(newState("*oauth-islocal"), true, "config_is_local", "Use web browser to automatically authenticate rclone with remote?\n * Say Y if the machine running rclone has a web browser you can use\n * Say N if running rclone on a (remote) machine without web browser access\nIf not sure try Y. If Y failed, try N.\n")
```

- [ ] **Step 3: Add `*oauth-method-choice` state to route to the right flow**

```go
	case "*oauth-method-choice":
		switch in.Result {
		case "browser":
			return fs.ConfigGoto(newState("*oauth-do"))
		case "device":
			return fs.ConfigGoto(newState("*oauth-device"))
		case "remote":
			return fs.ConfigGoto(newState("*oauth-remote"))
		default:
			return fs.ConfigGoto(newState("*oauth-method"))
		}
```

- [ ] **Step 4: Keep `*oauth-islocal` as-is for backward compatibility**

The existing `*oauth-islocal` case remains unchanged — it handles backends without device flow support:

```go
	case "*oauth-islocal":
		if in.Result == "true" {
			return fs.ConfigGoto(newState("*oauth-do"))
		}
		return fs.ConfigGoto(newState("*oauth-remote"))
```

- [ ] **Step 5: Verify it compiles**

Run: `go build ./lib/oauthutil/...`
Expected: success

- [ ] **Step 6: Commit**

```bash
git add lib/oauthutil/oauthutil.go
git commit -m "oauthutil: add auth method choice menu with device flow option"
```

---

### Task 3: Implement the `*oauth-device` state

**Files:**
- Modify: `lib/oauthutil/oauthutil.go` (add new case in `ConfigOAuth` switch and a helper function)

- [ ] **Step 1: Add `deviceFlowGetToken` helper function**

Add this function after the existing `clientCredentialsFlowGetToken` function (or near the bottom of the file, before `init()`). It uses the `oauth2` library's built-in device flow:

```go
// deviceFlowGetToken performs the OAuth2 device authorization flow (RFC 8628).
// It requests a device code, displays the user code and verification URL,
// then polls for the token until the user completes authentication.
func deviceFlowGetToken(ctx context.Context, name string, m configmap.Mapper, oauthConfig *Config, opt *Options) error {
	oauth2Conf := oauthConfig.MakeOauth2Config()

	// Request device code
	devAuth, err := oauth2Conf.DeviceAuth(ctx, opt.OAuth2Opts...)
	if err != nil {
		return fmt.Errorf("device authorization request failed: %w", err)
	}

	// Display instructions to the user
	fs.Logf(nil, "To authorize rclone, visit:\n\n\t%s\n\nAnd enter the code:\n\n\t%s\n", devAuth.VerificationURI, devAuth.UserCode)
	if devAuth.VerificationURIComplete != "" {
		fs.Logf(nil, "Or visit the following URL to authorize automatically:\n\n\t%s\n", devAuth.VerificationURIComplete)
	}
	fs.Logf(nil, "Waiting for authorization...")

	// Poll for token (the library handles polling interval and slow_down)
	token, err := oauth2Conf.DeviceAccessToken(ctx, devAuth, opt.OAuth2Opts...)
	if err != nil {
		return fmt.Errorf("device flow token exchange failed: %w", err)
	}

	return PutToken(name, m, token, false)
}
```

- [ ] **Step 2: Add `*oauth-device` case to the ConfigOAuth switch**

Add this case before the `*oauth-do` case:

```go
	case "*oauth-device":
		opt, err := getOAuth()
		if err != nil {
			return nil, err
		}
		oauthConfig, _ := OverrideCredentials(name, m, opt.OAuth2Config)
		err = deviceFlowGetToken(ctx, name, m, oauthConfig, opt)
		if err != nil {
			return nil, err
		}
		return fs.ConfigGoto(newState("*oauth-done"))
```

- [ ] **Step 3: Verify it compiles**

Run: `go build ./lib/oauthutil/...`
Expected: success

- [ ] **Step 4: Commit**

```bash
git add lib/oauthutil/oauthutil.go
git commit -m "oauthutil: implement device code flow (RFC 8628) authentication"
```

---

### Task 4: Opt OneDrive into device flow

**Files:**
- Modify: `backend/onedrive/onedrive.go:67-88` (constants and oauthConfig)
- Modify: `backend/onedrive/onedrive.go:561-589` (makeOauthConfig function)

- [ ] **Step 1: Add device code path constant**

Add `devicecodePath` alongside the existing `authPath` and `tokenPath` constants in `backend/onedrive/onedrive.go`:

```go
	// Define the paths used for token operations
	commonPathPrefix = "/common" // prefix for the paths if tenant isn't known
	authPath         = "/oauth2/v2.0/authorize"
	tokenPath        = "/oauth2/v2.0/token"
	devicecodePath   = "/oauth2/v2.0/devicecode"
```

- [ ] **Step 2: Set DeviceAuthURL in makeOauthConfig**

In `makeOauthConfig()`, set the `DeviceAuthURL` right after setting `AuthURL`:

```go
func makeOauthConfig(ctx context.Context, opt *Options) (*oauthutil.Config, error) {
	// Copy the default oauthConfig
	oauthConfig := *oauthConfig

	// Set the scopes
	oauthConfig.Scopes = opt.AccessScopes
	if opt.DisableSitePermission {
		oauthConfig.Scopes = scopeAccessWithoutSites
	}

	// Construct the auth URLs
	prefix := commonPathPrefix
	if opt.Tenant != "" {
		prefix = "/" + opt.Tenant
	}
	oauthConfig.TokenURL = authEndpoint[opt.Region] + prefix + tokenPath
	oauthConfig.AuthURL = authEndpoint[opt.Region] + prefix + authPath
	oauthConfig.DeviceAuthURL = authEndpoint[opt.Region] + prefix + devicecodePath

	// Check to see if we are using client credentials flow
	if opt.ClientCredentials {
		// Override scope to .default
		oauthConfig.Scopes = scopeAccessClientCred
		if opt.Tenant == "" {
			return nil, fmt.Errorf("tenant parameter must be set when using %s", config.ConfigClientCredentials)
		}
	}

	return &oauthConfig, nil
}
```

- [ ] **Step 3: Verify the full project compiles**

Run: `go build ./...`
Expected: success (may take a while for full project build — `go build ./backend/onedrive/...` is sufficient)

- [ ] **Step 4: Commit**

```bash
git add backend/onedrive/onedrive.go
git commit -m "onedrive: enable device code flow authentication"
```

---

### Task 5: Manual testing

- [ ] **Step 1: Test device flow with OneDrive**

Run: `rclone config`

Create a new OneDrive remote. At the auth method prompt, verify you see:

```
Choose how to authenticate:
 1) Use a web browser to automatically authenticate (recommended if available)
 2) Enter a code on a different device to authenticate
 3) Use rclone authorize on a different machine
```

Select option 2. Verify:
- A user code and verification URL are displayed
- After visiting the URL and entering the code, the token is obtained and saved

- [ ] **Step 2: Test browser flow still works**

Create another OneDrive remote, select option 1 (browser). Verify the existing browser-based flow still works.

- [ ] **Step 3: Test a non-Microsoft backend**

Run `rclone config` for a backend that does NOT set `DeviceAuthURL` (e.g., Google Drive). Verify you see the original yes/no browser prompt, not the 3-option menu.

- [ ] **Step 4: Final commit if any fixes needed**

```bash
git add -u
git commit -m "oauthutil: fix issues found during manual testing"
```
