package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type User struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	DisplayName string                `json:"displayName"`
	Credentials []webauthn.Credential `json:"credentials"`
}

// WebAuthn User interface implementation
func (u User) WebAuthnID() []byte {
	return u.ID
}

func (u User) WebAuthnName() string {
	return u.Name
}

func (u User) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u User) WebAuthnIcon() string {
	return ""
}

func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

type Server struct {
	webAuthn *webauthn.WebAuthn
	users    map[string]*User
	sessions map[string]*webauthn.SessionData
	mu       sync.RWMutex
}

func NewServer() *Server {
	wconfig := &webauthn.Config{
		RPDisplayName: "Passkey Demo",
		RPID:          "37c8a855a418.ngrok-free.app",
		RPOrigins:     []string{
			"http://localhost:3000", 
			"http://192.168.29.216:3000", 
			"http://192.168.29.136:3000", 
			"https://localhost:3000",
			"https://37c8a855a418.ngrok-free.app",
		},
		Timeouts: webauthn.TimeoutsConfig{
			// Login: webauthn.TimeoutConfig{},
			Login: webauthn.TimeoutConfig{
				Enforce: true,  // Enable server-side timeout
				Timeout: 5 * time.Second,  // Optional: override default
			},
		},
	}

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		panic(err)
	}

	return &Server{
		webAuthn: webAuthn,
		users:    make(map[string]*User),
		sessions: make(map[string]*webauthn.SessionData),
	}
}

func (s *Server) getOrCreateUser(username string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user, exists := s.users[username]; exists {
		return user
	}

	userID := make([]byte, 32)
	rand.Read(userID)

	user := &User{
		ID:          userID,
		Name:        username,
		DisplayName: username,
		Credentials: []webauthn.Credential{},
	}

	s.users[username] = user
	return user
}

func (s *Server) BeginRegistration(c echo.Context) error {
	username := c.QueryParam("username")
	if username == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Username required"})
	}

	user := s.getOrCreateUser(username)

	/*
	 1. Generates a cryptographically-random challenge that the browser/passkey must sign.
	 2. Builds a PublicKeyCredentialCreationOptions JSON structure that tells the browser:
	 	- the relying party information (RPID, name, origins)
	 	- who the user is (user.id, user.name, user.displayName)
	 	- which public-key algorithms are acceptable (e.g. ES256, RS256)
	 	- authenticator preferences (platform vs. cross-platform, resident key, user verification)
	 	- the challenge from step 1
	 3. Bundles a webauthn.SessionData object containing the challenge, user ID, 
	 	and other fields that will be needed later to validate the response.
	*/

	/*
	options  -> sent to client, kicks off navigator.credentials.create()
	session  -> saved on server(On cache with a TTL), used later in FinishRegistration() to verify
	err      -> non-nil if something went wrong building options (e.g. invalid config)
	*/
	// Configure registration to allow both platform (Touch ID/Face ID) and cross-platform authenticators
	options, session, err := s.webAuthn.BeginRegistration(
		user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.AuthenticatorAttachment(""), // Allows both platform (built-in Touch ID/Face ID) and cross-platform (external security keys) authenticators
			RequireResidentKey:      protocol.ResidentKeyRequired(),
			// ResidentKey: "required" - Discoverable Credentials (resident keys) are 
			// required for userless authentication. A resident key contains 
			// enough information for the authenticator to identify the user 
			// without the relying party providing a username.
			ResidentKey:            protocol.ResidentKeyRequirementRequired,

			// User verification ensures the person using the authenticator is the legitimate owner, typically through:
			// Biometrics: fingerprint, face scan, iris scan
			// Knowledge factor: PIN, password, pattern
			// Physical presence: just touching a security key (no verification)
			UserVerification:       protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Store session
	sessionID := base64.URLEncoding.EncodeToString(make([]byte, 32))
	rand.Read([]byte(sessionID))

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	// Debug: print the options structure
	fmt.Printf("BeginRegistration options: %+v\n, session: %s\n", options, session.Expires.String())

	response := map[string]interface{}{
		"options":   options,
		"sessionId": sessionID,
	}

	return c.JSON(http.StatusOK, response)
}

func (s *Server) FinishRegistration(c echo.Context) error {
	sessionID := c.QueryParam("sessionId")
	username := c.QueryParam("username")

	if sessionID == "" || username == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "SessionId and username required"})
	}

	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	user := s.users[username]
	s.mu.RUnlock()

	if !exists || user == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session or user"})
	}

	credential, err := s.webAuthn.FinishRegistration(user, *session, c.Request())
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	s.mu.Lock()
	user.Credentials = append(user.Credentials, *credential)
	// delete(s.sessions, sessionID)
	fmt.Printf("✅ Successfully registered user '%s' with %d credentials\n", username, len(user.Credentials))
	s.mu.Unlock()

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

func (s *Server) BeginLogin(c echo.Context) error {
	username := c.QueryParam("username")
	if username == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Username required"})
	}

	s.mu.RLock()
	user, exists := s.users[username]
	fmt.Printf("BeginLogin: Looking for user '%s', exists: %v\n", username, exists)
	if exists {
		fmt.Printf("User found with %d credentials\n", len(user.Credentials))
	}
	s.mu.RUnlock()

	if !exists {
		fmt.Printf("❌ User '%s' not found. Available users: %v\n", username, func() []string {
			s.mu.RLock()
			defer s.mu.RUnlock()
			var usernames []string
			for name := range s.users {
				usernames = append(usernames, name)
			}
			return usernames
		}())
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "User not found"})
	}

	options, session, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Store session
	sessionID := base64.URLEncoding.EncodeToString(make([]byte, 32))
	rand.Read([]byte(sessionID))

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	response := map[string]interface{}{
		"options":   options,
		"sessionId": sessionID,
	}

	return c.JSON(http.StatusOK, response)
}

func (s *Server) BeginDiscoverableLogin(c echo.Context) error {
	fmt.Printf("BeginDiscoverableLogin: Starting userless authentication\n")
	
	// For discoverable credentials, we don't specify a user
	// The webauthn library will create options without allowCredentials
	options, session, err := s.webAuthn.BeginDiscoverableLogin(
		// Configure signature validity to be atleast 30 minutes

	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Store session
	sessionID := base64.URLEncoding.EncodeToString(make([]byte, 32))
	rand.Read([]byte(sessionID))

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()
	fmt.Printf("BeginDiscoverableLogin options: %+v\n, session: %s\n", options, session.Expires.String())

	response := map[string]interface{}{
		"options":   options,
		"sessionId": sessionID,
	}

	return c.JSON(http.StatusOK, response)
}

func (s *Server) FinishLogin(c echo.Context) error {
	sessionID := c.QueryParam("sessionId")
	username := c.QueryParam("username")

	if sessionID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "SessionId required"})
	}

	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()
	if !session.Expires.IsZero() && session.Expires.Before(time.Now()) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Session has Expired"})
	}
	if !exists {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid session"})
	}

	if username != "" {
		// Username-based login (traditional flow)
		s.mu.RLock()
		user := s.users[username]
		s.mu.RUnlock()

		if user == nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "User not found"})
		}

		_, err := s.webAuthn.FinishLogin(user, *session, c.Request())
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}

		s.mu.Lock()
		// delete(s.sessions, sessionID)
		s.mu.Unlock()

		return c.JSON(http.StatusOK, map[string]string{"status": "success", "username": username})
	} else {
		// Discoverable login (userless flow)
		var foundUser *User
		
		credential, err := s.webAuthn.FinishDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			// Find user by credential ID or user handle
			s.mu.RLock()
			defer s.mu.RUnlock()
			
			for _, u := range s.users {
				// Check if this user has a credential with the given rawID
				for _, cred := range u.Credentials {
					if string(cred.ID) == string(rawID) {
						fmt.Printf("✅ Found user '%s' by credential ID\n", u.Name)
						foundUser = u
						return u, nil
					}
				}
				// Also check by user handle if provided
				if userHandle != nil && string(u.ID) == string(userHandle) {
					fmt.Printf("✅ Found user '%s' by user handle\n", u.Name)
					foundUser = u
					return u, nil
				}
			}
			
			return nil, fmt.Errorf("user not found for credential")
		}, *session, c.Request())

		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}

		s.mu.Lock()
		// delete(s.sessions, sessionID)
		s.mu.Unlock()

		// Update the credential in the user's record
		if foundUser != nil && credential != nil {
			for i, cred := range foundUser.Credentials {
				if string(cred.ID) == string(credential.ID) {
					foundUser.Credentials[i] = *credential
					break
				}
			}
			return c.JSON(http.StatusOK, map[string]string{"status": "success", "username": foundUser.Name})
		}

		return c.JSON(http.StatusOK, map[string]string{"status": "success"})
	}
}

func main() {
	server := NewServer()

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOriginFunc: func(origin string) (bool, error) {
			// Allow all origins for development
			return true, nil
		},
		AllowMethods:     []string{echo.GET, echo.POST, echo.PUT, echo.DELETE, echo.OPTIONS},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
		AllowCredentials: true,
	}))

	// Routes
	e.GET("/register/begin", server.BeginRegistration)
	e.POST("/register/finish", server.FinishRegistration)

	e.GET("/login/begin", server.BeginLogin)
	e.POST("/login/finish", server.FinishLogin)
	
	e.GET("/login/discoverable/begin", server.BeginDiscoverableLogin)
	e.POST("/login/discoverable/finish", server.FinishLogin)

	// Start server
	fmt.Println("Server starting on :8080")
	e.Logger.Fatal(e.Start(":8080"))
}
