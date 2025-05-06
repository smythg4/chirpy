package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/smythg4/chirpy/internal/auth"
	"github.com/smythg4/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbqueries      *database.Queries
	platform       string
	secret         string
	polkaKey       string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		// Count the request
		cfg.fileserverHits.Add(1)
		// Pass the request to the next handler
		next.ServeHTTP(writer, req)
	})
}

func NewApiConfig() *apiConfig {
	var cfg apiConfig
	cfg.fileserverHits.Store(0)
	return &cfg
}

func unprofanitize(text string) string {
	bannedWords := map[string]bool{
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}
	words := strings.Fields(text)
	for _, word := range words {
		if bannedWords[strings.ToLower(word)] {
			text = strings.Replace(text, word, "****", -1)
		}
	}
	return text
}

func respondWithJSON(writer http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusInternalServerError)
		writer.Write([]byte(`{"error": "error marshaling JSON"}`))
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(code)
	writer.Write(response)
}

func respondWithError(writer http.ResponseWriter, code int, msg string) {
	respondWithJSON(writer, code, map[string]string{"error": msg})
}

func handlerReadiness(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(200)
	writer.Write([]byte("OK"))
}

func validateChirp(body string) (string, error) {
	if len(body) > 140 {
		return "", fmt.Errorf("chirp is too long")
	}
	msg := unprofanitize(body)
	return msg, nil
}

func (cfg *apiConfig) handlerNewChirp(writer http.ResponseWriter, req *http.Request) {
	type request_params struct {
		Body string `json:"body"`
	}

	type JSONChirp struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}

	tokenString, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(writer, http.StatusUnauthorized, "invalid token")
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.secret)
	if err != nil {
		respondWithError(writer, http.StatusUnauthorized, "invalid token")
		return
	}

	decoder := json.NewDecoder(req.Body)
	params := request_params{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "can't decode json")
		return
	}

	// validate and sanitize the chirp body
	clean_body, err := validateChirp(params.Body)
	if err != nil {
		respondWithError(writer, http.StatusBadRequest, "chirp is too long")
		return
	}

	chirp_params := database.CreateChirpParams{
		Body:   clean_body,
		UserID: userID,
	}
	chirp, err := cfg.dbqueries.CreateChirp(req.Context(), chirp_params)
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "unable to write chirp to DB")
		return
	}
	response := JSONChirp{
		Id:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}

	respondWithJSON(writer, http.StatusCreated, response)
}

func (cfg *apiConfig) handlerDeleteChirp(writer http.ResponseWriter, req *http.Request) {
	tokenString, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(writer, http.StatusUnauthorized, "invalid token")
		return
	}

	user_id, err := auth.ValidateJWT(tokenString, cfg.secret)
	if err != nil {
		respondWithError(writer, http.StatusForbidden, "invalid token")
		return
	}
	chirp_id, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "can't convert path value to uuid")
		return
	}
	chirp, err := cfg.dbqueries.GetChirpByID(req.Context(), chirp_id)
	if err != nil {
		respondWithError(writer, http.StatusNotFound, "chirp not found")
		return
	}
	if user_id != chirp.UserID {
		respondWithError(writer, http.StatusForbidden, "can't delete another user's chirp!")
		return
	}

	err = cfg.dbqueries.DeleteChirp(req.Context(), chirp_id)
	if err != nil {
		respondWithError(writer, http.StatusNotFound, "chirp not found")
		return
	}

	respondWithJSON(writer, http.StatusNoContent, nil)
}

func (cfg *apiConfig) handlerGetChirpByID(writer http.ResponseWriter, req *http.Request) {
	type JSONChirp struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}
	chirp_id, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "can't convert path value to uuid")
		return
	}
	chirp, err := cfg.dbqueries.GetChirpByID(req.Context(), chirp_id)
	if err != nil {
		respondWithError(writer, http.StatusNotFound, "can't retrieve chirp from db")
		return
	}
	jsonchirp := JSONChirp{
		Id:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}

	respondWithJSON(writer, http.StatusOK, jsonchirp)
}

func (cfg *apiConfig) handlerGetChirps(writer http.ResponseWriter, req *http.Request) {

	type JSONChirp struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}

	var chirpdata []database.Chirp
	userstr := req.URL.Query().Get("author_id")
	sortorder := req.URL.Query().Get("sort")
	userid, err := uuid.Parse(userstr)
	if err != nil {
		chirpdata, err = cfg.dbqueries.GetAllChirps(req.Context())
		if err != nil {
			respondWithError(writer, http.StatusNotFound, "can't fetch chirps from db")
			return
		}
	} else {
		chirpdata, err = cfg.dbqueries.GetChirpByUserID(req.Context(), userid)
		if err != nil {
			respondWithError(writer, http.StatusNotFound, "can't fetch chirps from db")
			return
		}
	}

	jsonChirps := make([]JSONChirp, len(chirpdata))
	for i, chirp := range chirpdata {
		jsonChirps[i] = JSONChirp{
			Id:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}
	}
	if sortorder == "desc" {
		sort.Slice(jsonChirps, func(i, j int) bool { return jsonChirps[i].CreatedAt.After(jsonChirps[j].CreatedAt) })
	} else {
		sort.Slice(jsonChirps, func(i, j int) bool { return jsonChirps[j].CreatedAt.After(jsonChirps[i].CreatedAt) })
	}
	respondWithJSON(writer, http.StatusOK, jsonChirps)
}

func (cfg *apiConfig) handlerRevoke(writer http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(writer, http.StatusUnauthorized, "no refresh token provided")
		return
	}
	// see if refresh token exists
	ref_token, err := cfg.dbqueries.GetRefreshToken(req.Context(), token)
	if err != nil {
		respondWithError(writer, http.StatusUnauthorized, "no refresh token found")
		return
	}
	// revoke the token
	params := database.RevokeTokenParams{
		UpdatedAt: time.Now().UTC(),
		Token:     ref_token.Token,
	}
	_, err = cfg.dbqueries.RevokeToken(req.Context(), params)
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "error updating database")
		return
	}
	respondWithJSON(writer, http.StatusNoContent, nil)
}

func (cfg *apiConfig) handlerCheckRefreshToken(writer http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(writer, http.StatusUnauthorized, "no refresh token provided")
		return
	}
	// see if refresh token exists
	ref_token, err := cfg.dbqueries.GetRefreshToken(req.Context(), token)
	if err != nil {
		respondWithError(writer, http.StatusUnauthorized, "no refresh token found")
		return
	}
	// see if the token has been revoked
	if ref_token.RevokedAt.Valid {
		respondWithError(writer, http.StatusUnauthorized, "refresh token revoked")
		return
	}
	// see if the token is expired
	if ref_token.ExpiresAt.Sub(time.Now().UTC()) < 0 {
		respondWithError(writer, http.StatusUnauthorized, "refresh token expired")
		return
	}
	// so now we know we have a good refresh token. Time to make a new access token
	access_token, err := auth.MakeJWT(ref_token.UserID, cfg.secret, time.Hour)
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "error generating new access token")
		return
	}
	response_package := struct {
		Token string `json:"token"`
	}{Token: access_token}
	respondWithJSON(writer, http.StatusOK, response_package)
}

func (cfg *apiConfig) handlerLogin(writer http.ResponseWriter, req *http.Request) {
	type request_params struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type JSONUser struct {
		Id           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
		IsChirpyRed  bool      `json:"is_chirpy_red"`
	}

	decoder := json.NewDecoder(req.Body)
	req_params := request_params{}
	err := decoder.Decode(&req_params)

	if err != nil {
		//couldn't decode json
		respondWithError(writer, http.StatusInternalServerError, "error decoding json request")
		return
	}

	user, err := cfg.dbqueries.GetUserByEmail(req.Context(), req_params.Email)
	if err != nil {
		//couldn't query db
		respondWithError(writer, http.StatusUnauthorized, "incorrect email or password")
		return
	}

	err = auth.CheckPasswordHash(user.HashedPassword, req_params.Password)
	if err != nil {
		//passwords don't match
		respondWithError(writer, http.StatusUnauthorized, "incorrect email or password")
		return
	}

	access_token, err := auth.MakeJWT(user.ID, cfg.secret, time.Hour)
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "error generating user token")
		return
	}

	refresh_token, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "error generating refresh token")
		return
	}

	refresh_params := database.CreateRefreshTokenParams{
		Token:     refresh_token,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(60 * 24 * time.Hour),
	}

	_, err = cfg.dbqueries.CreateRefreshToken(req.Context(), refresh_params)
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "error entering refresh token into db")
		return
	}

	return_val := JSONUser{
		Id:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        access_token,
		RefreshToken: refresh_token,
		IsChirpyRed:  user.IsChirpyRed,
	}

	respondWithJSON(writer, http.StatusOK, return_val)
}

func (cfg *apiConfig) handlerUpgradeUser(writer http.ResponseWriter, req *http.Request) {

	apikey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		respondWithError(writer, http.StatusUnauthorized, "no api key provided")
		return
	}
	if apikey != cfg.polkaKey {
		respondWithError(writer, http.StatusUnauthorized, "api key invalid")
		return
	}

	type user_params struct {
		UserID uuid.UUID `json:"user_id"`
	}
	type hooks_params struct {
		Event string      `json:"event"`
		Data  user_params `json:"data"`
	}
	decoder := json.NewDecoder(req.Body)
	params := hooks_params{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "can't decode json")
		return
	}
	if params.Event != "user.upgraded" {
		// don't care!
		respondWithJSON(writer, http.StatusNoContent, nil)
		return
	}
	_, err = cfg.dbqueries.UpgradeUserToRed(req.Context(), params.Data.UserID)
	if err != nil {
		respondWithError(writer, http.StatusNotFound, "user not found")
		return
	}
	respondWithJSON(writer, http.StatusNoContent, nil)
}

func (cfg *apiConfig) handlerUpdateUser(writer http.ResponseWriter, req *http.Request) {
	type request_params struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type JSONUser struct {
		Id          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}

	tokenString, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(writer, http.StatusUnauthorized, "invalid token")
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.secret)
	if err != nil {
		respondWithError(writer, http.StatusUnauthorized, "invalid token")
		return
	}

	decoder := json.NewDecoder(req.Body)
	params := request_params{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "can't decode json")
		return
	}

	hPass, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "couldn't hash password")
		return
	}

	user_params := database.UpdateUserParams{
		HashedPassword: hPass,
		Email:          params.Email,
		ID:             userID,
	}

	user, err := cfg.dbqueries.UpdateUser(req.Context(), user_params)
	if err != nil {
		respondWithError(writer, http.StatusInternalServerError, "couldn't retrieve user data")
		return
	}

	data := JSONUser{
		Id:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}

	respondWithJSON(writer, http.StatusOK, data)

}

func (cfg *apiConfig) handlerAddUser(writer http.ResponseWriter, req *http.Request) {
	type request_params struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type JSONUser struct {
		Id          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}

	decoder := json.NewDecoder(req.Body)
	req_params := request_params{}
	err := decoder.Decode(&req_params)
	if err != nil {
		//couldn't decode json
		respondWithError(writer, http.StatusInternalServerError, "error decoding json request")
		return
	}
	if len(req_params.Password) < 1 || len(req_params.Email) < 1 {
		respondWithError(writer, http.StatusBadRequest, "email AND password required")
		return
	}
	hashPass, err := auth.HashPassword(req_params.Password)
	if err != nil {
		//couldn't hash password
		respondWithError(writer, http.StatusInternalServerError, "unable to hash password")
		return
	}

	params := database.CreateUserParams{
		Email:          req_params.Email,
		HashedPassword: hashPass,
	}
	user, err := cfg.dbqueries.CreateUser(req.Context(), params)
	if err != nil {
		// couldn't create the user
		respondWithError(writer, http.StatusInternalServerError, "unable to create user")
		return
	}

	return_val := JSONUser{
		Id:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}

	respondWithJSON(writer, http.StatusCreated, return_val)
}

func (cfg *apiConfig) handlerHitCount(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(200)
	text := fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", cfg.fileserverHits.Load())
	writer.Write([]byte(text))
}

func (cfg *apiConfig) handlerReset(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if cfg.platform != "dev" {
		writer.WriteHeader(403)
		writer.Write([]byte("You must be in local dev environment to do this."))
		return
	} else {
		writer.WriteHeader(200)
		cfg.fileserverHits.Store(0)
		cfg.dbqueries.ResetUsers(req.Context())

		text := fmt.Sprintf("Hits: %d", cfg.fileserverHits.Load())
		writer.Write([]byte(text))
	}
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	secret := os.Getenv("SECRET")
	polkaKey := os.Getenv("POLKA_KEY")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("Error loading database: %v", err)
		os.Exit(1)
	}
	dbQueries := database.New(db)

	apiCfg := NewApiConfig()
	apiCfg.dbqueries = dbQueries
	apiCfg.platform = platform
	apiCfg.secret = secret
	apiCfg.polkaKey = polkaKey

	mux := http.NewServeMux()
	// must strip the app prefix from the handler path
	fileserver_handler := http.StripPrefix("/app", http.FileServer(http.Dir("./app")))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fileserver_handler))

	mux.HandleFunc("GET /api/healthz", handlerReadiness)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerHitCount)
	mux.HandleFunc("POST /admin/reset", apiCfg.handlerReset)
	mux.HandleFunc("POST /api/users", apiCfg.handlerAddUser)
	mux.HandleFunc("POST /api/chirps", apiCfg.handlerNewChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.handlerGetChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handlerGetChirpByID)
	mux.HandleFunc("POST /api/login", apiCfg.handlerLogin)
	mux.HandleFunc("POST /api/refresh", apiCfg.handlerCheckRefreshToken)
	mux.HandleFunc("POST /api/revoke", apiCfg.handlerRevoke)
	mux.HandleFunc("PUT /api/users", apiCfg.handlerUpdateUser)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handlerDeleteChirp)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlerUpgradeUser)

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	err = server.ListenAndServe()
	if err != nil {
		fmt.Printf("Error listening and serving: %v", err)
		os.Exit(1)
	}

}
